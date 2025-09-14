#!/usr/bin/env python3
"""
Train a matched TF-IDF + LogisticRegression classifier for SQLi dialect detection.

This produces a consistent pair:
- sqli_dialect_model.joblib
- sqli_dialect_vectorizer.joblib

It uses a lightweight synthetic corpus based on known error tokens
from backend.modules.sqli_dialect_rules, plus a few Oracle/unknown patterns.
"""

from pathlib import Path
import argparse
import json
from typing import List, Tuple

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib

from backend.app_state import MODEL_DIR
from backend.modules.sqli_dialect_rules import TOKENS as RULE_TOKENS


# Add a small set of Oracle and unknown tokens
ORACLE_TOKENS = [
    "ORA-00933: SQL command not properly ended",
    "ORA-00936: missing expression",
    "ORA-01756: quoted string not properly terminated",
    "Oracle", "OCI"
]

UNKNOWN_TOKENS = [
    "database error occurred", "db error", "internal error", "unexpected error"
]


def build_synthetic_corpus() -> Tuple[List[str], List[str]]:
    """Create a small synthetic corpus from tokens for each dialect."""
    X: List[str] = []
    y: List[str] = []

    def add_samples(label: str, toks: List[str]):
        # multiple short variants per token + combined
        for t in toks:
            X.append(f"{t} CT_HTML HTTP_500")
            y.append(label)
            X.append(f"Error: {t} occurred CT_HTML HTTP_500")
            y.append(label)
        # Combine a few tokens together
        if len(toks) >= 2:
            combo = f"{toks[0]} ... {toks[1]} CT_HTML HTTP_500"
            X.append(combo)
            y.append(label)

    # Map rules tokens (already lowercase) to labels
    for label, toks in RULE_TOKENS.items():
        add_samples(label, [t.lower() for t in toks])

    # Oracle and unknown
    add_samples("oracle", [t.lower() for t in ORACLE_TOKENS])
    add_samples("unknown", [t.lower() for t in UNKNOWN_TOKENS])

    return X, y


def train_and_save(outdir: Path, min_df: int = 1, max_features: int = 2048) -> dict:
    X, y = build_synthetic_corpus()

    # Vectorizer and model
    vectorizer = TfidfVectorizer(lowercase=True, ngram_range=(1, 2), min_df=min_df, max_features=max_features)
    clf = LogisticRegression(max_iter=200, multi_class="auto")

    # Train/test split just for reporting
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20, random_state=42, stratify=y)

    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    clf.fit(X_train_vec, y_train)
    y_pred = clf.predict(X_test_vec)
    acc = accuracy_score(y_test, y_pred)

    # Save matched pair
    outdir.mkdir(parents=True, exist_ok=True)
    joblib.dump(clf, outdir / "sqli_dialect_model.joblib")
    joblib.dump(vectorizer, outdir / "sqli_dialect_vectorizer.joblib")

    meta = {
        "model_type": "LogisticRegression",
        "vectorizer_type": "TfidfVectorizer",
        "n_features": int(getattr(clf, "n_features_in_", X_train_vec.shape[1])),
        "classes": list(getattr(clf, "classes_", [])),
        "accuracy": float(acc),
        "samples_total": len(X),
        "notes": "Synthetic corpus from rules + oracle/unknown tokens",
    }

    with open(outdir / "sqli_dialect_meta.json", "w") as f:
        json.dump(meta, f, indent=2)

    return meta


def main():
    parser = argparse.ArgumentParser(description="Train TF-IDF SQLi dialect classifier")
    parser.add_argument("--outdir", default=str(MODEL_DIR), help="Output directory for model/vectorizer")
    parser.add_argument("--min-df", type=int, default=1, help="Vectorizer min_df")
    parser.add_argument("--max-features", type=int, default=2048, help="Vectorizer max_features")
    args = parser.parse_args()

    outdir = Path(args.outdir)
    meta = train_and_save(outdir, min_df=args.min_df, max_features=args.max_features)
    print("Saved matched pair to", outdir)
    print(json.dumps(meta, indent=2))


if __name__ == "__main__":
    main()

