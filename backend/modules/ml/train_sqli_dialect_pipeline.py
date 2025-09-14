#!/usr/bin/env python3
"""
Train a robust SQLi dialect Pipeline that combines word + char TF‑IDF and
produces calibrated probabilities. Saves a single sklearn Pipeline that is
version-stable for serving in the current venv.

Outputs (in MODEL_DIR):
- sqli_dialect_classifier.joblib        (Pipeline[FeatureUnion(TFIDF), Calibrated LR])
- sqli_dialect_pipeline_meta.json       (classes, features, tau_unknown, sklearn/numpy versions)

The corpus is synthesized from backend.modules.sqli_dialect_rules.TOKENS with
oracle/unknown augmentations, similar to train_sqli_dialect_text.py but using a
single Pipeline + FeatureUnion (word + char TF‑IDF) and a calibrated classifier.
"""

from pathlib import Path
import argparse
import json
import sys
import platform
import numpy as np
from typing import List, Tuple

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.calibration import CalibratedClassifierCV
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import joblib

# Local imports
from backend.app_state import MODEL_DIR
from backend.modules.sqli_dialect_rules import TOKENS as RULE_TOKENS


ORACLE_TOKENS = [
    "ORA-00933: SQL command not properly ended",
    "ORA-00936: missing expression",
    "ORA-01756: quoted string not properly terminated",
    "Oracle", "OCI"
]

UNKNOWN_TOKENS = [
    "database error occurred", "db error", "internal error", "unexpected error"
]


def _meta_tokens(text: str, status: int = 500, content_type: str = "text/html") -> str:
    """Append coarse meta tokens to the text (content-type, status, length bin)."""
    t = text or ""
    ct = (content_type or "").lower()
    if "text/html" in ct:
        t += " CT_HTML"
    if "application/json" in ct:
        t += " CT_JSON"
    try:
        sc = int(status or 0)
    except Exception:
        sc = 0
    if sc:
        t += f" HTTP_{sc}"
    # length bins
    L = len(text or "")
    if L < 80:
        t += " LEN_S"
    elif L < 200:
        t += " LEN_M"
    else:
        t += " LEN_L"
    return t


def build_synth() -> Tuple[List[str], List[str]]:
    X: List[str] = []
    y: List[str] = []

    def add(label: str, toks: List[str], status: int = 500, ct: str = "text/html"):
        for tok in toks:
            s1 = _meta_tokens(tok.lower(), status, ct)
            X.append(s1); y.append(label)
            s2 = _meta_tokens(f"Error: {tok.lower()} occurred", status, ct)
            X.append(s2); y.append(label)
        if len(toks) >= 2:
            combo = _meta_tokens(f"{toks[0].lower()} ... {toks[1].lower()}", status, ct)
            X.append(combo); y.append(label)

    for label, toks in RULE_TOKENS.items():
        add(label, toks)
    add("oracle", ORACLE_TOKENS)
    add("unknown", UNKNOWN_TOKENS)
    return X, y


def train_pipeline(outdir: Path, max_word: int = 6000, max_char: int = 8000, C: float = 2.0, tau_unknown: float = 0.6):
    X, y = build_synth()

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)

    # FeatureUnion: word + char TF‑IDF
    word = TfidfVectorizer(lowercase=True, analyzer='word', ngram_range=(1,2), max_features=max_word, min_df=1)
    char = TfidfVectorizer(lowercase=True, analyzer='char', ngram_range=(3,5), max_features=max_char, min_df=1)
    feats = FeatureUnion([('word', word), ('char', char)])

    base = LogisticRegression(max_iter=400, C=C, n_jobs=None)
    clf = CalibratedClassifierCV(base, method='sigmoid', cv=3)

    pipe = Pipeline([
        ('feats', feats),
        ('clf', clf)
    ])

    pipe.fit(X_train, y_train)
    y_pred = pipe.predict(X_test)
    acc = accuracy_score(y_test, y_pred)

    outdir.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipe, outdir / 'sqli_dialect_classifier.joblib')

    meta = {
        'classes': list(sorted(set(y))),
        'accuracy': float(acc),
        'tau_unknown': float(tau_unknown),
        'sklearn_version': getattr(sys.modules.get('sklearn'), '__version__', 'unknown'),
        'numpy_version': np.__version__,
        'platform': platform.platform(),
        'features': {
            'word_ngrams': '1-2',
            'char_ngrams': '3-5',
            'max_word': max_word,
            'max_char': max_char
        }
    }
    with open(outdir / 'sqli_dialect_pipeline_meta.json', 'w') as f:
        json.dump(meta, f, indent=2)
    print('Saved Pipeline to', outdir)
    print(json.dumps(meta, indent=2))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--outdir', default=str(MODEL_DIR))
    parser.add_argument('--max-word', type=int, default=6000)
    parser.add_argument('--max-char', type=int, default=8000)
    parser.add_argument('--C', type=float, default=2.0)
    parser.add_argument('--tau-unknown', type=float, default=0.6)
    args = parser.parse_args()
    train_pipeline(Path(args.outdir), args.max_word, args.max_char, args.C, args.tau_unknown)


if __name__ == '__main__':
    main()

