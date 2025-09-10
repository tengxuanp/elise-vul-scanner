from __future__ import annotations
import os, json, random
from pathlib import Path
from typing import List, Dict
import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import classification_report
from .utils import window

def load_jsonl(path:str):
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            yield json.loads(line)

def split(items, frac=0.9, seed=7):
    items = list(items)
    random.Random(seed).shuffle(items)
    k = int(len(items)*frac)
    return items[:k], items[k:]

def vectorizer():
    return TfidfVectorizer(analyzer="char", ngram_range=(3,5),
                           min_df=2, max_features=200000, lowercase=False)

def train_task(examples:List[Dict], labels:List[str]):
    vec = vectorizer()
    X = vec.fit_transform([window(ex["text"]) for ex in examples])
    base = LogisticRegression(max_iter=200, n_jobs=1, multi_class="auto")
    clf = CalibratedClassifierCV(base, method="sigmoid", cv=3)
    clf.fit(X, np.array(labels))
    return vec, clf

def report(vec, clf, items, name):
    X = vec.transform([window(ex["text"]) for ex in items])
    y = np.array([ex["label"] for ex in items])
    pred = clf.predict(X)
    print(f"\n{name} report:\n", classification_report(y, pred, digits=3))

def main():
    data_path = os.environ.get("DATA", "data/xss_ctx/train.jsonl")
    out_dir = Path(os.environ.get("OUT_DIR","models"))
    out_dir.mkdir(parents=True, exist_ok=True)

    rows = list(load_jsonl(data_path))
    ctx_rows = [ {"text":r["text"], "label": r["ctx"]} for r in rows ]
    esc_rows = [ {"text":r["text"], "label": r["esc"]} for r in rows ]

    tr_ctx, te_ctx = split(ctx_rows)
    tr_esc, te_esc = split(esc_rows)

    ctx_vec, ctx_clf = train_task(tr_ctx, [r["label"] for r in tr_ctx])
    report(ctx_vec, ctx_clf, te_ctx, "Context")

    esc_vec, esc_clf = train_task(tr_esc, [r["label"] for r in tr_esc])
    report(esc_vec, esc_clf, te_esc, "Escaping")

    joblib.dump(ctx_vec, out_dir / "xss_context_vectorizer.joblib")
    joblib.dump(ctx_clf, out_dir / "xss_context_model.joblib")
    joblib.dump(esc_vec, out_dir / "xss_escaping_vectorizer.joblib")
    joblib.dump(esc_clf, out_dir / "xss_escaping_model.joblib")

    meta = {
        "task":"xss_context_and_escaping",
        "vectorizer":"char-3-5 tf-idf on ±120 window",
        "model":"LogReg + sigmoid calibration",
        "samples": len(rows),
        "labels": {
            "context": ["html_body","attr","js_string","url","css","comment","json"],
            "escaping": ["raw","html","url","js"]
        }
    }
    (out_dir / "xss_ctx_meta.json").write_text(json.dumps(meta, indent=2))

if __name__ == "__main__":
    main()
