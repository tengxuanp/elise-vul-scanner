#!/usr/bin/env python3
from __future__ import annotations
import json, numpy as np, pickle, re
from pathlib import Path
from collections import Counter
from backend.modules.ml.param_prioritizer import MODEL_PATH, TOKENS_RE, WEAK_POS, WEAK_PATH

JOBS_DIR = Path("data/jobs")

def featurize(method, url, param):
    feats = Counter()
    feats[f"m:{(method or 'GET').upper()}"] += 1
    feats[f"p:{(param or '').lower()}"] += 1
    for t in TOKENS_RE.findall((url or '').lower())[-6:]:
        feats[f"path:{t}"] += 1
    return feats

def label(method, url, param):
    # Weak labels: likely interesting if matches known patterns
    p = (param or '').lower(); u = (url or '').lower()
    y = 0
    if p in WEAK_POS: y = 1
    if any(x in u for x in WEAK_PATH): y = max(y, 1)
    return y

def main():
    rows = []
    for job_dir in JOBS_DIR.glob("*"):
        f = job_dir / "crawl_result.json"
        if not f.exists(): continue
        try:
            obj = json.loads(f.read_text("utf-8"))
            for ep in obj.get("endpoints", []):
                method = ep.get("method","GET")
                url = ep.get("url")
                for p in (ep.get("params") or []) + (ep.get("body_keys") or []):
                    rows.append((method, url, p, label(method,url,p)))
        except Exception:
            continue

    if not rows:
        print("No data; abort.")
        return

    # Build vocab
    feats_list = [featurize(m,u,p) for (m,u,p,_) in rows]
    vocab = sorted(set().union(*[set(f.keys()) for f in feats_list]))
    X = np.array([[f.get(w,0.0) for w in vocab] for f in feats_list], dtype=float)
    y = np.array([r[3] for r in rows], dtype=float)

    # Train tiny logistic regression (L2)
    w = np.zeros(X.shape[1]); b = 0.0
    lr, reg, epochs = 0.1, 1e-3, 200
    for _ in range(epochs):
        z = X.dot(w) + b
        p = 1/(1+np.exp(-z))
        grad_w = X.T.dot(p - y)/len(y) + reg*w
        grad_b = float(np.sum(p - y))/len(y)
        w -= lr * grad_w
        b -= lr * grad_b

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(MODEL_PATH, "wb") as f:
        pickle.dump({"model":{"w":w, "b":b}, "vocab":vocab}, f)
    print("Saved:", MODEL_PATH)

if __name__ == "__main__":
    main()
