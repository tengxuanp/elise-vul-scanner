# scripts/train_ranker.py
from __future__ import annotations
import argparse, json, joblib, numpy as np
from pathlib import Path
from sklearn.linear_model import LogisticRegression
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import train_test_split
from backend.modules.ml_ranker import featurize, FEATURES

def weak_label(row: dict) -> int | None:
    sig = row.get("detector_hits") or row.get("signals") or {}
    # Positives: strong oracles
    if sig.get("open_redirect") or sig.get("login_success") or sig.get("sql_error") or sig.get("xss_js") or sig.get("boolean_sqli") or sig.get("time_sqli"):
        return 1
    # Negatives: very quiet attempts
    sd = int(row.get("status_delta") or 0)
    ld = int(row.get("len_delta") or 0)
    md = int(row.get("latency_ms_delta") or 0)
    if not any(sig.values()) and sd == 0 and abs(ld) < 30 and md < 200:
        return 0
    return None  # ignore ambiguous

def to_Xy(lines):
    X, y = [], []
    for ln in lines:
        try:
            row = json.loads(ln)
        except Exception:
            continue
        if row.get("type") not in ("attempt","finding"):
            continue
        lab = weak_label(row)
        if lab is None:
            continue
        feats = featurize(row)
        X.append([feats.get(k,0.0) for k in FEATURES])
        y.append(lab)
    return np.array(X, float), np.array(y, int)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="path to evidence.jsonl (or a directory of them)")
    ap.add_argument("--out", default="./models/ranker.joblib")
    args = ap.parse_args()

    paths = []
    p = Path(args.input)
    if p.is_dir():
        paths = list(p.rglob("evidence.jsonl"))
    else:
        paths = [p]

    lines = []
    for f in paths:
        lines += Path(f).read_text(encoding="utf-8", errors="ignore").splitlines()

    X, y = to_Xy(lines)
    if len(y) < 50 or y.sum() == 0 or y.sum() == len(y):
        raise SystemExit("Not enough weak labels to train a classifier.")

    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    base = LogisticRegression(max_iter=200, class_weight="balanced")
    clf = CalibratedClassifierCV(base, method="isotonic", cv=3)
    clf.fit(Xtr, ytr)

    print("Train size:", len(ytr), "Test size:", len(yte), "Pos rate:", y.mean())
    print("Test pos mean prob:", clf.predict_proba(Xte)[yte==1,1].mean() if (yte==1).any() else "n/a")

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(clf, args.out)
    print("Saved:", args.out)

if __name__ == "__main__":
    main()
