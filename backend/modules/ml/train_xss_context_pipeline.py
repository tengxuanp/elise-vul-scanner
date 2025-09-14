#!/usr/bin/env python3
"""
Train XSS Context and Escaping Pipelines with word+char TF‑IDF + calibrated LR.

Input JSONL (default data/xss_ctx/train.jsonl) lines:
  {"text": "...EliseXSSCanary123...", "ctx": "html_body|attr|js_string|url|css|comment|json", "esc": "raw|html|url|js"}

Outputs in MODEL_DIR:
  - xss_context_pipeline.joblib
  - xss_escaping_pipeline.joblib
  - xss_ctx_pipeline_meta.json   (classes, versions)
"""

from pathlib import Path
import argparse, json, sys, platform
from typing import List, Dict, Tuple
import numpy as np
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.linear_model import LogisticRegression
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

from backend.app_state import MODEL_DIR
from backend.ml.xss_ctx.utils import window


def load_jsonl(path: Path) -> List[Dict]:
    rows = []
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                continue
    return rows


def build_features() -> FeatureUnion:
    word = TfidfVectorizer(analyzer='word', ngram_range=(1,2), lowercase=False, max_features=120000)
    char = TfidfVectorizer(analyzer='char', ngram_range=(3,5), lowercase=False, max_features=200000)
    return FeatureUnion([('word', word), ('char', char)])


def train_pipe(texts: List[str], labels: List[str]) -> Tuple[Pipeline, Dict[str,float]]:
    feats = build_features()
    base = LogisticRegression(max_iter=300, n_jobs=None, multi_class='auto')
    clf = CalibratedClassifierCV(base, method='sigmoid', cv=3)
    pipe = Pipeline([('feats', feats), ('clf', clf)])
    pipe.fit(texts, labels)
    # quick acc (dev set would be better)
    acc = None
    try:
        X_tr, X_te, y_tr, y_te = train_test_split(texts, labels, test_size=0.2, random_state=42, stratify=labels)
        pipe_tmp = Pipeline([('feats', build_features()), ('clf', CalibratedClassifierCV(LogisticRegression(max_iter=300), method='sigmoid', cv=3))])
        pipe_tmp.fit(X_tr, y_tr)
        pred = pipe_tmp.predict(X_te)
        acc = float(accuracy_score(y_te, pred))
    except Exception:
        acc = None
    return pipe, ({'acc': acc} if acc is not None else {})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--data', default='data/xss_ctx/train.jsonl')
    ap.add_argument('--outdir', default=str(MODEL_DIR))
    args = ap.parse_args()
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    rows = load_jsonl(Path(args.data))
    if not rows:
        raise SystemExit(f"No training rows found at {args.data}")

    texts = [window(r['text']) for r in rows if 'text' in r]
    ctx_labels = [r['ctx'] for r in rows]
    esc_labels = [r['esc'] for r in rows]

    ctx_pipe, ctx_metrics = train_pipe(texts, ctx_labels)
    esc_pipe, esc_metrics = train_pipe(texts, esc_labels)

    joblib.dump(ctx_pipe, outdir / 'xss_context_pipeline.joblib')
    joblib.dump(esc_pipe, outdir / 'xss_escaping_pipeline.joblib')

    meta = {
        'context_classes': sorted(list(set(ctx_labels))),
        'escaping_classes': sorted(list(set(esc_labels))),
        'sklearn_version': sys.modules.get('sklearn').__version__,
        'numpy_version': np.__version__,
        'platform': platform.platform(),
        'metrics': {
            'context': ctx_metrics,
            'escaping': esc_metrics
        }
    }
    (outdir / 'xss_ctx_pipeline_meta.json').write_text(json.dumps(meta, indent=2))
    print(json.dumps(meta, indent=2))


if __name__ == '__main__':
    main()

