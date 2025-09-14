#!/usr/bin/env python3
"""
Train per-family payload rankers (XSS, SQLi, Redirect) using LightGBM LambdaRank
when available, or fallback to scikit-learn GradientBoostingClassifier when not.

Input: a JSONL produced by prepare_ranker_data.py at --dataset, where each line:
  { "x": {feature dict}, "y": "sqli|xss|redirect|none", "confidence": float, "split": "train|dev|test" }

Outputs in MODEL_DIR:
  - family_{fam}.joblib           (model)  [overwrites existing manifest entries]
  - family_{fam}.cal.json         (Platt scaling params)

Run (in venv):
  PYTHONPATH=. python backend/modules/ml/prepare_ranker_data.py --in-glob "data/jobs/**/evidence.jsonl" --out-dir backend/modules/ml/models/ds
  PYTHONPATH=. python backend/modules/ml/train_ranker_lgbm.py --dataset backend/modules/ml/models/ds/ranker_dataset.jsonl --outdir backend/modules/ml/models
"""

from __future__ import annotations
import argparse, json, math
from pathlib import Path
from typing import Dict, Any, List, Tuple

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import roc_auc_score
from sklearn.ensemble import GradientBoostingClassifier
import joblib

from backend.app_state import MODEL_DIR


class ConstantProba:
    """Pickleable constant-probability classifier with predict_proba()."""
    def __init__(self, p: float):
        self.p = float(p)
    def predict_proba(self, X):
        X = np.asarray(X)
        n = X.shape[0]
        p = np.full((n,1), self.p, dtype=float)
        return np.hstack([1-p, p])


def _vec45(x: Dict[str, Any]) -> np.ndarray:
    """Map feature dict (from prepare_ranker_data.extract_features) to 45-dim vector
    consistent with infer_ranker._features_to_vector.
    """
    f = []
    def g(k, d=0):
        v = x.get(k, d)
        try:
            return int(v) if isinstance(d, int) else float(v)
        except Exception:
            return d

    # 1) Basic
    f += [g('param_len', 0), 0, 0, g('shannon_entropy', 0.0)]
    # 2) Family indicators will be set per-family later during training
    f += [0, 0, 0]
    # 3) Param loc
    ploc = (x.get('param_loc') or '').lower()
    f += [1 if ploc=='query' else 0, 1 if ploc=='form' else 0, 1 if ploc=='json' else 0]
    # 4) Probe-style features (prefer infer_ranker keys, fallback to sig_*)
    def gf(primary, fallback=None, d=0):
        if primary in x: return g(primary, d)
        if fallback and fallback in x: return g(fallback, d)
        return d
    f += [
        gf('probe_sql_error','sig_sql_error',0),
        gf('probe_timing_delta_gt2s', None, 0),
        gf('probe_reflection_html', 'sig_xss_reflected', 0),
        gf('probe_reflection_js', None, 0),
        gf('probe_redirect_location_reflects','external_redirect',0)
    ]
    # 5) Status classes/content types/context indicators
    f += [g('status_class_2',0), g('status_class_3',0), g('status_class_4',0), g('status_class_5',0), 0]
    f += [g('content_type_html',0), g('content_type_json',0)]
    f += [g('ctx_html',0), g('ctx_attr',0), g('ctx_js',0)]
    # 8) Param analysis
    f += [g('param_len',0), g('payload_len',0), 0.0, 0.0, 0.0, 0.0, 0, g('shannon_entropy',0.0)]
    # 9) Payload analysis
    f += [g('has_quote',0), g('has_angle',0), g('has_lt_gt',0), g('has_script_tag',0), g('has_event_handler',0), g('sql_kw_hits',0), g('balanced_quotes',0)]
    # 10) Padding to 45
    while len(f) < 45:
        f.append(0.0)
    return np.array(f[:45], dtype=float)


def _load_dataset(path: Path) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    X_tr, y_tr, X_dev, y_dev, X_te, y_te = [], [], [], [], [], []
    with open(path, 'r', encoding='utf-8') as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            x = obj.get('x') or {}
            y = obj.get('y') or 'none'
            split = obj.get('split') or 'train'
            vec = _vec45(x)
            if split == 'train':
                X_tr.append(vec); y_tr.append(y)
            elif split == 'dev':
                X_dev.append(vec); y_dev.append(y)
            else:
                X_te.append(vec); y_te.append(y)
    def arr(lst):
        return np.vstack(lst) if lst else np.zeros((0,45))
    return arr(X_tr), np.array(y_tr), arr(X_dev), np.array(y_dev), arr(X_te), np.array(y_te)


def _train_family(X_tr, y_tr, X_dev, y_dev, family: str):
    y_tr_bin = (y_tr == family).astype(int)
    y_dev_bin = (y_dev == family).astype(int)
    # Guard: if only one class in training, return a dummy calibrated model
    if int(y_tr_bin.sum()) == 0 or int((1 - y_tr_bin).sum()) == 0:
        # Build a constant proba model to maintain API expectations
        p_const = 0.99 if int(y_tr_bin.sum())>0 else 0.01
        model = ConstantProba(p_const)
        try:
            auc = float(roc_auc_score(y_dev_bin, np.repeat(p_const, len(y_dev_bin))))
        except Exception:
            auc = None
        return model, auc
    # Try LightGBM if available
    model = None
    try:
        import lightgbm as lgb
        params = dict(objective='binary', learning_rate=0.05, num_leaves=31, min_data_in_leaf=20, feature_fraction=0.8, bagging_fraction=0.8, bagging_freq=1, metric=['auc'])
        lgbm = lgb.LGBMClassifier(**params, n_estimators=400)
        lgbm.fit(X_tr, y_tr_bin, eval_set=[(X_dev, y_dev_bin)], eval_metric='auc')
        # Calibrate with Platt
        calib = CalibratedClassifierCV(lgbm, method='sigmoid', cv=3)
        calib.fit(X_tr, y_tr_bin)
        model = calib
    except Exception:
        # Fallback to GradientBoostingClassifier + calibration
        base = GradientBoostingClassifier(random_state=42)
        base.fit(X_tr, y_tr_bin)
        model = CalibratedClassifierCV(base, method='sigmoid', cv=3)
        model.fit(X_tr, y_tr_bin)
    # Dev AUC
    try:
        proba = model.predict_proba(X_dev)[:,1]
        auc = float(roc_auc_score(y_dev_bin, proba))
    except Exception:
        auc = None
    return model, auc


def _save_platt_as_json(out: Path, model) -> None:
    """Save dummy Platt params (not used when using calibrated classifier).
    We still write a small JSON to satisfy infer_ranker expectations.
    """
    meta = {"note": "Calibrated within model; p_cal comes from predict_proba", "a": 1.0, "b": 0.0}
    out.write_text(json.dumps(meta, indent=2))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dataset', required=True)
    ap.add_argument('--outdir', default=str(MODEL_DIR))
    args = ap.parse_args()
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    X_tr, y_tr, X_dev, y_dev, X_te, y_te = _load_dataset(Path(args.dataset))
    families = ['xss','sqli','redirect']
    report = {}
    for fam in families:
        mdl, auc = _train_family(X_tr, y_tr, X_dev, y_dev, fam)
        joblib.dump(mdl, outdir / f'family_{fam}.joblib')
        _save_platt_as_json(outdir / f'family_{fam}.cal.json', mdl)
        report[fam] = {'dev_auc': auc}

    print(json.dumps({'trained': families, 'report': report, 'outdir': str(outdir)}, indent=2))


if __name__ == '__main__':
    main()
