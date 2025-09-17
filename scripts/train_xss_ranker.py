#!/usr/bin/env python3
import json, math, argparse
from pathlib import Path
from typing import List, Dict

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import train_test_split
import joblib

import sys
sys.path.append('')
from backend.app_state import MODEL_DIR
from backend.modules.ml.infer_ranker import _features_to_vector


def load_dataset(path: Path) -> List[Dict]:
    rows = []
    with path.open('r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                pass
    return rows


def make_features(ex: Dict, family: str = 'xss') -> np.ndarray:
    """Map dataset example x->features expected by _features_to_vector."""
    x = ex.get('x', {})
    # Construct the context dict expected by feature_spec/_features_to_vector
    ctx = {
        'family': family,
        'param_in': x.get('param_loc', ''),
        'param': x.get('param', ''),
        'payload': '',  # not required for vector build; stats already present in x
        'probe_sql_error': x.get('probe_sql_error', 0),
        'probe_timing_delta_gt2s': x.get('probe_timing_delta_gt2s', 0),
        'probe_reflection_html': x.get('probe_reflection_html', 0),
        'probe_reflection_js': x.get('probe_reflection_js', 0),
        'probe_redirect_location_reflects': x.get('probe_redirect_location_reflects', 0),
        'status_class': 2 if x.get('status_class_2', 0) else 3 if x.get('status_class_3', 0) else 4 if x.get('status_class_4', 0) else 5 if x.get('status_class_5', 0) else 0,
        'content_type_html': x.get('content_type_html', 0),
        'content_type_json': x.get('content_type_json', 0),
        'ctx_html': x.get('ctx_html', 0),
        'ctx_attr': x.get('ctx_attr', 0),
        'ctx_js': x.get('ctx_js', 0),
    }
    # The vector builder also expects shape/statistics; we inject directly
    feats = {
        'param_len': x.get('param_len', 0),
        'payload_len': x.get('payload_len', 0),
        'alnum_ratio': x.get('alnum_ratio', 0.0),
        'digit_ratio': x.get('digit_ratio', 0.0),
        'symbol_ratio': x.get('symbol_ratio', 0.0),
        'url_encoded_ratio': x.get('url_encoded_ratio', 0.0),
        'double_encoded_hint': x.get('double_encoded_hint', 0),
        'shannon_entropy': x.get('shannon_entropy', 0.0),
        'has_quote': x.get('has_quote', 0),
        'has_angle': x.get('has_angle', 0),
        'has_lt_gt': x.get('has_lt_gt', 0),
        'has_script_tag': x.get('has_script_tag', 0),
        'has_event_handler': x.get('has_event_handler', 0),
        'sql_kw_hits': x.get('sql_kw_hits', 0),
        'balanced_quotes': x.get('balanced_quotes', 0),
        'has_comment_seq': x.get('has_comment_seq', 0),
    }
    ctx.update(feats)
    vec = _features_to_vector(ctx)
    return vec[0]


def platt(dev_p: np.ndarray, dev_y: np.ndarray) -> Dict[str, float]:
    # Avoid extremes for logit
    eps = 1e-6
    p = np.clip(dev_p, eps, 1 - eps)
    z = np.log(p / (1 - p))
    # Fit y ~ sigmoid(a*z + b) by logistic regression with single feature z
    lr = LogisticRegression(fit_intercept=True, solver='liblinear')
    lr.fit(z.reshape(-1,1), dev_y)
    a = float(lr.coef_[0][0])
    b = float(lr.intercept_[0])
    return {'slope': a, 'intercept': b}


def ndcg_at_k(groups: Dict[str, List[Dict]], pred: Dict[int, float], k: int = 5) -> float:
    from sklearn.metrics import ndcg_score
    vals = []
    for gid, items in groups.items():
        if len(items) < 2:
            continue
        y_true = np.array([[1 if it['y']=='xss' else 0 for it in items]])
        y_score = np.array([[pred[it['idx']] for it in items]])
        vals.append(ndcg_score(y_true, y_score, k=min(k, y_true.shape[1])))
    return float(np.mean(vals)) if vals else 0.0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dataset', default='backend/modules/ml/data/ranker/ranker_dataset.jsonl')
    ap.add_argument('--outdir', default=None)
    args = ap.parse_args()

    ds_path = Path(args.dataset)
    rows = load_dataset(ds_path)
    # Build arrays
    X, y, w, groups = [], [], [], {}
    for idx, ex in enumerate(rows):
        split = ex.get('split','train')
        if split not in {'train','dev','test'}:
            split = 'train'
        vec = make_features(ex, 'xss')
        X.append(vec)
        lab = ex.get('y')
        if isinstance(lab, str):
            y.append(1 if lab == 'xss' else 0)
        else:
            y.append(int(lab))
        w.append(float(ex.get('confidence', 1.0)))
        gid = f"{ex['x'].get('host','')}|{ex['x'].get('path','')}|{ex['x'].get('method','')}|{ex['x'].get('param','')}|{split}"
        groups.setdefault(gid, []).append({'idx': idx, 'y': ex.get('y'), 'split': split})

    X = np.array(X)
    y = np.array(y)
    w = np.array(w)

    # Split ensuring both classes appear in train/dev
    all_idx = np.arange(len(rows))
    pos_idx = all_idx[y==1]
    neg_idx = all_idx[y==0]
    # 80/20 split for positives
    if len(pos_idx) == 0 or len(neg_idx) == 0:
        raise SystemExit('Dataset lacks positive or negative examples')
    rng = np.random.default_rng(42)
    rng.shuffle(pos_idx)
    rng.shuffle(neg_idx)
    npos_tr = max(1, int(0.8*len(pos_idx)))
    nneg_tr = max(npos_tr, int(0.8*len(neg_idx)))  # allow more negs
    tr = np.concatenate([pos_idx[:npos_tr], neg_idx[:nneg_tr]])
    rest = np.concatenate([pos_idx[npos_tr:], neg_idx[nneg_tr:]])
    rng.shuffle(tr)
    rng.shuffle(rest)
    if len(rest) < 2:
        rest = tr
    # dev/test share the rest
    split_pt = len(rest)//2
    de = rest[:split_pt]
    te = rest[split_pt:]

    # Train simple LR
    clf = LogisticRegression(max_iter=500)
    clf.fit(X[tr], y[tr], sample_weight=w[tr])

    # Offline metrics
    def prob(m, Z):
        try:
            return m.predict_proba(Z)[:,1]
        except Exception:
            p = m.predict(Z)
            return (p - p.min())/(max(1e-6, p.max()-p.min()))

    p_dev = prob(clf, X[de])
    p_test = prob(clf, X[te])
    auc_dev = roc_auc_score(y[de], p_dev) if len(np.unique(y[de]))>1 else float('nan')
    auc_test = roc_auc_score(y[te], p_test) if len(np.unique(y[te]))>1 else float('nan')

    # NDCG by group (@3/@5)
    pred_map = {i: float(prob(clf, X[[i]])[0]) for i in range(len(X))}
    ndcg3 = ndcg_at_k(groups, pred_map, k=3)
    ndcg5 = ndcg_at_k(groups, pred_map, k=5)

    print(json.dumps({'auc_dev': auc_dev, 'auc_test': auc_test, 'ndcg@3': ndcg3, 'ndcg@5': ndcg5}, indent=2))

    # Calibrate on dev
    cal = platt(p_dev, y[de])
    outdir = Path(args.outdir or MODEL_DIR)
    outdir.mkdir(parents=True, exist_ok=True)
    joblib.dump(clf, outdir / 'family_xss.joblib')
    (outdir / 'family_xss.cal.json').write_text(json.dumps(cal, indent=2))
    print('Saved model to', outdir / 'family_xss.joblib')
    print('Saved calibration to', outdir / 'family_xss.cal.json')

if __name__ == '__main__':
    main()
