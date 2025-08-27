# backend/modules/ml/train_ranker.py
from __future__ import annotations

"""
Train per-family Learning-to-Rank (Stage-B) models from evidence logs.

What it does
------------
- Parses evidence.jsonl (attempts + findings).
- Labels each (endpoint, payload) as:
    2 = hard positive (SQL error / boolean or time oracle / JS XSS / external redirect)
    1 = soft positive (big Δlen+Δstatus, large latency delta, or high ML p)
    0 = negative
- Builds per-family ranking datasets grouped by endpoint.
- Trains LambdaMART with objective=rank:pairwise (robust and avoids brittle built-in ndcg@K quirks).
- Reports NDCG@3 and Hit@1/3/5 and saves reliability bins (calibration) on a validation split.
- Exports ranker_{family}.joblib and recommender_meta.json.

Critical contract with runtime
------------------------------
Recommender at inference time concatenates:
  [endpoint_feature_vector] + [payload_desc(payload)]
This trainer uses the exact same recipe:
- Endpoint vector comes from FeatureExtractor.extract_endpoint_features(...) (payload-agnostic, no navigation).
- Payload descriptor mirrors backend/modules/recommender._payload_desc.

Output files go to backend/modules/ml/ by default and are picked up by
backend/modules/recommender.py via RANKER_PATHS + META_PATHS.
"""

import argparse
import glob
import json
import math
import os
import random
from collections import defaultdict
from dataclasses import dataclass
from hashlib import sha1
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

# --- Dependencies: xgboost + joblib (ensure in requirements.txt) -------------
try:
    from xgboost import XGBRanker  # type: ignore
except Exception as e:
    raise SystemExit("xgboost is required. Add `xgboost` to backend/requirements.txt") from e

try:
    import joblib  # type: ignore
except Exception as e:
    raise SystemExit("joblib is required. Add `joblib` to backend/requirements.txt") from e

import numpy as np

# Internal helpers (payload families & endpoint features)
try:
    # Canonical pools not strictly required for training, but import to keep module deps aligned
    from ..family_router import payload_pool_for  # noqa: F401
except Exception:
    def payload_pool_for(_: str) -> List[str]:
        return []

try:
    # Payload-agnostic endpoint features (same API the runtime uses)
    from ..feature_extractor import FeatureExtractor
except Exception as e:
    raise SystemExit("FeatureExtractor is required at train time.") from e


# ============================ Core configs ===================================

FAMILIES_DEFAULT = ("sqli", "xss", "redirect")
MODEL_FILENAMES = {
    "sqli": "ranker_sqli.joblib",
    "xss": "ranker_xss.joblib",
    "redirect": "ranker_redirect.joblib",
}

RANDOM_SEED = 42
random.seed(RANDOM_SEED)
np.random.seed(RANDOM_SEED)


# ============================ Utilities ======================================

def _payload_family(p: str) -> str:
    s = (p or "").lower()
    if any(x in s for x in ("<script", "<svg", "onerror=", "<img")):
        return "xss"
    if any(x in s for x in (" union ", " or ", " and ", "waitfor delay", "'--", "/*", " sleep(")) or s.startswith("'"):
        return "sqli"
    if s.startswith(("http://", "https://", "//")) or "%2f%2f" in s:
        return "redirect"
    return "base"


def _payload_desc(payload: str) -> List[float]:
    """Mirror backend/modules/recommender._payload_desc to avoid drift."""
    s = payload or ""
    specials = sum(1 for ch in s if not ch.isalnum())
    lower = s.lower()
    return [
        float(len(s)),
        float(specials),
        1.0 if ("<script" in lower or "onerror=" in lower or "onload=" in lower) else 0.0,  # XSS-ish
        1.0 if (" or 1=1" in lower or "union select" in lower or "waitfor" in lower or "sleep(" in lower) else 0.0,  # SQLi-ish
        1.0 if (lower.startswith("http") or lower.startswith("//")) else 0.0,  # Redirect-ish
    ]


def _endpoint_vec(fe: FeatureExtractor, t: Dict[str, Any]) -> List[float]:
    """
    EXACTLY the same payload-agnostic endpoint vector used at inference,
    with no headless navigation / HTTP fetches.
    """
    return fe.extract_endpoint_features(
        url=t.get("url") or t.get("request", {}).get("url", ""),
        param=t.get("param") or t.get("request", {}).get("param", ""),
        method=t.get("method") or t.get("request", {}).get("method", "GET"),
        content_type=t.get("content_type") or t.get("response", {}).get("headers", {}).get("content-type"),
        headers=t.get("headers") or t.get("request", {}).get("headers"),
    )


def _endpoint_key(t: Dict[str, Any]) -> str:
    url = t.get("url") or t.get("request", {}).get("url", "")
    method = (t.get("method") or t.get("request", {}).get("method", "GET")).upper()
    param = t.get("param") or t.get("request", {}).get("param", "")
    raw = f"{method}|{url}|{param}"
    return sha1(raw.encode("utf-8", "ignore")).hexdigest()[:16]


def _family_from_record(rec: Dict[str, Any]) -> str:
    fam = rec.get("payload_family_used")
    if fam:
        return str(fam).lower()
    return _payload_family(rec.get("payload_string") or rec.get("payload") or "")


@dataclass
class Attempt:
    endpoint_id: str
    family: str
    payload: str
    label: int  # 2 hard, 1 soft, 0 negative
    tmeta: Dict[str, Any]  # endpoint meta for features


# ===================== Evidence parsing & labeling ===========================

def _score_label(rec: Dict[str, Any]) -> int:
    """
    Convert an 'attempt' or 'finding' record into a label:
      2 = hard positive
      1 = soft positive
      0 = negative
    """
    det = rec.get("detector_hits") or rec.get("signals") or {}
    # Normalize detector hits
    sql_err = bool(det.get("sql_error") or (isinstance(det.get("sql_error"), dict) and det["sql_error"].get("hit")))
    bool_sqli = bool(det.get("boolean_sqli"))
    time_sqli = bool(det.get("time_sqli"))
    xss_js = bool(det.get("xss_js") or (isinstance(det.get("reflection"), dict) and det["reflection"].get("js_context")))
    xss_raw = bool(det.get("xss_raw"))
    xss_escaped = bool(det.get("xss_html_escaped"))
    open_redirect = bool(det.get("open_redirect") or (isinstance(det.get("open_redirect"), dict) and det["open_redirect"].get("external")))

    # Strong oracles → hard positive
    if sql_err or bool_sqli or time_sqli or xss_js or open_redirect:
        return 2
    if xss_raw and not xss_escaped:
        return 2

    # Soft positives by deltas / ML conf
    status_delta = int(rec.get("status_delta") or 0)
    len_delta = int(rec.get("len_delta") or 0)
    ms_delta = int(rec.get("latency_ms_delta") or 0)
    mlp = float((rec.get("ml") or {}).get("p") or 0.0)

    if status_delta >= 1 and abs(len_delta) >= 300:
        return 1
    if ms_delta >= 800:  # noticeable timing difference (time-based hints)
        return 1
    if mlp >= 0.65:
        return 1

    return 0


def _iter_evidence_records(paths: Iterable[str]) -> Iterable[Dict[str, Any]]:
    for p in paths:
        with open(p, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except Exception:
                    continue


def _collect_attempts(data_glob: str, families: Tuple[str, ...]) -> List[Attempt]:
    files = sorted(glob.glob(data_glob, recursive=True))
    if not files:
        raise SystemExit(f"No evidence files found for glob: {data_glob}")

    fe = FeatureExtractor(headless=True)
    out: List[Attempt] = []

    for rec in _iter_evidence_records(files):
        t = rec.get("type")
        if t not in ("attempt", "finding"):
            continue

        payload = rec.get("payload_string") or rec.get("payload")
        if not payload:
            continue

        fam = _family_from_record(rec)
        if fam not in families:
            continue

        lbl = _score_label(rec)

        # Endpoint meta for features
        tmeta = {
            "url": rec.get("url") or (rec.get("request") or {}).get("url"),
            "param": rec.get("param") or (rec.get("request") or {}).get("param"),
            "method": rec.get("method") or (rec.get("request") or {}).get("method"),
            "content_type": rec.get("content_type") or (rec.get("response") or {}).get("headers", {}).get("content-type"),
            "headers": rec.get("headers") or (rec.get("request") or {}).get("headers"),
        }

        ep_id = _endpoint_key({"url": tmeta["url"], "param": tmeta["param"], "method": tmeta["method"]})
        out.append(Attempt(endpoint_id=ep_id, family=fam, payload=payload, label=lbl, tmeta=tmeta))

    # Deduplicate exact (endpoint,family,payload) keeping max label
    dedup: Dict[Tuple[str, str, str], Attempt] = {}
    for a in out:
        k = (a.endpoint_id, a.family, a.payload)
        if k not in dedup or a.label > dedup[k].label:
            dedup[k] = a
    return list(dedup.values())


# ========================== Dataset building =================================

@dataclass
class LTRDataset:
    X: np.ndarray
    y: np.ndarray
    group: List[int]
    payloads: List[str]
    endpoint_ids: List[str]


def _build_family_dataset(attempts: List[Attempt], family: str) -> LTRDataset:
    """
    Build per-family ranking dataset with group=per-endpoint.
    Only keep endpoints that have at least 2 payloads and at least one positive.
    """
    fe = FeatureExtractor(headless=True)

    # Group attempts by endpoint
    by_ep: Dict[str, List[Attempt]] = defaultdict(list)
    for a in attempts:
        if a.family == family:
            by_ep[a.endpoint_id].append(a)

    X_rows: List[List[float]] = []
    y_rows: List[float] = []
    group_sizes: List[int] = []
    payloads_all: List[str] = []
    endpoint_all: List[str] = []

    for ep_id, items in by_ep.items():
        # collapse duplicates per payload (keep max label)
        best_by_payload: Dict[str, Attempt] = {}
        for a in items:
            if a.payload not in best_by_payload or a.label > best_by_payload[a.payload].label:
                best_by_payload[a.payload] = a
        items = list(best_by_payload.values())

        # Need at least two candidates and at least one positive
        if len(items) < 2 or not any(it.label > 0 for it in items):
            continue

        # Endpoint vector (payload-agnostic)
        ep_vec = _endpoint_vec(fe, {
            "url": items[0].tmeta["url"],
            "param": items[0].tmeta["param"],
            "method": items[0].tmeta["method"],
            "content_type": items[0].tmeta["content_type"],
            "headers": items[0].tmeta["headers"],
        })

        # Assemble rows
        for it in items:
            X_rows.append(ep_vec + _payload_desc(it.payload))
            y_rows.append(float(it.label))  # 0/1/2 gains
            payloads_all.append(it.payload)
            endpoint_all.append(ep_id)

        group_sizes.append(len(items))

    if not X_rows:
        raise ValueError(f"No usable training rows for family '{family}'. Check your evidence logs.")

    X = np.asarray(X_rows, dtype=float)
    y = np.asarray(y_rows, dtype=float)
    return LTRDataset(X=X, y=y, group=group_sizes, payloads=payloads_all, endpoint_ids=endpoint_all)


# ============================= Metrics =======================================

def _ndcg_at_k(y_true: List[float], y_score: List[float], k: int = 3) -> float:
    """
    Compute NDCG@k for a single query.

    Robust to queries with fewer than k candidates by capping k to the
    actual list length (this avoids shape-mismatch errors like (2,) vs (3,)).
    """
    if not y_true or not y_score:
        return 0.0
    k_eff = min(k, len(y_true), len(y_score))
    if k_eff <= 0:
        return 0.0

    order = np.argsort(-np.asarray(y_score))[:k_eff]
    y_true_sorted = np.asarray(y_true)[order]  # length = k_eff
    gains = (2 ** y_true_sorted - 1)
    discounts = 1 / np.log2(np.arange(2, k_eff + 2))
    dcg = float(np.sum(gains * discounts))

    # ideal
    ideal_order = np.sort(y_true)[::-1][:k_eff]
    ideal_gains = (2 ** ideal_order - 1)
    ideal_dcg = float(np.sum(ideal_gains * discounts))
    return dcg / ideal_dcg if ideal_dcg > 0 else 0.0


def _hit_at_k(y_true: List[float], y_score: List[float], k: int) -> int:
    order = np.argsort(-np.asarray(y_score))[:k]
    return int(max(np.asarray(y_true)[order]) > 0) if len(order) else 0


def _softmax(xs: List[float]) -> List[float]:
    m = max(xs) if xs else 0.0
    exps = [math.exp(x - m) for x in xs]
    s = sum(exps) or 1.0
    return [x / s for x in exps]


def _evaluate_per_endpoint(
    endpoint_ids: List[str], payloads: List[str], y_true: np.ndarray, y_score: np.ndarray
) -> Dict[str, float]:
    """Aggregate NDCG@3 + Hits over endpoints (groups)."""
    # Build groups
    by_ep: Dict[str, List[int]] = defaultdict(list)
    for idx, ep in enumerate(endpoint_ids):
        by_ep[ep].append(idx)

    ndcgs, hit1, hit3, hit5 = [], [], [], []
    for _, idxs in by_ep.items():
        yt = [float(y_true[i]) for i in idxs]
        ys = [float(y_score[i]) for i in idxs]
        ndcgs.append(_ndcg_at_k(yt, ys, k=3))              # safe for groups < 3
        hit1.append(_hit_at_k(yt, ys, k=1))
        hit3.append(_hit_at_k(yt, ys, k=3))
        hit5.append(_hit_at_k(yt, ys, k=min(5, len(idxs))))

    return {
        "NDCG@3": float(np.mean(ndcgs) if ndcgs else 0.0),
        "Hit@1": float(np.mean(hit1) if hit1 else 0.0),
        "Hit@3": float(np.mean(hit3) if hit3 else 0.0),
        "Hit@5": float(np.mean(hit5) if hit5 else 0.0),
        "queries": len(by_ep),
    }


def _reliability_bins(endpoint_ids: List[str], y_true: np.ndarray, y_score: np.ndarray, bins: int = 10) -> List[Dict[str, float]]:
    """
    Build bin-wise calibration (predicted softmax prob vs. empirical success rate).
    Success = label > 0.
    """
    # Convert scores to per-query softmax probabilities
    by_ep: Dict[str, List[int]] = defaultdict(list)
    for i, ep in enumerate(endpoint_ids):
        by_ep[ep].append(i)

    probs, succ = [], []
    for _, idxs in by_ep.items():
        sm = _softmax([float(y_score[i]) for i in idxs])
        for j, i in enumerate(idxs):
            probs.append(sm[j])
            succ.append(1.0 if float(y_true[i]) > 0 else 0.0)

    probs = np.asarray(probs)
    succ = np.asarray(succ)
    if probs.size == 0:
        return []

    edges = np.linspace(0, 1, bins + 1)
    out = []
    for b in range(bins):
        lo, hi = edges[b], edges[b + 1]
        mask = (probs >= lo) & (probs < hi) if b < bins - 1 else (probs >= lo) & (probs <= hi)
        if not np.any(mask):
            avg_p = (lo + hi) / 2.0
            out.append({"bin": b, "p_mean": float(avg_p), "emp_rate": 0.0, "count": 0})
            continue
        out.append({
            "bin": b,
            "p_mean": float(np.mean(probs[mask])),
            "emp_rate": float(np.mean(succ[mask])),
            "count": int(np.sum(mask)),
        })
    return out


# ============================= Train / Eval ==================================

def _train_ranker(dataset: LTRDataset) -> XGBRanker:
    """
    Train LambdaMART WITHOUT tying ourselves to a fragile built-in ndcg@K.
    We use pairwise objective and do metrics ourselves on a val split.
    """
    model = XGBRanker(
        objective="rank:pairwise",     # robust; no top-k eval dependency during fit
        n_estimators=300,
        max_depth=6,
        learning_rate=0.10,
        subsample=0.8,
        colsample_bytree=0.8,
        reg_lambda=1.0,
        random_state=RANDOM_SEED,
        tree_method="hist",
        n_jobs=max(1, os.cpu_count() or 1),
    )
    model.fit(dataset.X, dataset.y, group=dataset.group)
    return model


def _train_val_split(endpoint_ids: List[str], group_sizes: List[int], val_ratio: float = 0.2) -> Tuple[List[int], List[int]]:
    """
    Split by endpoint (query) to avoid leakage.
    Returns (train_indices, val_indices) over rows.
    """
    # Build query index ranges
    q_ranges: List[Tuple[int, int]] = []
    start = 0
    for g in group_sizes:
        q_ranges.append((start, start + g))
        start += g

    # Shuffle endpoints deterministically
    idxs = list(range(len(q_ranges)))
    random.Random(RANDOM_SEED).shuffle(idxs)
    cut = int(round(len(idxs) * (1.0 - val_ratio)))
    train_q = set(idxs[:cut])
    val_q = set(idxs[cut:])

    train_rows, val_rows = [], []
    for qi, (lo, hi) in enumerate(q_ranges):
        rows = list(range(lo, hi))
        if qi in train_q:
            train_rows.extend(rows)
        else:
            val_rows.extend(rows)

    return train_rows, val_rows


def _slice_dataset(ds: LTRDataset, rows: List[int]) -> LTRDataset:
    # To preserve valid group structure, rebuild group vector from rows by endpoint
    idxs = sorted(rows)
    X = ds.X[idxs]
    y = ds.y[idxs]
    payloads = [ds.payloads[i] for i in idxs]
    endpoints = [ds.endpoint_ids[i] for i in idxs]

    # recompute group sizes by contiguous endpoint_id blocks
    group: List[int] = []
    if endpoints:
        cur = endpoints[0]
        count = 0
        for e in endpoints:
            if e == cur:
                count += 1
            else:
                group.append(count)
                cur = e
                count = 1
        group.append(count)

    return LTRDataset(X=X, y=y, group=group, payloads=payloads, endpoint_ids=endpoints)


def train_one_family(attempts: List[Attempt], family: str, out_dir: Path) -> Dict[str, Any]:
    print(f"\n[Family: {family}] Building dataset...")
    ds = _build_family_dataset(attempts, family)
    print(f"[Family: {family}] Samples: {len(ds.y)} | Queries: {len(ds.group)} | Dim: {ds.X.shape[1]}")

    # Split
    train_rows, val_rows = _train_val_split(ds.endpoint_ids, ds.group, val_ratio=0.2)
    ds_tr = _slice_dataset(ds, train_rows)
    ds_va = _slice_dataset(ds, val_rows)

    # Sanity: every training group must have >= 2 rows (pairwise objective).
    min_g = min(ds_tr.group) if ds_tr.group else 0
    if min_g < 2:
        raise ValueError(f"Training groups contain size-1 queries (min={min_g}). Your evidence is too thin for {family}.")

    # Train
    print(f"[Family: {family}] Training XGBRanker on {len(ds_tr.y)} rows / {len(ds_tr.group)} queries...")
    model = _train_ranker(ds_tr)

    # Evaluate (validation)
    y_score = model.predict(ds_va.X)
    metrics = _evaluate_per_endpoint(ds_va.endpoint_ids, ds_va.payloads, ds_va.y, y_score)
    calib = _reliability_bins(ds_va.endpoint_ids, ds_va.y, y_score, bins=10)

    # Save model
    out_path = out_dir / MODEL_FILENAMES[family]
    joblib.dump(model, out_path)
    print(f"[Family: {family}] Saved model to {out_path}")

    # Save report
    report = {
        "family": family,
        "samples_train": len(ds_tr.y),
        "queries_train": len(ds_tr.group),
        "samples_val": len(ds_va.y),
        "queries_val": len(ds_va.group),
        "metrics": metrics,
        "reliability_bins": calib,
        "feature_dim_note": "Each row = endpoint_vec + payload_desc(5). Endpoint vec comes from FeatureExtractor.extract_endpoint_features(...)",
        "objective": "rank:pairwise",
        "min_group_train": min_g,
    }
    (out_dir / f"ranker_report_{family}.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"[Family: {family}] Validation metrics: {metrics}")

    return report


# ============================== CLI ==========================================

def main() -> None:
    ap = argparse.ArgumentParser(description="Train per-family LambdaMART/XGBRanker from evidence logs.")
    ap.add_argument("--data-glob", required=True, help="Glob for evidence jsonl files, e.g., data/**/evidence.jsonl")
    ap.add_argument("--out-dir", default=str(Path(__file__).resolve().parent), help="Output dir (default: backend/modules/ml)")
    ap.add_argument("--families", nargs="+", default=list(FAMILIES_DEFAULT), help="Families to train: sqli xss redirect")
    args = ap.parse_args()

    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    families = tuple(x.lower() for x in args.families)
    for fam in families:
        if fam not in MODEL_FILENAMES:
            raise SystemExit(f"Unsupported family '{fam}'. Supported: {list(MODEL_FILENAMES)}")

    # Collect attempts
    print("[Data] Mining evidence records...")
    attempts = _collect_attempts(args.data_glob, families)
    print(f"[Data] Collected {len(attempts)} labeled attempts across families {families}")

    if not attempts:
        raise SystemExit("No attempts found. Make sure your --data-glob points to evidence.jsonl files.")

    # Train per family
    summaries: Dict[str, Any] = {}
    for fam in families:
        try:
            summaries[fam] = train_one_family(attempts, fam, out_dir)
        except Exception as e:
            print(f"[Family: {fam}] Skipped: {e}")

    # Write recommender meta to keep vectorization in sync (endpoint feature length).
    # IMPORTANT: feature_dim here is ONLY the endpoint vector (without payload_desc).
    # Inference concatenates [endpoint_vec(feature_dim)] + [payload_desc(5)] internally.
    fe = FeatureExtractor(headless=True)
    meta = {
        "feature_dim": len(_endpoint_vec(fe, {"url": "", "param": "", "method": "GET", "content_type": None, "headers": None})),
        "feature_names": None,  # not needed because we pass a numeric list in stable order
        "note": "Rankers expect [endpoint_feature_vector] + [payload_desc(5)] at inference.",
        "families_trained": [k for k, _ in summaries.items()],
    }
    (out_dir / "recommender_meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"[Meta] Wrote {out_dir / 'recommender_meta.json'}")

    # Summary manifest
    manifest = {
        "summaries": summaries,
        "out_dir": str(out_dir),
    }
    (out_dir / "ranker_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"[Done] Trained families: {list(summaries.keys())}")


if __name__ == "__main__":
    main()
