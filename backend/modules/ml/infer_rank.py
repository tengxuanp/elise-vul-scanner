# backend/modules/ml/infer_ranker.py
from __future__ import annotations

"""
Runtime payload ranking (Learning-to-Rank) for per-family recommenders.

Contract:
- Each score vector = [endpoint_feature_vector] + [payload_desc(5)]
- Endpoint features: FeatureExtractor.extract_endpoint_features(...) (NO network I/O)
- payload_desc: mirrors train_ranker._payload_desc

Public API:
    rank_payloads(endpoint_meta, family, candidates, *, model_dir=None, top_k=None) -> List[dict]
        endpoint_meta: dict with keys {url, param, method, content_type, headers}
        family: "sqli" | "xss" | "redirect"
        candidates: list of dicts:
            {
              "payload_id": "sqli.union.null",
              "payload": "...' UNION SELECT NULL-- -",   # body/string (required for descriptor)
              ... any extra you want to preserve ...
            }

        returns same list sorted by descending predicted relevance, optionally truncated to top_k.

If model missing or fails to load → we fall back to a deterministic heuristic that still beats random.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

try:
    import joblib  # type: ignore
except Exception as e:
    raise SystemExit("joblib is required. Add `joblib` to backend/requirements.txt") from e

# Endpoint features (payload-agnostic) at inference must MATCH training extractor.
try:
    from ..feature_extractor import FeatureExtractor
except Exception as e:
    raise SystemExit("FeatureExtractor is required at inference time.") from e


MODEL_FILENAMES = {
    "sqli": "ranker_sqli.joblib",
    "xss": "ranker_xss.joblib",
    "redirect": "ranker_redirect.joblib",
}

ML_DIR = Path(__file__).resolve().parent  # backend/modules/ml
META_PATH = ML_DIR / "recommender_meta.json"

# ----- singleton caches -----
_MODELS: Dict[str, Any] = {}
_FE = FeatureExtractor(headless=True)  # don't do navigation here
_META: Dict[str, Any] = {}


# ---------------- payload + endpoint featurization ----------------

def _payload_desc(payload: str) -> List[float]:
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


def _endpoint_vec(endpoint_meta: Dict[str, Any]) -> List[float]:
    return _FE.extract_endpoint_features(
        url=endpoint_meta.get("url", ""),
        param=endpoint_meta.get("param", ""),
        method=endpoint_meta.get("method", "GET"),
        content_type=endpoint_meta.get("content_type"),
        headers=endpoint_meta.get("headers"),
    )


# ---------------- model loading ----------------

def _load_meta(meta_path: Path = META_PATH) -> Dict[str, Any]:
    global _META
    if _META:
        return _META
    if meta_path.exists():
        try:
            _META = json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception:
            _META = {}
    else:
        _META = {}
    return _META


def _model_path_for(family: str, model_dir: Optional[str] = None) -> Path:
    base = Path(model_dir) if model_dir else ML_DIR
    return base / MODEL_FILENAMES[family]


def _load_model(family: str, model_dir: Optional[str] = None):
    key = f"{family}::{model_dir or ''}"
    if key in _MODELS:
        return _MODELS[key]
    path = _model_path_for(family, model_dir)
    if not path.exists():
        _MODELS[key] = None
        return None
    try:
        _MODELS[key] = joblib.load(path)
        return _MODELS[key]
    except Exception:
        _MODELS[key] = None
        return None


# ---------------- fallback heuristic (when model missing) ----------------

def _fallback_score(payload: str, family: str, param_name: str) -> float:
    """Cheap deterministic scoring that uses obvious hints; strictly worse than ML but better than random."""
    s = (payload or "").lower()
    p = (param_name or "").lower()
    score = 0.0

    # family-aligned keyword boosts
    if family == "xss":
        if any(k in s for k in ("<script", "onerror=", "onload=", "javascript:")):
            score += 2.0
        if any(k in p for k in ("q", "query", "search", "term", "cb", "callback", "html", "msg", "comment", "title")):
            score += 1.0
    elif family == "sqli":
        if any(k in s for k in ("union select", " or 1=1", " and 1=1", "sleep(", "waitfor")):
            score += 2.0
        if any(k in p for k in ("id", "uid", "pid", "ref", "order", "page", "idx", "num", "key", "cat")):
            score += 1.0
    elif family == "redirect":
        if s.startswith(("http://", "https://", "//")) or "%2f%2f" in s:
            score += 2.0
        if any(k in p for k in ("next", "return", "redirect", "url", "target", "dest", "goto", "continue", "callback", "cb")):
            score += 1.0

    # minor tie-breakers
    score += min(len(s), 200) / 200.0 * 0.25
    return score


# ---------------- public API ----------------

def rank_payloads(
    endpoint_meta: Dict[str, Any],
    family: str,
    candidates: List[Dict[str, Any]],
    *,
    model_dir: Optional[str] = None,
    top_k: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """
    Score and rank candidate payloads for a given endpoint/param family.

    candidates: list of dicts with at least {"payload_id": str, "payload": str}
    returns: same dicts, sorted by score desc (optionally truncated to top_k)
    """
    family = (family or "").lower()
    if family not in MODEL_FILENAMES:
        # Unknown family → return as-is
        return candidates[:top_k] if top_k else list(candidates)

    model = _load_model(family, model_dir=model_dir)
    ep_vec = _endpoint_vec(endpoint_meta)

    if model is None:
        # Fallback heuristic
        scored = [
            (c, _fallback_score(c.get("payload", ""), family, endpoint_meta.get("param", "")))
            for c in candidates
        ]
        ranked = [c for c, _ in sorted(scored, key=lambda z: z[1], reverse=True)]
        return ranked[:top_k] if top_k else ranked

    # Build design matrix
    rows, ids = [], []
    for c in candidates:
        payload = c.get("payload", "")  # string body
        vec = ep_vec + _payload_desc(payload)
        rows.append(vec)
        ids.append(c)

    X = np.asarray(rows, dtype=float)
    scores = model.predict(X)
    ranked = [c for _, c in sorted(zip(list(scores), ids), key=lambda z: z[0], reverse=True)]
    return ranked[:top_k] if top_k else ranked
