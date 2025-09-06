# backend/modules/ml/infer_ranker.py
from __future__ import annotations
"""
Runtime payload ranking (Learning-to-Rank) for per-family recommenders.

Contract (MUST hold at train and inference):
  total_dims = endpoint_dims (≈17) + payload_desc_dims (20) = 37

We read recommender_meta.json (if present) to discover:
  - endpoint_feature_names (order matters)
  - payload_feature_names (order matters; OPTIONAL — we still enforce 20 dims)
  - endpoint_dims / payload_dims / expected_total_dim

Public API (signature-flex):
  rank_payloads(endpoint_meta, family, candidates, *, model_dir=None, top_k=None)
  rank_payloads(family, endpoint_meta, candidates, top_k)
  rank_payloads(context=..., family=..., candidates=..., top_k=..., model_dir=...)

Returns: same dicts sorted by predicted relevance desc (optionally truncated to top_k),
with extra keys: ranker_score, ranker_used_model, ranker_feature_dim_total.

Notes:
- NEVER perform network I/O here.
- If model missing: deterministic heuristic fallback (logged).
- If feature shape mismatch: raise ValueError (do NOT silently degrade).
"""

import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

try:
    import joblib  # type: ignore
except Exception as e:
    raise SystemExit("joblib is required. Add `joblib` to backend/requirements.txt") from e

# Optional XGBoost JSON fallback for artifact/runtime mismatch
try:
    import xgboost as xgb  # type: ignore
    _XGB_OK = True
except Exception:
    xgb = None  # type: ignore
    _XGB_OK = False

# Endpoint features must MATCH the training extractor.
try:
    from ..feature_extractor import FeatureExtractor
except Exception as e:
    raise SystemExit("FeatureExtractor is required at inference time.") from e


log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

MODEL_FILENAMES = {
    "sqli": "ranker_sqli.joblib",
    "xss": "ranker_xss.joblib",
    "redirect": "ranker_redirect.joblib",
}

ML_DIR = Path(__file__).resolve().parent  # backend/modules/ml
META_PATH = ML_DIR / "recommender_meta.json"

# ----- singleton caches -----
_MODELS: Dict[str, Any] = {}
_META: Dict[str, Any] = {}

# keep the extractor lightweight (no navigation)
_FE = FeatureExtractor(headless=True)

# --------------------------------------------------------------------------- #
# Meta / config
# --------------------------------------------------------------------------- #

def _load_meta(meta_path: Path = META_PATH) -> Dict[str, Any]:
    global _META
    if _META:
        return _META
    try:
        if meta_path.exists():
            _META = json.loads(meta_path.read_text(encoding="utf-8"))
            # normalize old keys
            if "endpoint_dims" not in _META:
                _META["endpoint_dims"] = _META.get("feature_dim") or _META.get("endpoint_feature_dim")
            if "payload_dims" not in _META:
                _META["payload_dims"] = _META.get("payload_feature_dim") or (
                    len(_META.get("payload_feature_names", [])) or None
                )
            if "expected_total_dim" not in _META and _META.get("endpoint_dims") and _META.get("payload_dims"):
                _META["expected_total_dim"] = int(_META["endpoint_dims"]) + int(_META["payload_dims"])
        else:
            _META = {}
    except Exception as e:
        log.warning("[LTR] Failed to read recommender_meta.json: %s", e)
        _META = {}
    return _META


def _expected_dims() -> Tuple[Optional[int], Optional[int], Optional[int]]:
    m = _load_meta()
    return (
        (int(m["endpoint_dims"]) if m.get("endpoint_dims") else None),
        (int(m["payload_dims"]) if m.get("payload_dims") else None),
        (int(m["expected_total_dim"]) if m.get("expected_total_dim") else None),
    )


def _model_base_dir(user_model_dir: Optional[str]) -> Path:
    # Env override precedence: ELISE_ML_MODEL_DIR > MODEL_DIR > ELISE_MODEL_DIR
    env_dir = os.getenv("ELISE_ML_MODEL_DIR") or os.getenv("MODEL_DIR") or os.getenv("ELISE_MODEL_DIR")
    base = user_model_dir or env_dir
    if base:
        p = Path(base)
        if p.exists() and any((p / name).exists() for name in MODEL_FILENAMES.values()):
            return p
    return ML_DIR

def _model_path_for(family: str, model_dir: Optional[str]) -> Path:
    family = "redirect" if family == "open_redirect" else family
    return _model_base_dir(model_dir) / MODEL_FILENAMES[family]


def _load_model(family: str, model_dir: Optional[str]) -> Any:
    """Load joblib model; if that fails and a .json booster exists, load booster as fallback."""
    family = "redirect" if family == "open_redirect" else family
    base_dir = _model_base_dir(model_dir)
    key = f"{family}::{base_dir}"
    if key in _MODELS:
        return _MODELS[key]

    jl_path = base_dir / MODEL_FILENAMES[family]
    if not jl_path.exists():
        log.warning("[LTR] Model missing for %s at %s (fallback → heuristic).", family, jl_path)
        _MODELS[key] = None
        return None

    # Try joblib first
    try:
        mdl = joblib.load(jl_path)
        _MODELS[key] = mdl
        log.info("[LTR] Loaded %s model: %s", family, jl_path)
        return mdl
    except Exception as e:
        log.error("[LTR] joblib load failed for %s at %s: %s", family, jl_path, e)

    # Try JSON booster fallback if available
    json_path = jl_path.with_suffix(".json")
    if _XGB_OK and json_path.exists():
        try:
            booster = xgb.Booster()  # type: ignore[attr-defined]
            booster.load_model(str(json_path))
            _MODELS[key] = ("booster", booster)
            log.info("[LTR] Loaded %s booster JSON: %s", family, json_path)
            return _MODELS[key]
        except Exception as e2:
            log.error("[LTR] booster JSON load failed for %s at %s: %s", family, json_path, e2)

    _MODELS[key] = None
    log.warning("[LTR] No usable model for %s; using heuristic.", family)
    return None


# --------------------------------------------------------------------------- #
# Endpoint features
# --------------------------------------------------------------------------- #

def _endpoint_vec(endpoint_meta: Dict[str, Any]) -> List[float]:
    """
    Obtain endpoint features from FeatureExtractor.
    If recommender_meta.json provides names, we align strictly to that order.
    """
    raw = _FE.extract_endpoint_features(
        url=endpoint_meta.get("url", ""),
        param=endpoint_meta.get("param", ""),
        method=endpoint_meta.get("method", "GET"),
        content_type=endpoint_meta.get("content_type"),
        headers=endpoint_meta.get("headers"),
    )

    meta = _load_meta()
    ep_names: List[str] = meta.get("endpoint_feature_names", []) or []
    ep_dim_expected, _, _ = _expected_dims()

    if isinstance(raw, dict):
        if ep_names:
            vec = [float(raw.get(name, 0.0)) for name in ep_names]
        else:
            # Fallback: deterministic order (sorted keys) with warning.
            log.warning("[LTR] endpoint_feature_names missing in meta; using sorted dict keys (risky).")
            vec = [float(raw[k]) for k in sorted(raw.keys())]
    else:
        vec = [float(x) for x in (raw or [])]

    # If meta doesn't carry endpoint_dims, infer it now to enable total-dim enforcement later.
    if ep_dim_expected is None:
        _META["endpoint_dims"] = len(vec)
        ep_dim_expected = len(vec)

    if ep_dim_expected is not None and len(vec) != ep_dim_expected:
        raise ValueError(
            f"[LTR] Endpoint feature shape mismatch: got {len(vec)}, expected {ep_dim_expected}. "
            f"Check FeatureExtractor vs recommender_meta.json."
        )
    return vec


# --------------------------------------------------------------------------- #
# Payload descriptor (EXACT same 20-dim as training)
# --------------------------------------------------------------------------- #

_BASE64ISH_RE = re.compile(r'^[A-Za-z0-9+/=]{12,}$')

def _payload_desc_from_body(payload: str) -> List[float]:
    """
    Expanded, deterministic payload features (MUST match trainer).
    20 features in this fixed order:
      [len, specials, xss/script, xss/event, has_img, has_svg, has_js_url,
       starts_angle, attr_breakout, close_script, sqli/union, sqli/or1eq1,
       sqli/comment, sqli/timefn, is_numeric_like, redir/proto_rel,
       redir/double_urlenc, redir/js_location, redir/http, looks_base64]
    """
    s = payload or ""
    lower = s.lower()
    specials = sum(1 for ch in s if not ch.isalnum())

    # XSS cues
    has_script_tag    = "<script" in lower or "</script>" in lower
    has_event_attr    = ("onerror=" in lower) or ("onload=" in lower) or ("onclick=" in lower)
    has_img           = "<img" in lower
    has_svg           = "<svg" in lower
    has_js_url        = "javascript:" in lower
    starts_with_angle = s[:1] in "<>"
    has_attr_breakout = (('"' in s or "'" in s) and (" on" in lower or "javascript:" in lower))
    has_close_script  = "</script>" in lower

    # SQLi cues
    has_union         = "union select" in lower
    has_or_1eq1       = (" or 1=1" in lower) or ("' or" in lower) or ('" or' in lower)
    has_comment       = "--" in lower or "/*" in lower or "*/" in lower
    has_time_fn       = "sleep(" in lower or "benchmark(" in lower or "waitfor" in lower
    is_numeric_like   = lower.strip().isdigit() or lower.strip().replace(".", "", 1).isdigit()

    # Redirect cues
    is_proto_rel      = lower.startswith("//")
    has_double_urlenc = "%252f%252f" in lower or "%2f%2f" in lower
    has_js_location   = "window.location" in lower
    has_http          = lower.startswith("http://") or lower.startswith("https://")
    looks_base64      = bool(_BASE64ISH_RE.match(s))

    return [
        float(len(s)),                # 0 length
        float(specials),              # 1 specials
        1.0 if has_script_tag else 0.0,     # 2
        1.0 if has_event_attr else 0.0,     # 3
        1.0 if has_img else 0.0,            # 4
        1.0 if has_svg else 0.0,            # 5
        1.0 if has_js_url else 0.0,         # 6
        1.0 if starts_with_angle else 0.0,  # 7
        1.0 if has_attr_breakout else 0.0,  # 8
        1.0 if has_close_script else 0.0,   # 9
        1.0 if has_union else 0.0,          # 10
        1.0 if has_or_1eq1 else 0.0,        # 11
        1.0 if has_comment else 0.0,        # 12
        1.0 if has_time_fn else 0.0,        # 13
        1.0 if is_numeric_like else 0.0,    # 14
        1.0 if is_proto_rel else 0.0,       # 15
        1.0 if has_double_urlenc else 0.0,  # 16
        1.0 if has_js_location else 0.0,    # 17
        1.0 if has_http else 0.0,           # 18
        1.0 if looks_base64 else 0.0,       # 19
    ]


def _payload_desc_from_id(pid: Optional[str]) -> List[float]:
    """
    Fallback when no raw body; approximate booleans from payload_id pattern.
    Matches trainer's approximation.
    """
    s = (pid or "").lower()

    if s.startswith("xss."):
        length_proxy, specials = 40.0, 8.0
        has_script_tag = "script" in s
        has_event_attr = any(k in s for k in ("onerror", "onload", "onclick"))
        has_img        = "img" in s
        has_svg        = "svg" in s
        has_js_url     = "javascript" in s and "url" in s
        starts_angle   = True
        attr_breakout  = "breakout" in s or "attr" in s
        close_script   = "script_injection" in s
        union = or1eq1 = comment = timefn = isnum = False
        proto_rel = "protocol_relative" in s
        double_urlenc = "double_urlencode" in s
        js_loc = "js_location" in s
        has_http = ("http" in s and "javascript" not in s)
        looks_b64 = False

    elif s.startswith("sqli."):
        length_proxy, specials = 28.0, 5.0
        has_script_tag = has_event_attr = has_img = has_svg = has_js_url = starts_angle = attr_breakout = close_script = False
        union     = "union" in s
        or1eq1    = "boolean" in s or "or1eq1" in s or "numeric_or1eq1" in s
        comment   = "comment" in s or "stack_comment" in s or "inline_comment" in s
        timefn    = "sleep" in s or "benchmark" in s or "waitfor" in s
        isnum     = "numeric" in s
        proto_rel = double_urlenc = js_loc = False
        has_http  = False
        looks_b64 = False

    elif s.startswith(("redir.", "redirect.")):
        length_proxy, specials = 24.0, 3.0
        has_script_tag = has_event_attr = has_img = has_svg = False
        has_js_url     = "javascript" in s
        starts_angle = attr_breakout = close_script = False
        union = or1eq1 = comment = timefn = isnum = False
        proto_rel     = "protocol_relative" in s
        double_urlenc = "double_urlencode" in s
        js_loc        = "js_location" in s
        has_http      = "http" in s
        looks_b64     = "base64" in s
    else:
        length_proxy, specials = 18.0, 2.0
        has_script_tag = has_event_attr = has_img = has_svg = has_js_url = starts_angle = attr_breakout = close_script = False
        union = or1eq1 = comment = timefn = isnum = False
        proto_rel = double_urlenc = js_loc = has_http = looks_b64 = False

    return [
        length_proxy, specials,
        1.0 if has_script_tag else 0.0,
        1.0 if has_event_attr else 0.0,
        1.0 if has_img else 0.0,
        1.0 if has_svg else 0.0,
        1.0 if has_js_url else 0.0,
        1.0 if starts_angle else 0.0,
        1.0 if attr_breakout else 0.0,
        1.0 if close_script else 0.0,
        1.0 if union else 0.0,
        1.0 if or1eq1 else 0.0,
        1.0 if comment else 0.0,
        1.0 if timefn else 0.0,
        1.0 if isnum else 0.0,
        1.0 if proto_rel else 0.0,
        1.0 if double_urlenc else 0.0,
        1.0 if js_loc else 0.0,
        1.0 if has_http else 0.0,
        1.0 if looks_b64 else 0.0,
    ]


def _payload_desc(payload: Optional[str], payload_id: Optional[str]) -> List[float]:
    if payload is not None and payload != "":
        return _payload_desc_from_body(payload)
    return _payload_desc_from_id(payload_id)


# --------------------------------------------------------------------------- #
# Heuristic fallback
# --------------------------------------------------------------------------- #

def _fallback_score(payload: str, family: str, param_name: str) -> float:
    """Cheap deterministic scoring; better than random, worse than ML."""
    s = (payload or "").lower()
    p = (param_name or "").lower()
    score = 0.0

    if family == "xss":
        if any(k in s for k in ("<script", "onerror=", "onload=", "javascript:")):
            score += 2.0
        if any(k in p for k in ("q", "query", "search", "term", "cb", "callback", "html", "msg", "comment", "title")):
            score += 1.0
    elif family == "sqli":
        if any(k in s for k in ("union select", " or 1=1", " and 1=1", "sleep(", "waitfor", "benchmark(")):
            score += 2.0
        if any(k in p for k in ("id", "uid", "pid", "ref", "order", "page", "idx", "num", "key", "cat")):
            score += 1.0
    elif family == "redirect":
        if s.startswith(("http://", "https://", "//")) or "%2f%2f" in s:
            score += 2.0
        if any(k in p for k in ("next", "return", "redirect", "url", "target", "dest", "goto", "continue", "callback", "cb")):
            score += 1.0

    score += min(len(s), 200) / 200.0 * 0.25  # tiny tie-break by length
    return score


# --------------------------------------------------------------------------- #
# Dispatcher + scoring helpers
# --------------------------------------------------------------------------- #

def _sigmoid(x: np.ndarray | float) -> np.ndarray | float:
    return 1.0 / (1.0 + np.exp(-x))

def _pick_scores(model: Any, X: np.ndarray) -> np.ndarray:
    """Try common interfaces, then Booster JSON; return 1D float array."""
    # XGBoost Booster fallback
    if isinstance(model, tuple) and model and model[0] == "booster":
        if not _XGB_OK:
            raise RuntimeError("XGBoost booster present but xgboost not installed")
        dmat = xgb.DMatrix(X.astype(np.float32))  # type: ignore
        y = model[1].predict(dmat)  # type: ignore[index]
        return np.asarray(y, dtype=float).reshape(-1)

    # scikit-style models
    if hasattr(model, "predict_proba"):
        try:
            proba = model.predict_proba(X)  # type: ignore
            proba = np.asarray(proba, dtype=float)
            if proba.ndim == 2 and proba.shape[1] >= 2:
                return proba[:, -1].reshape(-1)
            return proba.reshape(-1)
        except Exception as e:
            log.info("[LTR] predict_proba failed; trying predict(): %s", e)

    if hasattr(model, "predict"):
        y = model.predict(X)  # type: ignore
        y = np.asarray(y, dtype=float).reshape(-1)
        # For rankers/regressors, squash for stability; ranking invariant.
        return np.asarray(_sigmoid(y), dtype=float).reshape(-1)

    if hasattr(model, "decision_function"):
        y = model.decision_function(X)  # type: ignore
        y = np.asarray(y, dtype=float).reshape(-1)
        return np.asarray(_sigmoid(y), dtype=float).reshape(-1)

    # last resort: callable
    y = model(X)  # type: ignore
    return np.asarray(y, dtype=float).reshape(-1)


def _unpack_args(*args, **kwargs) -> Tuple[Dict[str, Any], str, List[Dict[str, Any]], Optional[str], Optional[int]]:
    """
    Accept all expected calling styles and normalize.
    Returns: (endpoint_meta, family, candidates, model_dir, top_k)
    """
    if args and isinstance(args[0], dict):
        endpoint_meta = args[0]
        family = args[1] if len(args) > 1 else kwargs.get("family")
        candidates = args[2] if len(args) > 2 else kwargs.get("candidates")
    elif args and isinstance(args[0], str):
        family = args[0]
        endpoint_meta = args[1] if len(args) > 1 else kwargs.get("context") or kwargs.get("endpoint_meta")
        candidates = args[2] if len(args) > 2 else kwargs.get("candidates")
    else:
        endpoint_meta = kwargs.get("context") or kwargs.get("endpoint_meta") or {}
        family = kwargs.get("family")
        candidates = kwargs.get("candidates")

    model_dir = kwargs.get("model_dir")
    top_k = kwargs.get("top_k")
    if family is None or candidates is None:
        raise TypeError("rank_payloads requires (endpoint_meta, family, candidates) or keyword equivalents.")
    return dict(endpoint_meta), str(family), list(candidates), model_dir, (int(top_k) if top_k is not None else None)


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #

def rank_payloads(*args, **kwargs) -> List[Dict[str, Any]]:
    """
    Score and rank candidate payloads for a given endpoint/param family.

    Returns: same dicts, sorted by score desc (optionally truncated to top_k).
    Adds keys: ranker_score, ranker_used_model, ranker_feature_dim_total.
    Raises: ValueError on feature-shape mismatches.
    """
    endpoint_meta, family, candidates, model_dir, top_k = _unpack_args(*args, **kwargs)
    family = ("redirect" if family == "open_redirect" else family).lower()
    if family not in MODEL_FILENAMES:
        return candidates[:top_k] if top_k else list(candidates)

    # Enhanced ML path (preferred)
    enhanced_engine = _get_enhanced_engine()
    if enhanced_engine is not None:
        try:
            # Extract endpoint and parameter info
            endpoint = {
                "url": endpoint_meta.get("url", ""),
                "method": endpoint_meta.get("method", "GET"),
                "content_type": endpoint_meta.get("content_type", "")
            }
            
            param = {
                "name": endpoint_meta.get("param", ""),
                "value": endpoint_meta.get("control_value", ""),
                "loc": endpoint_meta.get("injection_mode", "query")
            }
            
            # Extract payload list
            payloads = [c.get("payload", "") for c in candidates if c.get("payload")]
            if not payloads:
                log.warning("[Enhanced ML] No valid payloads found, falling back to legacy")
                enhanced_engine = None
            else:
                # Use enhanced payload ranking
                ranked_payloads = enhanced_engine.rank_payloads(
                    endpoint, param, family, payloads, top_k=top_k or len(payloads)
                )
                
                if ranked_payloads:
                    # Convert to expected format
                    ranked: List[Dict[str, Any]] = []
                    for i, item in enumerate(ranked_payloads):
                        c = dict(candidates[i]) if i < len(candidates) else {"payload": item["payload"]}
                        c["ranker_score"] = float(item.get("score", 0.0))
                        c["ranker_used_model"] = "enhanced_ml"
                        c["ranker_feature_dim_total"] = 48  # Enhanced ML uses 48 features
                        ranked.append(c)
                    
                    log.info(f"[Enhanced ML] Successfully ranked {len(ranked)} payloads for {family}")
                    return ranked
                else:
                    log.warning("[Enhanced ML] No results returned, falling back to legacy")
                    enhanced_engine = None
                    
        except Exception as e:
            log.warning(f"[Enhanced ML] Enhanced payload ranking failed: {e}, falling back to legacy")
            enhanced_engine = None

    # Legacy ML path (fallback)
    # Prepare endpoint vector (validates shape; may infer ep_dim if meta lacked it)
    ep_vec = _endpoint_vec(endpoint_meta)

    # Load model (joblib → booster JSON fallback)
    model = _load_model(family, model_dir=model_dir)
    used_model_path = str(_model_path_for(family, model_dir))
    if model is None:
        log.info("[LTR] Using heuristic fallback for %s (no model).", family)
        scored = [
            (c, _fallback_score(c.get("payload", "") or "", family, endpoint_meta.get("param", "")))
            for c in candidates
        ]
        ranked = []
        for c, s in sorted(scored, key=lambda z: z[1], reverse=True):
            x = dict(c)
            x["ranker_score"] = float(s)
            x["ranker_used_model"] = None
            x["ranker_feature_dim_total"] = None
            ranked.append(x)
        return ranked[:top_k] if top_k else ranked

    # Build design matrix
    rows: List[List[float]] = []
    ids: List[int] = []
    for i, c in enumerate(candidates):
        desc = _payload_desc(c.get("payload"), c.get("payload_id"))
        row = ep_vec + desc
        rows.append(row)
        ids.append(i)

    # Enforce dimensions: if meta missed payload/total dims, infer safely now
    ep_dim, pay_dim, total_expected = _expected_dims()
    if pay_dim is None:
        _META["payload_dims"] = 20  # fixed by construction
        pay_dim = 20
    if total_expected is None and ep_dim is not None and pay_dim is not None:
        _META["expected_total_dim"] = int(ep_dim) + int(pay_dim)
        total_expected = _META["expected_total_dim"]

    if rows:
        got_total = len(rows[0])
        if total_expected is not None and got_total != total_expected:
            raise ValueError(
                f"[LTR] Total feature shape mismatch: got {got_total}, expected {total_expected}. "
                f"Check endpoint/payload feature builders vs training."
            )

    X = np.asarray(rows, dtype=float)

    # Score
    scores = _pick_scores(model, X)

    order = list(np.argsort(-scores))
    if top_k is not None:
        order = order[:top_k]

    ranked: List[Dict[str, Any]] = []
    for idx in order:
        c = dict(candidates[ids[idx]])
        c["ranker_score"] = float(scores[idx])
        c["ranker_used_model"] = used_model_path
        c["ranker_feature_dim_total"] = int(len(rows[0])) if rows else None
        ranked.append(c)
    return ranked
