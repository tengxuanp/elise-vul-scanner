# backend/modules/ml_ranker.py
from __future__ import annotations
"""
ML ranker with per-family model loading, XGBRanker support, and schema-aware projection.

It tries in this order to determine feature order/size:
1) Family-specific schema JSON (feature name list).
2) Global schema JSON in the model dir.
3) Model attributes: feature_names_in_ or n_features_in_.
4) Fallback to our canonical FEATURES and zero-pad to expected dim.

Env:
  ELISE_USE_ML=1
  ELISE_ML_DEBUG=1
  ELISE_ML_MODEL_DIR=/abs/path/to/backend/modules/ml
  ELISE_ML_MODEL_PATH=/path/to/generic.joblib   # optional
  ELISE_ML_SCHEMA_PATH=/path/to/schema.json     # optional override
"""

import os
import math
import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

import joblib
import numpy as np

# ---- Feature order is CONTRACT for runtime-produced features. ----
FEATURES: List[str] = [
    "status_delta",
    "len_delta_abs",
    "ms_delta_over_1500",
    "ct_is_json",
    "sql_error",
    "xss_js",
    "xss_raw",
    "open_redirect",
    "login_success",
    "payload_family_sqli",
    "payload_family_xss",
    "payload_family_redirect",
]

_USE_ML: bool = os.getenv("ELISE_USE_ML", "1") != "0"
_DEBUG: bool = os.getenv("ELISE_ML_DEBUG", "0") == "1"
# If set, do not silently fall back when models are missing or broken
_REQUIRE_RANKER: bool = os.getenv("ELISE_REQUIRE_RANKER", "0") == "1"

_DEFAULT_MODEL_DIR = Path(__file__).with_name("ml")
MODEL_DIR: Path = Path(os.getenv("ELISE_ML_MODEL_DIR", str(_DEFAULT_MODEL_DIR)))

MODEL_FILES: Dict[str, str] = {
    "sqli": "ranker_sqli.joblib",
    "xss": "ranker_xss.joblib",
    "redirect": "ranker_redirect.joblib",
}

GENERIC_MODEL_PATH: Optional[Path] = (
    Path(os.getenv("ELISE_ML_MODEL_PATH")) if os.getenv("ELISE_ML_MODEL_PATH") else None
)

SCHEMA_OVERRIDE: Optional[Path] = (
    Path(os.getenv("ELISE_ML_SCHEMA_PATH")) if os.getenv("ELISE_ML_SCHEMA_PATH") else None
)

_MODELS: Dict[str, Optional[object]] = {}      # cache: family/generic -> model
_SCHEMAS: Dict[str, Optional[List[str]]] = {}  # cache: family/global -> feature name list


def _dbg(msg: str) -> None:
    if _DEBUG:
        print(f"[ML-RANKER] {msg}")


def _family_alias(fam: str) -> str:
    f = (fam or "").lower().strip()
    if f in ("open_redirect", "open-redirect"):
        return "redirect"
    return f


def _one_hot_family(fam: str) -> Dict[str, int]:
    fam = _family_alias(fam)
    return {
        "payload_family_sqli": 1 if fam == "sqli" else 0,
        "payload_family_xss": 1 if fam == "xss" else 0,
        "payload_family_redirect": 1 if fam == "redirect" else 0,
    }


def featurize(attempt: Dict[str, Any]) -> Dict[str, float]:
    sig = attempt.get("detector_hits") or attempt.get("signals") or {}
    refl = {}
    if isinstance(attempt.get("signals"), dict):
        refl = attempt["signals"].get("reflection", {}) or {}

    fam = (attempt.get("payload_family_used") or attempt.get("family_hint") or "").lower()

    status_delta = int(attempt.get("status_delta") or 0)
    len_delta = int(attempt.get("len_delta") or 0)
    ms_delta = int(attempt.get("latency_ms_delta") or 0)
    ct = (
        (attempt.get("response", {}).get("headers", {}) or {}).get("content-type", "")
        or attempt.get("response_headers", {}).get("content-type", "")
        or ""
    )

    d: Dict[str, float] = {
        "status_delta": status_delta,
        "len_delta_abs": abs(len_delta),
        "ms_delta_over_1500": max(0, ms_delta - 1500),
        "ct_is_json": 1.0 if "application/json" in str(ct).lower() else 0.0,
        "sql_error": 1.0 if sig.get("sql_error") else 0.0,
        "xss_js": 1.0 if (sig.get("xss_js") or (isinstance(refl, dict) and refl.get("js_context"))) else 0.0,
        "xss_raw": 1.0 if (sig.get("xss_raw") or (isinstance(refl, dict) and refl.get("raw"))) else 0.0,
        "open_redirect": 1.0 if sig.get("open_redirect") else 0.0,
        "login_success": 1.0 if sig.get("login_success") else 0.0,
        **_one_hot_family(fam),
    }
    return d


# ----------------- Schema discovery / projection -----------------

def _read_schema_file(path: Path) -> Optional[List[str]]:
    try:
        obj = json.loads(path.read_text())
        # accept several possible shapes
        for k in ("feature_names", "feature_names_", "features"):
            if isinstance(obj.get(k), list) and all(isinstance(x, str) for x in obj[k]):
                return obj[k]
        # combine sublists if provided
        if isinstance(obj.get("endpoint_features"), list) or isinstance(obj.get("payload_features"), list):
            ef = obj.get("endpoint_features") or []
            pf = obj.get("payload_features") or []
            names = [str(x) for x in list(ef) + list(pf)]
            return names if names else None
        return None
    except Exception as e:
        _dbg(f"schema read failed at {path}: {e}")
        return None


def _schema_paths_for(fam: str) -> List[Path]:
    fam = _family_alias(fam)
    candidates: List[Path] = []
    if SCHEMA_OVERRIDE:
        candidates.append(SCHEMA_OVERRIDE)
    # family-specific
    candidates.append(MODEL_DIR / f"ranker_{fam}.meta.json")
    candidates.append(MODEL_DIR / f"{fam}.meta.json")
    # global
    candidates.append(MODEL_DIR / "ranker.meta.json")
    candidates.append(MODEL_DIR / "recommender_meta.json")
    return candidates


def _load_schema_for(fam: str, model: Optional[object]) -> Tuple[Optional[List[str]], Optional[int]]:
    """
    Returns (feature_names, expected_dim). feature_names may be None; expected_dim may be None.
    """
    key = f"schema::{fam or 'generic'}"
    if key in _SCHEMAS:
        names = _SCHEMAS[key]
        # try to provide expected_dim too
        exp_dim = len(names) if names else getattr(model, "n_features_in_", None)
        return names, int(exp_dim) if exp_dim is not None else None

    # Try files
    for p in _schema_paths_for(fam):
        if p.exists():
            names = _read_schema_file(p)
            if names:
                _SCHEMAS[key] = names
                _dbg(f"loaded schema for {fam or 'generic'} from {p} (n={len(names)})")
                return names, len(names)

    # Try model attributes
    names_attr = None
    exp_dim = None
    try:
        if model is not None and hasattr(model, "feature_names_in_"):
            arr = getattr(model, "feature_names_in_")
            if hasattr(arr, "tolist"):
                arr = arr.tolist()
            names_attr = [str(x) for x in arr] if isinstance(arr, (list, tuple)) else None
    except Exception as e:
        _dbg(f"feature_names_in_ unavailable: {e}")
        names_attr = None

    try:
        if model is not None and hasattr(model, "n_features_in_"):
            exp_dim = int(getattr(model, "n_features_in_"))
    except Exception:
        exp_dim = None

    _SCHEMAS[key] = names_attr  # may be None
    return names_attr, exp_dim


def _vector_for_model(feats: Dict[str, float], model: Optional[object], fam: str) -> np.ndarray:
    """
    Project to model's expected space:
      - If we have an explicit feature name ORDER, fill by name.
      - Else, use our FEATURES order and pad/truncate to model.n_features_in_ if available.
    """
    names, exp_dim = _load_schema_for(fam, model)

    # Case A: we know the exact ORDER of feature names
    if names:
        N = len(names)
        row = np.zeros((1, N), dtype=float)
        for i, name in enumerate(names):
            row[0, i] = float(feats.get(name, 0.0))
        return row

    # Case B: no names; use our canonical order and pad/truncate as needed
    base = np.array([[float(feats.get(k, 0.0)) for k in FEATURES]], dtype=float)
    if exp_dim is None:
        return base
    cur = base.shape[1]
    if cur == exp_dim:
        return base
    if cur > exp_dim:
        _dbg(f"truncating features from {cur} -> {exp_dim}")
        return base[:, :exp_dim]
    # pad with zeros
    pad = np.zeros((1, exp_dim - cur), dtype=float)
    out = np.concatenate([base, pad], axis=1)
    _dbg(f"padding features from {cur} -> {exp_dim}")
    return out


# ----------------- Model loading / prediction -----------------

def _load_model_for(fam: str) -> Optional[object]:
    """Load model for the given family or raise if it cannot be loaded."""
    if not _USE_ML:
        return None
    fam = _family_alias(fam)
    key = fam or "generic"
    if key in _MODELS:
        mdl = _MODELS[key]
        if mdl is None:
            raise RuntimeError(f"ML model for {key} previously failed to load")
        return mdl

    path: Optional[Path] = None
    if fam in MODEL_FILES:
        path = MODEL_DIR / MODEL_FILES[fam]
    elif GENERIC_MODEL_PATH:
        path = GENERIC_MODEL_PATH

    if not path or not path.exists():
        msg = f"model path not found for {key}: {path}"
        _MODELS[key] = None
        _dbg(msg)
        raise RuntimeError(msg)

    try:
        mdl = joblib.load(path)
        _MODELS[key] = mdl
        _dbg(f"loaded {key} model from {path}")
        return mdl
    except Exception as e:
        msg = f"failed to load {key} model at {path}: {e}"
        _MODELS[key] = None
        _dbg(msg)
        raise RuntimeError(msg)


def _predict_with_model(model: object, feats: Dict[str, float], fam: str) -> Dict[str, Any]:
    """
    Use predict_proba when available; else predict() + sigmoid. Handles dim mismatches via _vector_for_model.
    """
    X = _vector_for_model(feats, model, fam)

    # Classifier path
    if hasattr(model, "predict_proba"):
        try:
            proba = model.predict_proba(X)
            if hasattr(proba, "shape") and len(proba.shape) == 2 and proba.shape[1] >= 2:
                p = float(proba[0, 1])
            else:
                p = float(np.ravel(proba)[0])
            return {"p": p, "meta": {"method": "predict_proba", "dim": int(X.shape[1])}}
        except Exception as e:
            _dbg(f"predict_proba failed: {e}")

    # Ranker / regressor path
    if hasattr(model, "predict"):
        try:
            score = float(np.ravel(model.predict(X))[0])
            p = 1.0 / (1.0 + math.exp(-score))  # squash for UI consistency
            return {"p": p, "meta": {"method": "predict_sigmoid", "raw": score, "dim": int(X.shape[1])}}
        except Exception as e:
            _dbg(f"predict failed: {e}")

    raise RuntimeError("model has neither usable predict_proba nor predict")


def _fallback_logistic(feats: Dict[str, float]) -> float:
    w = (
        1.3 * feats.get("sql_error", 0)
        + 1.2 * feats.get("open_redirect", 0)
        + 0.9 * feats.get("xss_js", 0)
        + 0.4 * feats.get("xss_raw", 0)
        + 0.0008 * feats.get("len_delta_abs", 0)
        + 0.0006 * feats.get("ms_delta_over_1500", 0)
        + 0.25 * feats.get("ct_is_json", 0)
        + 0.15 * feats.get("payload_family_sqli", 0)
    )
    return 1.0 / (1.0 + math.exp(-w))


def predict_proba(attempt: Dict[str, Any]) -> Dict[str, Any]:
    feats = featurize(attempt)
    fam = (attempt.get("payload_family_used") or attempt.get("family_hint") or "").lower()

    err_msg: Optional[str] = None
    try:
        model = _load_model_for(fam)
    except Exception as e:
        if _REQUIRE_RANKER:
            raise
        err_msg = str(e)
        _dbg(err_msg)
        model = None
    if model is None and GENERIC_MODEL_PATH:
        try:
            model = _load_model_for("generic")
        except Exception as e:
            if _REQUIRE_RANKER:
                raise
            err_msg = str(e)
            _dbg(err_msg)
            model = None

    if model is not None:
        try:
            out = _predict_with_model(model, feats, fam)
            src = f"ml:{_family_alias(fam) or 'generic'}"
            payload = {"p": out["p"], "feats": feats if _DEBUG else None, "source": src}
            if _DEBUG and "meta" in out:
                payload["meta"] = out["meta"]
            return payload
        except Exception as e:
            _dbg(f"inference failed for {fam or 'generic'}: {e}")

    # Fallback path
    proba = _fallback_logistic(feats)
    payload = {"p": proba, "feats": feats if _DEBUG else None, "source": "fallback"}
    if err_msg:
        payload["ranker_error"] = err_msg
    return payload


# ----------------- Diagnostics -----------------

def model_info() -> Dict[str, Any]:
    return {
        "use_ml": _USE_ML,
        "debug": _DEBUG,
        "model_dir": str(MODEL_DIR),
        "generic_model_path": str(GENERIC_MODEL_PATH) if GENERIC_MODEL_PATH else None,
        "known_files": {k: str(MODEL_DIR / v) for k, v in MODEL_FILES.items()},
        "cache_keys": list(_MODELS.keys()),
    }


def reset_model_cache() -> None:
    _MODELS.clear()
    _SCHEMAS.clear()
