# backend/modules/ml_ranker.py
from __future__ import annotations
import os
import math
import joblib
import numpy as np
from typing import Dict, Any, List

# ---- Feature order is CONTRACT. Do not reorder without retraining. ----
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

_MODEL = None
_USE_ML = os.getenv("ELISE_USE_ML", "0") == "1"
_MODEL_PATH = os.getenv("ELISE_ML_MODEL_PATH", "./models/ranker.joblib")
_DEBUG = os.getenv("ELISE_ML_DEBUG", "0") == "1"

def _try_load():
    global _MODEL
    if not _USE_ML:
        return
    try:
        _MODEL = joblib.load(_MODEL_PATH)
    except Exception as e:
        _MODEL = None

_try_load()

def _one_hot_family(fam: str) -> Dict[str, int]:
    fam = (fam or "").lower()
    return {
        "payload_family_sqli": 1 if fam == "sqli" else 0,
        "payload_family_xss": 1 if fam == "xss" else 0,
        "payload_family_redirect": 1 if fam == "redirect" else 0,
    }

def featurize(attempt: Dict[str, Any]) -> Dict[str, float]:
    sig = attempt.get("detector_hits") or attempt.get("signals") or {}
    refl = attempt.get("signals", {}).get("reflection", {}) if attempt.get("signals") else {}
    fam = (attempt.get("payload_family_used") or "").lower()

    status_delta = int(attempt.get("status_delta") or 0)
    len_delta = int(attempt.get("len_delta") or 0)
    ms_delta = int(attempt.get("latency_ms_delta") or 0)
    ct = (attempt.get("response", {}).get("headers", {}) or {}).get("content-type", "") or \
         attempt.get("response_headers", {}).get("content-type", "") or ""

    d: Dict[str, float] = {
        "status_delta": status_delta,
        "len_delta_abs": abs(len_delta),
        "ms_delta_over_1500": max(0, ms_delta - 1500),
        "ct_is_json": 1.0 if "application/json" in ct.lower() else 0.0,
        "sql_error": 1.0 if sig.get("sql_error") else 0.0,
        "xss_js": 1.0 if sig.get("xss_js") or (refl.get("js_context") if isinstance(refl, dict) else False) else 0.0,
        "xss_raw": 1.0 if sig.get("xss_raw") or (refl.get("raw") if isinstance(refl, dict) else False) else 0.0,
        "open_redirect": 1.0 if sig.get("open_redirect") else 0.0,
        "login_success": 1.0 if sig.get("login_success") else 0.0,
        **_one_hot_family(fam),
    }
    return d

def _to_vector(feats: Dict[str, float]) -> np.ndarray:
    return np.array([[float(feats.get(k, 0.0)) for k in FEATURES]], dtype=float)

def _fallback_logistic(feats: Dict[str, float]) -> float:
    # Simple, calibrated-ish fallback so you’re never blind.
    w = (
        1.3*feats.get("sql_error", 0) +
        1.2*feats.get("open_redirect", 0) +
        0.9*feats.get("xss_js", 0) +
        0.4*feats.get("xss_raw", 0) +
        0.0008*feats.get("len_delta_abs", 0) +
        0.0006*feats.get("ms_delta_over_1500", 0) +
        0.25*feats.get("ct_is_json", 0) +
        0.15*feats.get("payload_family_sqli", 0)
    )
    return 1 / (1 + math.exp(-w))

def predict_proba(attempt: Dict[str, Any]) -> Dict[str, Any]:
    feats = featurize(attempt)
    if _MODEL is not None:
        try:
            proba = float(_MODEL.predict_proba(_to_vector(feats))[0, 1])
            return {"p": proba, "feats": feats if _DEBUG else None, "source": "ml"}
        except Exception:
            pass
    # Fallback path
    proba = _fallback_logistic(feats)
    return {"p": proba, "feats": feats if _DEBUG else None, "source": "fallback"}
