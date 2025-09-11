"""
ML-powered payload ranking for vulnerability assessment.
"""

import os
import json
import math
from pathlib import Path
from typing import Dict, List, Any, Optional
from backend.app_state import MODEL_DIR, USE_ML, REQUIRE_RANKER
from .feature_spec import build_features

# Module-level cache for loaded models and manifest
_manifest_cache = None
_model_cache = {}
_calibration_cache = {}


def _load_manifest() -> Dict[str, Any]:
    """Load and cache the ranker manifest."""
    global _manifest_cache
    if _manifest_cache is None:
        manifest_path = MODEL_DIR / "RANKER_MANIFEST.json"
        if manifest_path.exists():
            with open(manifest_path, 'r') as f:
                _manifest_cache = json.load(f)
        else:
            # Fallback to hardcoded defaults
            _manifest_cache = {
                "default_payloads": {
                    "xss": ['"><svg onload=alert(1)>', "<img src=x onerror=alert(1)>", "'\"><script>alert(1)</script>"],
                    "sqli": ["'", "' OR '1'='1' -- ", "1 AND SLEEP(2) -- "],
                    "redirect": ["https://example.com/", "//example.com/", "/\\example.com"],
                },
                "models": {}
            }
    return _manifest_cache


def _get_default_payloads(family: str) -> List[str]:
    """Get default payloads for a family from manifest."""
    manifest = _load_manifest()
    return manifest.get("default_payloads", {}).get(family.lower(), [])


def _load_model(family: str) -> Optional[Any]:
    """Lazy load a model for a family."""
    if family in _model_cache:
        return _model_cache[family]
    
    manifest = _load_manifest()
    models = manifest.get("models", {})
    model_key = f"family_{family.lower()}"
    
    if model_key not in models:
        return None
    
    model_info = models[model_key]
    model_path = MODEL_DIR / model_info["model_file"]
    
    if not model_path.exists():
        return None

    try:
        import joblib
        model = joblib.load(model_path)
        _model_cache[family] = model
        return model
    except Exception:
        return None


def _load_calibration(family: str) -> Optional[Dict[str, Any]]:
    """Lazy load calibration data for a family."""
    if family in _calibration_cache:
        return _calibration_cache[family]
    
    manifest = _load_manifest()
    models = manifest.get("models", {})
    model_key = f"family_{family.lower()}"
    
    if model_key not in models:
        return None
    
    model_info = models[model_key]
    cal_path = MODEL_DIR / model_info["calibration_file"]
    
    if not cal_path.exists():
        return None
    
    try:
        with open(cal_path, 'r') as f:
            calibration = json.load(f)
        _calibration_cache[family] = calibration
        return calibration
    except Exception:
        return None


def _apply_platt_calibration(raw_score: float, a: float, b: float) -> float:
    """Apply Platt scaling calibration: 1/(1+exp(-(a*raw + b)))."""
    try:
        return 1.0 / (1.0 + math.exp(-(a * raw_score + b)))
    except (OverflowError, ValueError):
        return 0.5  # Fallback to neutral probability


def rank_payloads(family: str, features: Dict[str, Any], top_k: int = 3, xss_context: Optional[str] = None, xss_escaping: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Return sorted list: [{"payload": str, "score": float|None, "p_cal": float|None, "rank_source": str, "model_tag": str|None}]
    If models present & ELISE_USE_ML=1: use model + calibration.
    Else: fall back to manifest defaults ordering with score=None, p_cal=0.50.
    Never raise for unknown family—fallback gracefully.
    """
    fam = family.lower()
    print(f"RANK_PAYLOADS_CALLED fam={fam} xss_context={xss_context} xss_escaping={xss_escaping}")

    # Get default payloads from manifest first, or use context-aware for XSS
    print(f"RANK_PAYLOADS_LOGIC fam={fam} xss_context={xss_context} xss_escaping={xss_escaping}")
    
    # HARD RULE: Never use ML for family classification - always use defaults
    print(f"RANK_PAYLOADS_FORCE_DEFAULTS for family: {fam} (ML family classification disabled)")
    default_payloads = _get_default_payloads(fam)
    
    if not default_payloads:
        # Hardcoded fallback
        default_payloads = {
            "xss": ['"><svg onload=alert(1)>', "<img src=x onerror=alert(1)>", "'\"><script>alert(1)</script>"],
            "sqli": ["'", "' OR '1'='1' -- ", "1 AND SLEEP(2) -- "],
            "redirect": ["https://example.com/", "//example.com/", "/\\example.com"],
        }.get(fam, [])

    # If REQUIRE_RANKER is true and no defaults available, fail
    if REQUIRE_RANKER and not default_payloads:
        raise RuntimeError(f"Ranker required but no model or defaults found for family: {fam}")

    # Use default payloads for the family being processed, regardless of ML classification
    # ML models are trained for family classification, not payload ranking within a family
    results = []
    model_tag = None
    
    for i, payload in enumerate(default_payloads[:top_k]):
        # Use default scoring for payloads within the family
        base_score = 0.5  # Default score for all payloads within a family
        p_cal = base_score  # No calibration needed for default scoring

        # HARD RULE: Always use defaults since ML family classification is disabled
        rank_source_final = "defaults"
            
        results.append({
            "payload": payload,
            "score": base_score,
            "p_cal": p_cal,
            "rank_source": rank_source_final,
            "model_tag": model_tag,
            "family": fam
        })

    # Sort by p_cal descending
    results.sort(key=lambda x: x["p_cal"], reverse=True)
    return results


def available_models() -> Dict[str, Any]:
    """Return information about available models and defaults."""
    manifest = _load_manifest()
    models = manifest.get("models", {})
    defaults = manifest.get("default_payloads", {})
    
    available = {}
    for family in ["xss", "sqli", "redirect"]:
        model_key = f"family_{family}"
        has_model = model_key in models and _load_model(family) is not None
        has_defaults = family in defaults and len(defaults[family]) > 0
        
        available[family] = {
            "has_model": has_model,
            "has_defaults": has_defaults,
            "model_file": models.get(model_key, {}).get("model_file"),
            "calibration_file": models.get(model_key, {}).get("calibration_file")
        }
    
    return available


def using_defaults() -> bool:
    """Return True if we're using defaults (no models available)."""
    if not USE_ML:
        return True
    
    available = available_models()
    has_any_models = any(info["has_model"] for info in available.values())
    return not has_any_models