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

    # Get default payloads from manifest first, or use context-aware for XSS
    if fam == "xss" and xss_context and xss_escaping:
        # Use context-aware payload selection for XSS
        try:
            from backend.modules.payloads import payload_pool_for_xss
            default_payloads = payload_pool_for_xss(xss_context, xss_escaping)
        except ImportError:
            # Fallback to manifest defaults
            default_payloads = _get_default_payloads(fam)
    else:
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

    # Try to use ML model if available and USE_ML is enabled
    if USE_ML:
        model = _load_model(fam)
        calibration = _load_calibration(fam)

        if model is not None:
            try:
                results = []
                model_tag = f"family_{fam}.joblib"
                
                for i, payload in enumerate(default_payloads[:top_k]):
                    # Create payload-specific features
                    payload_features = features.copy()
                    payload_features['payload'] = payload
                    payload_features['payload_len'] = len(payload)
                    
                    # Use actual model prediction if available
                    try:
                        # Convert features to model input format
                        # For now, use a simplified approach - in production this would use proper feature vectorization
                        feature_vector = []
                        for key in sorted(payload_features.keys()):
                            val = payload_features[key]
                            if isinstance(val, (int, float)):
                                feature_vector.append(val)
                            elif isinstance(val, bool):
                                feature_vector.append(1.0 if val else 0.0)
                            elif isinstance(val, str):
                                feature_vector.append(len(val))
                            else:
                                feature_vector.append(0.0)
                        
                        # Pad or truncate to expected feature count (models expect fixed feature count)
                        expected_features = 20  # Adjust based on actual model training
                        while len(feature_vector) < expected_features:
                            feature_vector.append(0.0)
                        feature_vector = feature_vector[:expected_features]
                        
                        # Get model prediction
                        if hasattr(model, 'predict_proba'):
                            proba = model.predict_proba([feature_vector])
                            base_score = float(proba[0][1]) if len(proba[0]) > 1 else float(proba[0][0])
                        else:
                            base_score = float(model.predict([feature_vector])[0])
                            
                    except Exception:
                        # Fallback to heuristic scoring if model prediction fails
                        base_score = 0.5
                        
                        # Boost score based on relevant features
                        if fam == 'xss':
                            if payload_features.get('has_script_tag', 0):
                                base_score += 0.2
                            if payload_features.get('has_event_handler', 0):
                                base_score += 0.15
                            if payload_features.get('probe_reflection_html', 0):
                                base_score += 0.1
                        elif fam == 'sqli':
                            if payload_features.get('sql_kw_hits', 0) > 0:
                                base_score += 0.2
                            if payload_features.get('probe_sql_error', 0):
                                base_score += 0.15
                            if payload_features.get('has_comment_seq', 0):
                                base_score += 0.1
                        elif fam == 'redirect':
                            if payload_features.get('probe_redirect_location_reflects', 0):
                                base_score += 0.2
                    
                    # Apply calibration if available
                    if calibration and "a" in calibration and "b" in calibration:
                        p_cal = _apply_platt_calibration(base_score, calibration["a"], calibration["b"])
                    else:
                        p_cal = base_score

                    results.append({
                        "payload": payload,
                        "score": base_score,
                        "p_cal": p_cal,
                        "rank_source": "ctx_pool" if (fam == "xss" and xss_context and xss_escaping) else "ml",
                        "model_tag": model_tag,
                        "family": fam
                    })

                # Sort by p_cal descending
                results.sort(key=lambda x: x["p_cal"], reverse=True)
                return results

            except Exception as e:
                # If ML model fails and REQUIRE_RANKER is set, fail the request
                if REQUIRE_RANKER:
                    raise RuntimeError(f"ML ranker failed for family {fam}: {str(e)}")
                # Otherwise fall back to defaults
                pass

    # Fallback to default payloads without ML - use score=None, p_cal=0.50 as specified
    return [{"payload": p, "score": None, "p_cal": 0.50, "rank_source": "ctx_pool" if (fam == "xss" and xss_context and xss_escaping) else "defaults", "model_tag": None, "family": fam} for p in default_payloads[:top_k]]


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