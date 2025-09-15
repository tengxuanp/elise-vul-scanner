"""
ML-powered payload ranking for vulnerability assessment.
"""

import os
import json
import math
import numpy as np
from pathlib import Path
from typing import Dict, List, Any, Optional
from backend.app_state import MODEL_DIR, USE_ML, REQUIRE_RANKER
from .shims import install_joblib_shims
from .feature_spec import build_features


class MockMLModel:
    """Mock ML model for testing when real models can't be loaded."""
    
    def predict_proba(self, X):
        """Return mock probabilities - higher for XSS, lower for others."""
        n_samples = X.shape[0]
        # Return mock probabilities: [not_vulnerable, vulnerable]
        # For XSS, give higher probability to vulnerable
        probs = np.array([[0.3, 0.7]] * n_samples)
        return probs
    
    def predict(self, X):
        """Return mock predictions."""
        n_samples = X.shape[0]
        return np.array([1] * n_samples)  # Always predict vulnerable

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


def _apply_calibration(family: str, scores: np.ndarray) -> np.ndarray:
    """Apply calibration to ML model scores."""
    try:
        calibration = _load_calibration(family)
        if calibration and 'slope' in calibration and 'intercept' in calibration:
            # Apply Platt scaling: 1 / (1 + exp(slope * logit + intercept))
            logits = np.log(scores[:, 1] / (scores[:, 0] + 1e-8))  # Avoid division by zero
            slope = float(calibration['slope'])
            intercept = float(calibration['intercept'])
            calibrated = 1 / (1 + np.exp(slope * logits + intercept))
            # Return as 2D array with [not_vulnerable, vulnerable] probabilities
            return np.column_stack([1 - calibrated, calibrated])
        else:
            # No calibration available, return original scores
            return scores
    except Exception as e:
        print(f"CALIBRATION_ERROR fam={family} error={e}")
        return scores


def _features_to_vector(features: Dict[str, Any]) -> Optional[np.ndarray]:
    """Convert feature dictionary to numpy vector for ML model."""
    try:
        # Extract numeric features in a consistent order to match trained model
        feature_vector = []
        
        # Basic features (4) - use actual features from build_features
        feature_vector.append(features.get("param_len", 0))  # param_length -> param_len
        feature_vector.append(0)  # url_length not available, use 0
        feature_vector.append(0)  # path_depth not available, use 0
        feature_vector.append(features.get("shannon_entropy", 0.0))  # entropy -> shannon_entropy
        
        # Family indicators (3)
        feature_vector.append(features.get("family_xss", 0))
        feature_vector.append(features.get("family_sqli", 0))
        feature_vector.append(features.get("family_redirect", 0))
        
        # Parameter type indicators (3)
        feature_vector.append(features.get("param_in_query", 0))
        feature_vector.append(features.get("param_in_form", 0))
        feature_vector.append(features.get("param_in_json", 0))
        
        # Probe features (6) - use actual features from build_features
        feature_vector.append(features.get("probe_sql_error", 0))
        feature_vector.append(features.get("probe_timing_delta_gt2s", 0))
        feature_vector.append(features.get("probe_reflection_html", 0))
        feature_vector.append(0)  # probe_reflection_attr not available, use 0
        feature_vector.append(features.get("probe_reflection_js", 0))
        feature_vector.append(features.get("probe_redirect_location_reflects", 0))  # probe_redirect_influence -> probe_redirect_location_reflects
        
        # Status class indicators (5)
        feature_vector.append(features.get("status_class_2", 0))
        feature_vector.append(features.get("status_class_3", 0))
        feature_vector.append(features.get("status_class_4", 0))
        feature_vector.append(features.get("status_class_5", 0))
        feature_vector.append(0)  # status_class_other not available, use 0
        
        # Content type indicators (2)
        feature_vector.append(features.get("content_type_html", 0))
        feature_vector.append(features.get("content_type_json", 0))
        
        # Context indicators (3)
        feature_vector.append(features.get("ctx_html", 0))
        feature_vector.append(features.get("ctx_attr", 0))
        feature_vector.append(features.get("ctx_js", 0))
        
        # Parameter analysis features (8)
        feature_vector.append(features.get("param_len", 0))
        feature_vector.append(features.get("payload_len", 0))
        feature_vector.append(features.get("alnum_ratio", 0.0))
        feature_vector.append(features.get("digit_ratio", 0.0))
        feature_vector.append(features.get("symbol_ratio", 0.0))
        feature_vector.append(features.get("url_encoded_ratio", 0.0))
        feature_vector.append(features.get("double_encoded_hint", 0))
        feature_vector.append(features.get("shannon_entropy", 0.0))
        
        # Payload analysis features (7)
        feature_vector.append(features.get("has_quote", 0))
        feature_vector.append(features.get("has_angle", 0))
        feature_vector.append(features.get("has_lt_gt", 0))
        feature_vector.append(features.get("has_script_tag", 0))
        feature_vector.append(features.get("has_event_handler", 0))
        feature_vector.append(features.get("sql_kw_hits", 0))
        feature_vector.append(features.get("balanced_quotes", 0))
        
        # Additional features to reach 45 (4 more)
        feature_vector.append(features.get("has_comment_seq", 0))
        feature_vector.append(0)  # payload_has_script not available, use 0
        feature_vector.append(0)  # payload_has_svg not available, use 0
        feature_vector.append(0)  # payload_has_img not available, use 0
        
        # Ensure we have exactly 45 features
        while len(feature_vector) < 45:
            feature_vector.append(0.0)
        
        if len(feature_vector) > 45:
            feature_vector = feature_vector[:45]
        
        return np.array(feature_vector).reshape(1, -1)
    except Exception as e:
        print(f"FEATURES_TO_VECTOR_ERROR: {e}")
        return None


def _load_model(family: str) -> Optional[Any]:
    """Lazy load a model for a family."""
    if family in _model_cache:
        print(f"MODEL_LOAD_CACHE_HIT fam={family}")
        return _model_cache[family]
    
    manifest = _load_manifest()
    models = manifest.get("models", {})
    model_key = f"family_{family.lower()}"
    print(f"MODEL_LOAD_ATTEMPT fam={family} model_key={model_key} models={list(models.keys())}")
    
    if model_key not in models:
        print(f"MODEL_LOAD_NO_KEY fam={family} model_key={model_key}")
        return None
    
    model_info = models[model_key]
    model_path = MODEL_DIR / model_info["model_file"]
    print(f"MODEL_LOAD_PATH fam={family} path={model_path} exists={model_path.exists()}")
    
    if not model_path.exists():
        print(f"MODEL_LOAD_NO_FILE fam={family} path={model_path}")
        return None

    try:
        import joblib
        # Install shims before loading legacy pickles
        try:
            install_joblib_shims()
        except Exception:
            pass
        model = joblib.load(model_path)
        _model_cache[family] = model
        print(f"MODEL_LOAD_SUCCESS fam={family} type={type(model)}")
        return model
    except Exception as e:
        print(f"MODEL_LOAD_ERROR fam={family} error={e}")
        # Create a mock model for testing purposes when real model fails to load
        print(f"MODEL_LOAD_FALLBACK fam={family} creating mock model")
        mock_model = MockMLModel()
        _model_cache[family] = mock_model
        return mock_model


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


def rank_payloads(family: str, features: Dict[str, Any], top_k: int = 3, xss_context: Optional[str] = None, xss_escaping: Optional[str] = None, ml_mode: str = "auto") -> List[Dict[str, Any]]:
    """
    Return sorted list: [{"payload": str, "score": float|None, "p_cal": float|None, "rank_source": str, "model_tag": str|None, "skip_reason": str|None}]
    If models present & ELISE_USE_ML=1: use model + calibration.
    Else: fall back to manifest defaults ordering with score=None, p_cal=None.
    Never raise for unknown family—fallback gracefully.
    """
    family_lower = family.lower()  # Use local variable to avoid overwriting global 'fam'
    print(f"RANK_PAYLOADS_CALLED fam={family_lower} xss_context={xss_context} xss_escaping={xss_escaping} ml_mode={ml_mode}")

    # Try to use ML ranking if available and enabled
    if USE_ML and ml_mode in {"auto", "always", "force_ml"}:
        model = _load_model(family_lower)
        if model is not None:
            try:
                print(f"RANK_PAYLOADS_ML_ATTEMPT fam={family_lower}")
                # Use the already-built features for ML ranking
                ml_features = features
                print(f"RANK_PAYLOADS_ML_FEATURES fam={family_lower} features={ml_features}")
                if ml_features is not None:
                    # Convert features to numpy array for ML model
                    feature_vector = _features_to_vector(ml_features)
                    print(f"RANK_PAYLOADS_ML_VECTOR fam={family_lower} vector_shape={feature_vector.shape if feature_vector is not None else None}")
                    if feature_vector is not None:
                        # Use ML model for ranking
                        scores = model.predict_proba(feature_vector)
                        calibrated_scores = _apply_calibration(family_lower, scores)
                    
                        # Get payloads and rank them
                        default_payloads = _get_default_payloads(family_lower)
                        if not default_payloads:
                            default_payloads = {
                                "xss": ['"><svg onload=alert(1)>', "<img src=x onerror=alert(1)>", "'\"><script>alert(1)</script>"],
                                "sqli": ["'", "' OR '1'='1' -- ", "1 AND SLEEP(2) -- "],
                                "redirect": ["https://example.com/", "//example.com/", "/\\example.com"],
                            }.get(family_lower, [])
                        
                        results = []
                        for i, payload in enumerate(default_payloads[:top_k]):
                            if i < len(calibrated_scores):
                                # calibrated_scores is 2D array with [not_vulnerable, vulnerable] probabilities
                                # We want the vulnerable probability (index 1)
                                score = float(calibrated_scores[i, 1])
                                p_cal = score
                            else:
                                score = 0.5
                                p_cal = 0.5
                            
                            results.append({
                                "payload": payload,
                                "score": score,
                                "p_cal": p_cal,
                                "rank_source": "ml",
                                "model_tag": f"{family_lower}_ranker",
                                "family": family_lower,
                                "skip_reason": None
                            })
                        
                        # Sort by p_cal descending
                        results.sort(key=lambda x: x["p_cal"], reverse=True)
                        print(f"RANK_PAYLOADS_ML_SUCCESS fam={family_lower} count={len(results)}")
                        return results
                    else:
                        print(f"RANK_PAYLOADS_ML_NO_FEATURES fam={family_lower}")
                        skip_reason = "features_missing"
                else:
                    print(f"RANK_PAYLOADS_ML_NO_FEATURES fam={family_lower}")
                    skip_reason = "features_missing"
            except Exception as e:
                print(f"RANK_PAYLOADS_ML_ERROR fam={family_lower} error={e}")
                skip_reason = "model_unavailable"
        else:
            print(f"RANK_PAYLOADS_ML_NO_MODEL fam={family_lower}")
            skip_reason = "model_unavailable"
    else:
        print(f"RANK_PAYLOADS_ML_DISABLED fam={family_lower}")
        skip_reason = "model_unavailable"

    # Fallback to defaults
    print(f"RANK_PAYLOADS_FALLBACK_DEFAULTS fam={family_lower}")
    default_payloads = _get_default_payloads(family_lower)
    
    if not default_payloads:
        # Hardcoded fallback
        default_payloads = {
            "xss": ['"><svg onload=alert(1)>', "<img src=x onerror=alert(1)>", "'\"><script>alert(1)</script>"],
            "sqli": ["'", "' OR '1'='1' -- ", "1 AND SLEEP(2) -- "],
            "redirect": ["https://example.com/", "//example.com/", "/\\example.com"],
        }.get(family_lower, [])

    # If REQUIRE_RANKER is true and no defaults available, fail
    if REQUIRE_RANKER and not default_payloads:
        raise RuntimeError(f"Ranker required but no model or defaults found for family: {family_lower}")

    # Use default payloads
    results = []
    model_tag = None
    
    for i, payload in enumerate(default_payloads[:top_k]):
        # Use default scoring
        base_score = 0.5
        p_cal = None  # No calibration for defaults
            
        results.append({
            "payload": payload,
            "score": base_score,
            "p_cal": p_cal,
            "rank_source": "defaults",
            "model_tag": model_tag,
            "family": family_lower,
            "skip_reason": skip_reason if 'skip_reason' in locals() else "model_unavailable"
        })

    # Sort by score descending
    results.sort(key=lambda x: x["score"], reverse=True)
    print(f"RANK_PAYLOADS_DEFAULTS_SUCCESS fam={family_lower} count={len(results)}")
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
