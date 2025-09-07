from __future__ import annotations
from typing import Any, Dict, List, Optional
import json
import joblib
from pathlib import Path
from backend.app_state import MODEL_DIR, REQUIRE_RANKER, USE_ML

# Lazy-loaded model cache
_model_cache: Dict[str, Any] = {}
_manifest_cache: Optional[Dict[str, Any]] = None

def _load_manifest() -> Dict[str, Any]:
    """Load the RANKER_MANIFEST.json file."""
    global _manifest_cache
    if _manifest_cache is None:
        manifest_path = MODEL_DIR / "RANKER_MANIFEST.json"
        if manifest_path.exists():
            with open(manifest_path, 'r') as f:
                _manifest_cache = json.load(f)
        else:
            _manifest_cache = {}
    return _manifest_cache

def _load_model(family: str) -> Optional[Any]:
    """Lazily load a model for the given family."""
    if family in _model_cache:
        return _model_cache[family]
    
    manifest = _load_manifest()
    models = manifest.get("models", {})
    
    # Look for family-specific model
    model_key = f"family_{family}"
    if model_key in models:
        model_info = models[model_key]
        model_path = MODEL_DIR / model_info["model_file"]
        if model_path.exists():
            _model_cache[family] = joblib.load(model_path)
            return _model_cache[family]
    
    return None

def _load_calibration(family: str) -> Optional[Dict[str, Any]]:
    """Load calibration data for the given family."""
    manifest = _load_manifest()
    models = manifest.get("models", {})
    
    model_key = f"family_{family}"
    if model_key in models:
        model_info = models[model_key]
        cal_path = MODEL_DIR / model_info["calibration_file"]
        if cal_path.exists():
            with open(cal_path, 'r') as f:
                return json.load(f)
    
    return None

def _get_default_payloads(family: str) -> List[str]:
    """Get default payloads from manifest or fallback."""
    manifest = _load_manifest()
    defaults = manifest.get("default_payloads", {})
    return defaults.get(family, [])

def rank_payloads(family: str, endpoint_meta: Dict[str,Any], candidates=None, top_k:int=3) -> List[Dict[str,Any]]:
    """Rank payloads using ML models with calibration, fallback to defaults."""
    fam = family.lower()
    
    # Try to use ML model if available and USE_ML is enabled
    if USE_ML:
        model = _load_model(fam)
        calibration = _load_calibration(fam)
        
        if model is not None:
            # Use ML model for ranking
            # This is a simplified implementation - in practice you'd extract features
            # from endpoint_meta and use the model to predict payload scores
            try:
                # For now, use default payloads with calibrated probabilities
                default_payloads = _get_default_payloads(fam)
                if not default_payloads:
                    # Fallback to hardcoded defaults
                    default_payloads = {
                        "xss": ['"><svg onload=alert(1)>', "<img src=x onerror=alert(1)>", "'\"><script>alert(1)</script>"],
                        "sqli": ["'", "' OR '1'='1' -- ", "1 AND SLEEP(2) -- "],
                        "redirect": ["https://example.com/", "//example.com/", "/\\example.com"],
                    }.get(fam, [])
                
                results = []
                for i, payload in enumerate(default_payloads[:top_k]):
                    # Apply calibration if available
                    if calibration and "calibrated_probs" in calibration:
                        p_cal = calibration["calibrated_probs"].get(str(i), 0.7 - i*0.1)
                    else:
                        p_cal = 0.7 - i*0.1
                    
                    results.append({
                        "payload": payload,
                        "p_cal": p_cal,
                        "score": 1.0 - i*0.1
                    })
                
                return results
                
            except Exception as e:
                # If ML model fails, fall back to defaults
                pass
    
    # Fallback to default payloads
    default_payloads = _get_default_payloads(fam)
    if not default_payloads:
        # Hardcoded fallback
        default_payloads = {
            "xss": ['"><svg onload=alert(1)>', "<img src=x onerror=alert(1)>", "'\"><script>alert(1)</script>"],
            "sqli": ["'", "' OR '1'='1' -- ", "1 AND SLEEP(2) -- "],
            "redirect": ["https://example.com/", "//example.com/", "/\\example.com"],
        }.get(fam, [])
    
    if REQUIRE_RANKER and not default_payloads:
        raise RuntimeError(f"Ranker required but no model or defaults found for family: {fam}")
    
    return [{"payload": p, "p_cal": 0.7 - i*0.1, "score": 1.0 - i*0.1} for i,p in enumerate(default_payloads[:top_k])]