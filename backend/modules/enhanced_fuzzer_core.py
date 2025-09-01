# backend/modules/enhanced_fuzzer_core.py
"""
Enhanced Fuzzer Core with Enhanced ML Integration

This module replaces the existing ML calls in fuzzer_core.py with:
1. engine.predict_with_confidence() instead of _ranker_predict()
2. engine.rank_payloads() instead of _rank_payloads_for_family()
3. Enhanced feature extraction and confidence scoring
"""

from __future__ import annotations

import json
import time
import hashlib
import statistics
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional
from urllib.parse import urlparse, urlencode, urlunparse, parse_qs, quote

import httpx
try:
    from .detectors import (
        reflection_signals,
        sql_error_signal,
        score,
        open_redirect_signal,
        time_delay_signal,
        boolean_divergence_signal,
    )
except ImportError:
    # Fallback for direct execution
    from detectors import (
        reflection_signals,
        sql_error_signal,
        score,
        open_redirect_signal,
        time_delay_signal,
        boolean_divergence_signal,
    )

# Import enhanced ML system
try:
    from .ml.enhanced_inference import EnhancedInferenceEngine
    from .ml.enhanced_features import EnhancedFeatureExtractor
    _ENHANCED_ML_AVAILABLE = True
    print("✅ Enhanced ML system loaded successfully")
except ImportError:
    try:
        from ml.enhanced_inference import EnhancedInferenceEngine
        from ml.enhanced_features import EnhancedFeatureExtractor
        _ENHANCED_ML_AVAILABLE = True
        print("✅ Enhanced ML system loaded successfully (direct import)")
    except Exception as e:
        print(f"❌ Failed to load enhanced ML system: {e}")
        _ENHANCED_ML_AVAILABLE = False

TRUNCATE_BODY = 2048

# ----------------------------- Enhanced ML integration -------------------
# Initialize enhanced ML engine
_ENHANCED_ENGINE = None
_ENHANCED_FEATURE_EXTRACTOR = None

if _ENHANCED_ML_AVAILABLE:
    try:
        _ENHANCED_ENGINE = EnhancedInferenceEngine()
        _ENHANCED_FEATURE_EXTRACTOR = EnhancedFeatureExtractor()
        print(f"✅ Enhanced ML engine initialized: {_ENHANCED_ENGINE}")
    except Exception as e:
        print(f"❌ Failed to initialize enhanced ML engine: {e}")
        _ENHANCED_ML_AVAILABLE = False

# ----------------------------- Stage A/B integration -------------------------
# Prefer canonical payload pools from family_router if present; otherwise use payloads.py
try:
    from .family_router import (
        FamilyClassifier,
        payload_pool_for as _payload_pool_for_router,
        decide_family as _router_decide_family,
        DEFAULT_MIN_PROB as _ROUTER_MIN_PROB,
        DEFAULT_EXPLORE_TOPK as _ROUTER_EXPLORE_TOPK,
    )
except Exception:
    FamilyClassifier = None  # type: ignore
    _payload_pool_for_router = None  # type: ignore
    _router_decide_family = None  # type: ignore
    _ROUTER_MIN_PROB = None
    _ROUTER_EXPLORE_TOPK = None

# Always try our curated pools as a fallback
try:
    from .payloads import payload_pool_for as _payload_pool_for_payloads
except Exception:
    _payload_pool_for_payloads = None  # type: ignore

# Recommender (Stage-B ranker and family-clf fallback)
try:
    from .recommender import Recommender
except Exception:
    Recommender = None  # type: ignore

# Singletons & caches
_FEATURE_CACHE: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
try:
    # payload-agnostic endpoint features
    from .feature_extractor import FeatureExtractor  # type: ignore
    _FE = FeatureExtractor(headless=True)  # type: ignore
except Exception:
    _FE = None

_FAM = FamilyClassifier() if FamilyClassifier else None
_RECO = Recommender() if Recommender else None

# Load the ML recommender if available
if _RECO is not None:
    try:
        print(f"DEBUG: Loading ML Recommender: {_RECO}")
        _RECO.load()
        print(f"DEBUG: ML Recommender loaded successfully: {_RECO}")
        print(f"DEBUG: Recommender ready: {getattr(_RECO, 'ready', 'N/A')}")
        print(f"DEBUG: Recommender meta: {getattr(_RECO, 'meta', {})}")
    except Exception as e:
        print(f"DEBUG: Failed to load ML Recommender: {e}")
        _RECO = None
else:
    print("DEBUG: No Recommender available to load")

# Defaults if router constants are missing
DEFAULT_MIN_PROB = float(_ROUTER_MIN_PROB) if _ROUTER_MIN_PROB is not None else 0.55
DEFAULT_EXPLORE_TOPK = int(_ROUTER_EXPLORE_TOPK) if _ROUTER_EXPLORE_TOPK is not None else 2


def _endpoint_key(t: Dict[str, Any]) -> Tuple[str, str, str]:
    return ((t.get("method") or "GET").upper(), t.get("url") or "", t.get("target_param") or "")


def _cheap_target_vector(t: Dict[str, Any]) -> Dict[str, Any]:
    """Extract basic target features for ML."""
    return {
        "method": (t.get("method") or "GET").upper(),
        "url": t.get("url") or "",
        "target_param": t.get("target_param") or "",
        "content_type": t.get("content_type") or "",
    }


def _endpoint_features(t: Dict[str, Any]) -> Dict[str, Any]:
    """Extract endpoint features for ML."""
    key = _endpoint_key(t)
    if key in _FEATURE_CACHE:
        return _FEATURE_CACHE[key]

    # Basic features
    feats = _cheap_target_vector(t)
    
    # Enhanced features if available
    if _ENHANCED_FEATURE_EXTRACTOR and _ENHANCED_ML_AVAILABLE:
        try:
            endpoint = {
                "url": t.get("url", ""),
                "method": t.get("method", "GET"),
                "content_type": t.get("content_type", "")
            }
            param = {
                "name": t.get("target_param", ""),
                "value": t.get("control_value", ""),
                "loc": t.get("in", "query")
            }
            
            # Extract enhanced features for each family
            enhanced_features = {}
            for family in ["sqli", "xss", "redirect"]:
                family_features = _ENHANCED_FEATURE_EXTRACTOR.extract_enhanced_features(
                    endpoint, param, family
                )
                # Prefix family features to avoid conflicts
                for feat_name, feat_value in family_features.items():
                    enhanced_features[f"{family}_{feat_name}"] = feat_value
            
            feats.update(enhanced_features)
            
        except Exception as e:
            print(f"Warning: Enhanced feature extraction failed: {e}")
    
    # Legacy feature extraction if available
    if _FE is not None:
        try:
            legacy_feats = _FE.extract_features(t)
            feats.update(legacy_feats)
        except Exception as e:
            print(f"Warning: Legacy feature extraction failed: {e}")

    _FEATURE_CACHE[key] = feats
    return feats


def _enhanced_ml_predict(self, features: Dict[str, Any], family: str = None) -> Dict[str, Any]:
    """
    Enhanced ML prediction using the new system.
    
    Args:
        features: Feature dictionary
        family: Vulnerability family (optional, will be inferred if not provided)
    
    Returns:
        Dictionary with enhanced prediction results
    """
    if not _ENHANCED_ML_AVAILABLE or _ENHANCED_ENGINE is None:
        return {"p": 0.0, "source": "fallback", "enhanced": False}
    
    try:
        # Extract endpoint and parameter info from features
        endpoint = {
            "url": features.get("url", ""),
            "method": features.get("method", "GET"),
            "content_type": features.get("content_type", "")
        }
        
        param = {
            "name": features.get("target_param", ""),
            "value": features.get("control_value", ""),
            "loc": features.get("in", "query")
        }
        
        # If family not provided, try to infer from features
        if not family:
            # Simple heuristic based on parameter name
            param_name = param["name"].lower()
            if any(x in param_name for x in ["id", "user", "search", "query"]):
                family = "sqli"
            elif any(x in param_name for x in ["comment", "message", "content", "text"]):
                family = "xss"
            elif any(x in param_name for x in ["next", "redirect", "return", "url"]):
                family = "redirect"
            else:
                family = "sqli"  # default
        
        # Make enhanced prediction
        result = _ENHANCED_ENGINE.predict_with_confidence(endpoint, param, family)
        
        # Convert to expected format
        enhanced_result = {
            "p": result.get("calibrated_probability", result.get("raw_probability", 0.0)),
            "source": f"enhanced_{result.get('model_type', 'unknown')}",
            "enhanced": True,
            "confidence": result.get("confidence", 0.0),
            "uncertainty": result.get("uncertainty", 0.0),
            "prediction": result.get("prediction", 0),
            "family": family,
            "model_type": result.get("model_type", "unknown"),
            "features_used": result.get("features_used", 0)
        }
        
        return enhanced_result
        
    except Exception as e:
        print(f"Enhanced ML prediction failed: {e}")
        return {"p": 0.0, "source": "fallback_error", "enhanced": False}


def _enhanced_rank_payloads_for_family(
    feats: Dict[str, Any],
    family: str,
    top_n: int = 3,
    threshold: float = 0.2,
    *,
    recent_fail_counts: Optional[Dict[str, int]] = None,
) -> Tuple[List[Tuple[str, float]], Dict[str, Any]]:
    """
    Enhanced Stage B: per-family payload ranking via enhanced ML; fallback to curated pool.
    Returns ([(payload, prob)], meta)
    """
    fam = (family or "").lower()
    pool = payload_pool_for(fam)
    if not pool:
        return ([], {"used_path": "no_pool", "family": fam})

    # Try enhanced ML ranking first
    if _ENHANCED_ML_AVAILABLE and _ENHANCED_ENGINE is not None:
        try:
            print(f"DEBUG: Using enhanced ML engine for family {fam}")
            
            # Extract endpoint and parameter info
            endpoint = {
                "url": feats.get("url", ""),
                "method": feats.get("method", "GET"),
                "content_type": feats.get("content_type", "")
            }
            
            param = {
                "name": feats.get("target_param", ""),
                "value": feats.get("control_value", ""),
                "loc": feats.get("in", "query")
            }
            
            # Use enhanced payload ranking
            ranked_payloads = _ENHANCED_ENGINE.rank_payloads(
                endpoint, param, fam, pool, top_k=top_n
            )
            
            if ranked_payloads:
                # Convert to expected format
                recs = [(p["payload"], p["score"]) for p in ranked_payloads]
                meta = {
                    "used_path": "enhanced_ml",
                    "family": fam,
                    "enhanced": True,
                    "confidence": ranked_payloads[0].get("confidence", 0.0),
                    "uncertainty": ranked_payloads[0].get("uncertainty", 0.0)
                }
                print(f"DEBUG: Enhanced ML engine returned {len(recs)} results")
                return (recs, meta)
                
        except Exception as e:
            print(f"DEBUG: Enhanced ML engine failed: {e}")
            pass

    # Fallback to legacy ML recommender
    if _RECO is not None:
        try:
            print(f"DEBUG: Using legacy ML recommender for family {fam}")
            if hasattr(_RECO, "recommend_with_meta"):
                fb = {"recent_fail_counts": dict(recent_fail_counts or {})} if recent_fail_counts else None
                recs, meta = _RECO.recommend_with_meta(
                    feats, pool=pool, top_n=top_n, threshold=threshold, family=fam, feedback=fb
                )
                print(f"DEBUG: Legacy ML recommender returned {len(recs)} results, meta: {meta}")
                return ([(p, float(prob)) for (p, prob) in recs], meta or {})
            else:
                recs = _RECO.recommend(feats, pool=pool, top_n=top_n, threshold=threshold, family=fam)
                return ([(p, float(prob)) for (p, prob) in recs], {"used_path": "legacy_recommend", "family": fam})
        except Exception as e:
            print(f"DEBUG: Legacy ML recommender failed: {e}")
            pass
    else:
        print(f"DEBUG: No ML recommender available (_RECO is None)")

    # Final fallback: naive order, uniform score
    out = [(p, 0.2) for p in pool[:top_n]]
    return (out, {"used_path": "heuristic", "family": fam})


# Helper function to get payload pool
def payload_pool_for(family: str) -> List[str]:
    """Get payload pool for a specific family."""
    if _payload_pool_for_router:
        return _payload_pool_for_router(family)
    elif _payload_pool_for_payloads:
        return _payload_pool_for_payloads(family)
    else:
        # Default payloads if no pools available
        if family == "sqli":
            return ["' OR 1=1--", "' UNION SELECT NULL--", "1 OR 1=1--"]
        elif family == "xss":
            return ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg/onload=alert(1)>"]
        elif family == "redirect":
            return ["https://evil.com", "//evil.com", "https:%2F%2Fevil.com"]
        else:
            return []


# Export the enhanced functions
__all__ = [
    "_enhanced_ml_predict",
    "_enhanced_rank_payloads_for_family",
    "_endpoint_features",
    "payload_pool_for",
    "_ENHANCED_ML_AVAILABLE"
]
