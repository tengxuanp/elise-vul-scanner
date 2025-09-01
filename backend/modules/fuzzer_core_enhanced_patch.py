# backend/modules/fuzzer_core_enhanced_patch.py
"""
Patch file showing exactly what needs to be changed in fuzzer_core.py
to integrate the enhanced ML system.

This file shows the minimal changes needed to replace:
1. _ranker_predict() calls with _enhanced_ml_predict()
2. _rank_payloads_for_family() calls with _enhanced_rank_payloads_for_family()
"""

# ============================================================================
# STEP 1: Add enhanced ML imports at the top of the file
# ============================================================================

# Add these imports after the existing imports (around line 30)
"""
# Import enhanced ML system
try:
    from .ml.enhanced_inference import EnhancedInferenceEngine
    from .ml.enhanced_features import EnhancedFeatureExtractor
    _ENHANCED_ML_AVAILABLE = True
    print("✅ Enhanced ML system loaded successfully")
except Exception as e:
    print(f"❌ Failed to load enhanced ML system: {e}")
    _ENHANCED_ML_AVAILABLE = False

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
"""

# ============================================================================
# STEP 2: Replace the _ranker_predict function definition
# ============================================================================

# Replace the existing _ranker_predict function (around line 32) with:
"""
def _ranker_predict(features: Dict[str, Any]) -> Dict[str, Any]:
    '''
    Enhanced ML prediction using the new system.
    
    Args:
        features: Feature dictionary
    
    Returns:
        Dictionary with enhanced prediction results
    '''
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
        
        # Try to infer family from parameter name
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
"""

# ============================================================================
# STEP 3: Replace the _rank_payloads_for_family function
# ============================================================================

# Replace the existing _rank_payloads_for_family function (around line 336) with:
"""
def _rank_payloads_for_family(
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
"""

# ============================================================================
# STEP 4: Update the _endpoint_features function to use enhanced features
# ============================================================================

# In the _endpoint_features function (around line 100), add enhanced feature extraction:
"""
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
"""

# ============================================================================
# STEP 5: Update ML result handling to use enhanced fields
# ============================================================================

# In the ML result handling sections (around lines 954, 1155, 1378), 
# the enhanced ML system will automatically provide additional fields:
# - enhanced: True/False
# - confidence: Enhanced confidence score
# - uncertainty: Uncertainty estimate
# - model_type: Type of model used
# - features_used: Number of features used

# The existing code will work with these new fields automatically.
# You can optionally add logging to show when enhanced ML is used:

"""
# Add this logging where ML results are processed:
if ml_out.get("enhanced", False):
    print(f"DEBUG: Enhanced ML used - Confidence: {ml_out.get('confidence', 0.0):.4f}, "
          f"Uncertainty: {ml_out.get('uncertainty', 0.0):.4f}, "
          f"Model: {ml_out.get('model_type', 'unknown')}")
"""
