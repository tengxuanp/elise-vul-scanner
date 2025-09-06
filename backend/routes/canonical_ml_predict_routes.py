"""
Canonical ML Predict Routes - /api/ml-predict
Implements the standardized ML prediction endpoint contract
"""

from fastapi import APIRouter, HTTPException
from typing import List, Dict, Any
import logging

# Import ML modules
try:
    from pipeline.workflow import assess_endpoints
    from app_state import ml_state
    ML_AVAILABLE = True
except ImportError as e:
    logging.error(f"Failed to import ML modules: {e}")
    ML_AVAILABLE = False

logger = logging.getLogger(__name__)
router = APIRouter(tags=["ml-predict"])

@router.post("/ml-predict")
async def ml_predict_endpoint(request: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Canonical ML prediction endpoint that predicts vulnerability families for endpoints.
    
    Request body:
    {
        "endpoints": [
            {
                "url": str,
                "method": "GET"|"POST",
                "params": [str],
                "param_locs": {
                    "query": [str],
                    "form": [str],
                    "json": [str]
                },
                "content_type": str
            }
        ]
    }
    
    Response:
    [
        {
            "endpoint": {...},
            "family": "xss"|"sqli"|"redirect"|"none",
            "confidence": number,
            "calibrated": true,
            "features_used": 48
        }
    ]
    """
    try:
        endpoints = request.get("endpoints", [])
        
        if not endpoints:
            raise HTTPException(400, "endpoints array is required")
        
        # Check if ML is available
        if not ML_AVAILABLE:
            raise HTTPException(500, {
                "error": "MLUnavailable",
                "detail": "ML pipeline not available. Check dependencies."
            })
        
        if not ml_state.ready:
            raise HTTPException(500, {
                "error": "MLEngineUnavailable",
                "detail": ml_state.error or "ML engine not ready"
            })
        
        logger.info(f"🧠 Starting canonical ML prediction for {len(endpoints)} endpoints")
        
        # Run the ML assessment pipeline
        result = assess_endpoints(endpoints)
        
        # Convert to canonical format
        predictions = []
        for finding in result.get("results", []):
            target = finding.get("target", {})
            endpoint = finding.get("endpoint", {})
            
            # Map ML family to canonical family
            ml_family = finding.get("ml_family", "none")
            canonical_family = "none"
            
            if ml_family in ["xss", "reflected_xss", "stored_xss"]:
                canonical_family = "xss"
            elif ml_family in ["sqli", "sql_injection"]:
                canonical_family = "sqli"
            elif ml_family in ["redirect", "open_redirect"]:
                canonical_family = "redirect"
            
            prediction = {
                "endpoint": {
                    "url": endpoint.get("url", ""),
                    "method": endpoint.get("method", "GET"),
                    "params": endpoint.get("param_names", []),
                    "param_locs": endpoint.get("param_locs", {
                        "query": [],
                        "form": [],
                        "json": []
                    }),
                    "content_type": endpoint.get("content_type", "text/html")
                },
                "family": canonical_family,
                "confidence": finding.get("ml_confidence", 0.0),
                "calibrated": True,
                "features_used": 48  # Standard feature count
            }
            predictions.append(prediction)
        
        logger.info(f"✅ Canonical ML prediction completed: {len(predictions)} predictions")
        
        return predictions
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Canonical ML prediction failed: {e}")
        raise HTTPException(500, f"ML prediction failed: {str(e)}")

