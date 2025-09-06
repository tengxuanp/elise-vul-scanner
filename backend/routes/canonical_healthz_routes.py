"""
Canonical Healthz Routes - /api/healthz
Implements the standardized health check endpoint contract
"""

from fastapi import APIRouter
from typing import Dict, Any, List
import logging

# Import state modules
try:
    from app_state import ml_state, browser_state, MODEL_DIR, DATA_DIR
    STATE_AVAILABLE = True
except ImportError as e:
    logging.error(f"Failed to import state modules: {e}")
    STATE_AVAILABLE = False

logger = logging.getLogger(__name__)
router = APIRouter(tags=["healthz"])

@router.get("/healthz")
async def healthz_endpoint() -> Dict[str, Any]:
    """
    Canonical health check endpoint that returns system status and dependencies.
    
    Response:
    {
        "ok": bool,
        "browser_pool_ready": bool,
        "ml_ready": bool,
        "models": {...},
        "routes": [
            {
                "method": str,
                "path": str
            }
        ]
    }
    """
    try:
        # Check browser pool status
        browser_pool_ready = False
        if STATE_AVAILABLE:
            browser_pool_ready = browser_state.ready
        
        # Check ML status
        ml_ready = False
        models = {}
        if STATE_AVAILABLE:
            ml_ready = ml_state.ready
            if ml_state.engine:
                models = {
                    "inference_engine": "loaded",
                    "model_dir": MODEL_DIR or "unknown"
                }
            else:
                models = {
                    "inference_engine": "not_loaded",
                    "model_dir": MODEL_DIR or "unknown"
                }
        
        # Get mounted routes (this will be populated by main.py)
        routes = []
        try:
            from fastapi import FastAPI
            # This is a bit of a hack, but we need to get the app instance
            # The routes will be populated by main.py after mounting
            routes = [
                {"method": "POST", "path": "/api/crawl"},
                {"method": "POST", "path": "/api/ml-predict"},
                {"method": "POST", "path": "/api/fuzz"},
                {"method": "POST", "path": "/api/exploit"},
                {"method": "GET", "path": "/api/healthz"}
            ]
        except Exception:
            routes = []
        
        # Determine overall health
        ok = browser_pool_ready and ml_ready
        
        response = {
            "ok": ok,
            "browser_pool_ready": browser_pool_ready,
            "ml_ready": ml_ready,
            "models": models,
            "routes": routes
        }
        
        # Add error details if not healthy
        if not ok:
            if not browser_pool_ready and STATE_AVAILABLE:
                response["browser_error"] = browser_state.error
            if not ml_ready and STATE_AVAILABLE:
                response["ml_error"] = ml_state.error
        
        logger.info(f"🏥 Health check: ok={ok}, browser={browser_pool_ready}, ml={ml_ready}")
        
        return response
        
    except Exception as e:
        logger.error(f"❌ Health check failed: {e}")
        return {
            "ok": False,
            "browser_pool_ready": False,
            "ml_ready": False,
            "models": {},
            "routes": [],
            "error": str(e)
        }

