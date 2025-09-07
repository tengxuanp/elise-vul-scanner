"""
DEPRECATED: Canonical Fuzz Routes - /api/fuzz
This endpoint has been deprecated in favor of the unified /api/assess endpoint.
Use /api/assess instead for vulnerability assessment workflow.
"""

from fastapi import APIRouter, HTTPException
from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)
router = APIRouter(tags=["fuzz-deprecated"])

@router.post("/fuzz")
async def fuzz_endpoint(request: Dict[str, Any]) -> Dict[str, Any]:
    """
    DEPRECATED: This endpoint has been deprecated.
    
    Use /api/assess instead for vulnerability assessment workflow.
    The /api/assess endpoint provides the same functionality with better integration.
    """
    raise HTTPException(
        status_code=410,  # Gone
        detail={
            "error": "Endpoint deprecated",
            "message": "The /api/fuzz endpoint has been deprecated. Use /api/assess instead.",
            "migration": {
                "old_endpoint": "/api/fuzz",
                "new_endpoint": "/api/assess",
                "example": {
                    "request": {
                        "endpoints": request.get("predictions", []).map(p => p.endpoint) if request.get("predictions") else [],
                        "job_id": "assessment-123",
                        "top_k": 3
                    }
                }
            }
        }
    )