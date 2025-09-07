"""
DEPRECATED: Canonical ML Predict Routes - /api/ml-predict
This endpoint has been deprecated in favor of the unified /api/assess endpoint.
Use /api/assess instead for vulnerability assessment workflow.
"""

from fastapi import APIRouter, HTTPException
from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)
router = APIRouter(tags=["ml-predict-deprecated"])

@router.post("/ml-predict")
async def ml_predict_endpoint(request: Dict[str, Any]) -> Dict[str, Any]:
    """
    DEPRECATED: This endpoint has been deprecated.
    
    Use /api/assess instead for vulnerability assessment workflow.
    The /api/assess endpoint provides the same functionality with better integration.
    """
    raise HTTPException(
        status_code=410,  # Gone
        detail={
            "error": "Endpoint deprecated",
            "message": "The /api/ml-predict endpoint has been deprecated. Use /api/assess instead.",
            "migration": {
                "old_endpoint": "/api/ml-predict",
                "new_endpoint": "/api/assess",
                "example": {
                    "request": {
                        "endpoints": request.get("endpoints", []),
                        "job_id": "assessment-123",
                        "top_k": 3
                    }
                }
            }
        }
    )

