"""
ML Routes for Target-Granular Vulnerability Assessment

Provides endpoints for machine learning predictions using the orchestration pipeline
with probe-based evidence and strict ML triage.
"""

from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

# Import modules
from pipeline.workflow import assess_endpoints
from app_state import ml_state

# Create router
router = APIRouter(tags=["ML"])


class MLPredictRequest(BaseModel):
    """Request model for ML prediction endpoint."""
    endpoints: Optional[List[Dict[str, Any]]] = None
    targets: Optional[List[Dict[str, Any]]] = None


class MLPredictResponse(BaseModel):
    """Response model for ML prediction endpoint."""
    total_endpoints: int
    eligible_targets: int
    results: List[Dict[str, Any]]


class MLErrorResponse(BaseModel):
    """Error response model for ML prediction endpoint."""
    error: str
    detail: str


@router.post(
    "/ml-predict",
    response_model=MLPredictResponse,
    responses={
        503: {"model": MLErrorResponse, "description": "Model not ready"}
    },
    summary="Assess targets using probe + ML pipeline",
    description="Run the complete vulnerability assessment pipeline: expand endpoints to targets, run probes, apply gates, and use ML for triage."
)
async def ml_predict(request: MLPredictRequest) -> MLPredictResponse:
    """
    Assess targets using the orchestration pipeline.
    
    This endpoint:
    1. Expands endpoints into individual parameter targets
    2. Runs probes to gather evidence
    3. Applies hard gates for applicability
    4. Uses ML for triage and orchestration (if available)
    5. Returns per-target decisions with evidence
    
    Returns 503 if the ML engine is not ready and required for orchestration.
    """
    try:
        # Validate input
        if not request.endpoints and not request.targets:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Either 'endpoints' or 'targets' must be provided"
            )
        
        # Use endpoints if provided, otherwise convert targets to endpoint format
        if request.endpoints:
            endpoints = request.endpoints
        else:
            # Convert targets to endpoint format (simplified)
            endpoints = []
            for target in request.targets:
                endpoints.append({
                    "url": target["url"],
                    "path": target.get("path", ""),
                    "method": target["method"],
                    "param_names": [target["param"]],
                    "param_locs": {target["param_in"]: [target["param"]]},
                    "status": target.get("status", 200),
                    "content_type": target.get("content_type", "text/html")
                })
        
        # Run the orchestration pipeline
        result = assess_endpoints(endpoints)
        
        return MLPredictResponse(
            total_endpoints=result["total_endpoints"],
            eligible_targets=result["eligible_targets"],
            results=result["results"]
        )
        
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        # Handle unexpected errors
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "AssessmentFailed",
                "detail": str(e)
            }
        )


@router.get(
    "/ml-status",
    summary="Get ML engine status",
    description="Check if the ML inference engine is ready and operational."
)
async def ml_status() -> Dict[str, Any]:
    """Get the current status of the ML inference engine."""
    if ml_state.ready and ml_state.engine:
        return {
            "status": "ready",
            "engine_loaded": True,
            "error": None
        }
    else:
        return {
            "status": "not_ready",
            "engine_loaded": False,
            "error": ml_state.error or "ML engine not initialized"
        }