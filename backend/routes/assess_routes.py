"""
Assessment API routes - handles vulnerability assessment with clear mode semantics.
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field, validator
from typing import Optional, List, Dict, Any, Union
import json
from pathlib import Path
from starlette.concurrency import run_in_threadpool

from backend.app_state import DATA_DIR, USE_ML, REQUIRE_RANKER
from backend.modules.fuzzer_core import run_job
# from backend.modules.ml.infer_ranker import available_models, using_defaults  # Not used in this file
from backend.routes.canonical_healthz_routes import get_healthz_data

router = APIRouter()

class AssessRequest(BaseModel):
    job_id: str = Field(..., description="Unique job identifier")
    
    # Pathway A: Explicit endpoint selection
    endpoints: Optional[List[Dict[str, Any]]] = Field(None, description="Explicit endpoints to assess")
    
    # Pathway B: Direct target URL assessment
    target_url: Optional[str] = Field(None, description="Target URL for direct assessment")
    persist_after_crawl: Optional[bool] = Field(False, description="Persist endpoints after crawl")
    
    # Common options
    top_k: Optional[int] = Field(3, description="Number of top payloads to try per family")
    
    @validator('*', pre=True, always=True)
    def validate_single_pathway(cls, v, values):
        """Ensure exactly one pathway is specified."""
        if 'endpoints' in values and 'target_url' in values:
            if values['endpoints'] is not None and values['target_url'] is not None:
                raise ValueError("Cannot specify both 'endpoints' and 'target_url'. Choose one pathway.")
        return v

class AssessResponse(BaseModel):
    job_id: str
    mode: str  # "direct" | "from_persisted" | "crawl_then_assess"
    summary: Dict[str, int]
    results: List[Dict[str, Any]]
    healthz: Dict[str, Any]

@router.post("/assess", response_model=AssessResponse)
async def assess_vulnerabilities(request: AssessRequest):
    """
    Assess vulnerabilities using one of three pathways:
    - (A) endpoints[]: explicit endpoint selection
    - (B) target_url: direct assessment with optional persistence
    - (C) job_id only: load from persisted endpoints.json
    """
    try:
        # Determine pathway and mode
        mode = None
        endpoints = None
        target_url = None
        
        if request.endpoints is not None:
            # Pathway A: Explicit endpoints
            mode = "direct"
            endpoints = request.endpoints
        elif request.target_url is not None:
            # Pathway B: Direct target URL
            mode = "crawl_then_assess" if request.persist_after_crawl else "direct"
            target_url = request.target_url
        else:
            # Pathway C: Load from persisted endpoints
            mode = "from_persisted"
            endpoints_path = DATA_DIR / "jobs" / request.job_id / "endpoints.json"
            
            if not endpoints_path.exists():
                raise HTTPException(
                    status_code=422, 
                    detail=f"No persisted endpoints found for job_id: {request.job_id}. Run /api/crawl first or provide endpoints/target_url."
                )
            
            with open(endpoints_path, 'r') as f:
                persisted_data = json.load(f)
                endpoints = persisted_data.get("endpoints", [])
                target_url = persisted_data.get("target_url")
        
        # Run assessment
        if target_url:
            # Use target_url pathway
            result = await run_in_threadpool(
                run_job,
                target_url=target_url,
                job_id=request.job_id,
                top_k=request.top_k or 3
            )
        else:
            # Use endpoints pathway - need to implement this in fuzzer_core
            # For now, we'll convert endpoints to a mock target_url
            if not endpoints:
                raise HTTPException(status_code=422, detail="No endpoints provided")
            
            # Extract base URL from first endpoint
            first_endpoint = endpoints[0]
            base_url = first_endpoint.get('url', '').split('?')[0].split('#')[0]
            if not base_url:
                raise HTTPException(status_code=422, detail="Invalid endpoint URL")
            
            result = await run_in_threadpool(
                run_job,
                target_url=base_url,
                job_id=request.job_id,
                top_k=request.top_k or 3
            )
        
        # Calculate summary from results
        results = result.get("results", [])
        summary = {
            "total": len(results),
            "positive": len([r for r in results if r.get("decision") == "positive"]),
            "suspected": len([r for r in results if r.get("decision") == "suspected"]),
            "abstain": len([r for r in results if r.get("decision") == "abstain"]),
            "na": len([r for r in results if r.get("decision") == "not_applicable"])
        }
        
        # Get healthz data
        healthz_data = get_healthz_data()
        
        return AssessResponse(
            job_id=request.job_id,
            mode=mode,
            summary=summary,
            results=results,
            healthz=healthz_data
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Assessment failed: {str(e)}")
