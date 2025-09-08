from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from starlette.concurrency import run_in_threadpool
from backend.modules.fuzzer_core import run_job
from backend.app_state import REQUIRE_RANKER

router = APIRouter()

class AssessReq(BaseModel):
    job_id: str
    top_k: Optional[int] = 3
    endpoints: Optional[List[Dict[str,Any]]] = Field(None, description="List of endpoints to assess directly")
    target_url: Optional[str] = Field(None, description="Target URL for full crawl and assessment")

@router.post("/assess")
async def assess(req: AssessReq):
    try:
        # If target_url is provided, use the full job orchestrator
        if req.target_url:
            return await run_in_threadpool(run_job, req.target_url, req.job_id, top_k=req.top_k or 3)
        elif req.endpoints:
            # Use the old workflow for direct endpoint assessment
            from backend.pipeline.workflow import assess_endpoints
            return await run_in_threadpool(assess_endpoints, req.endpoints, req.job_id, req.top_k or 3)
        else:
            raise ValueError("Either target_url or endpoints must be provided")
    except RuntimeError as e:
        # Handle ranker failures when REQUIRE_RANKER is set
        if REQUIRE_RANKER and "ranker" in str(e).lower():
            raise HTTPException(
                status_code=500,
                detail={
                    "error_code": "ranker_missing_or_bypassed",
                    "message": f"ML ranker required but failed: {str(e)}"
                }
            )
        else:
            raise HTTPException(status_code=500, detail=str(e))