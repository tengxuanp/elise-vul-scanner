from fastapi import APIRouter
from pydantic import BaseModel
from typing import List, Dict, Any
from starlette.concurrency import run_in_threadpool
from backend.pipeline.workflow import assess_endpoints

router = APIRouter()

class AssessReq(BaseModel):
    endpoints: List[Dict[str,Any]]
    job_id: str
    top_k: int = 3

@router.post("/assess")
async def assess(req: AssessReq):
    return await run_in_threadpool(assess_endpoints, req.endpoints, req.job_id, req.top_k)