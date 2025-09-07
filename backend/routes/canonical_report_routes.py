from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from pathlib import Path
from backend.app_state import DATA_DIR
from backend.reporting.generate import generate_markdown

router = APIRouter()

class ReportReq(BaseModel): job_id: str

@router.post("/report")
def report(req: ReportReq):
    p = DATA_DIR / "jobs" / req.job_id
    if not p.exists(): raise HTTPException(404,"job not found")
    md = generate_markdown(p)
    return {"job_id": req.job_id, "markdown": md}