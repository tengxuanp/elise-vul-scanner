from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from pathlib import Path
from backend.app_state import DATA_DIR
from backend.reporting.generate import generate_markdown

router = APIRouter()

class ReportReq(BaseModel): job_id: str

@router.post("/report")
def report(req: ReportReq):
    p = DATA_DIR / "jobs" / req.job_id
    if not p.exists():
        raise HTTPException(status_code=404, detail="job not found")
    md = generate_markdown(p)
    return {"job_id": req.job_id, "markdown": md}

# Convenience GET route to support frontend fetching raw markdown
@router.get("/report/{job_id}", response_class=PlainTextResponse)
def report_markdown(job_id: str):
    p = DATA_DIR / "jobs" / job_id
    if not p.exists():
        raise HTTPException(status_code=404, detail="job not found")
    return generate_markdown(p)
