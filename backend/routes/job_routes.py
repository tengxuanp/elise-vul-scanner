from __future__ import annotations
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from uuid import uuid4
from datetime import datetime

from ..db import SessionLocal
from ..models import ScanJob, JobPhase

router = APIRouter()

class StartJobIn(BaseModel):
    target: str
    notes: str = ""

@router.post("/job/start")
def start_job(body: StartJobIn):
    job_id = str(uuid4())
    with SessionLocal() as db:
        row = ScanJob(job_id=job_id, target=body.target, notes=body.notes, phase=JobPhase.discovery, created_at=datetime.utcnow())
        db.add(row)
        db.commit()
    return {"job_id": job_id}

@router.post("/job/phase/{job_id}/{phase}")
def set_phase(job_id: str, phase: JobPhase):
    with SessionLocal() as db:
        row = db.query(ScanJob).filter_by(job_id=job_id).first()
        if not row:
            raise HTTPException(404, "job not found")
        row.phase = phase
        row.updated_at = datetime.utcnow()
        db.commit()
    return {"ok": True}
