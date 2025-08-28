# backend/routes/job_routes.py
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from uuid import uuid4
from typing import Any, Dict, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

# --- Optional DB wiring (degrade gracefully if unavailable) ---
try:
    from ..db import SessionLocal  # type: ignore
    from ..models import ScanJob, JobPhase  # type: ignore
except Exception:  # pragma: no cover
    SessionLocal = None  # type: ignore
    ScanJob = None  # type: ignore
    JobPhase = None  # type: ignore

router = APIRouter()

# --- Filesystem layout (fallback when DB is not configured) ---
REPO_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = REPO_ROOT / "data"
JOBS_DIR = DATA_DIR / "jobs"
JOBS_DIR.mkdir(parents=True, exist_ok=True)


# ------------------------- helpers (FS fallback) -------------------------

def _write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=str), encoding="utf-8")

def _job_dir(job_id: str) -> Path:
    p = JOBS_DIR / job_id
    p.mkdir(parents=True, exist_ok=True)
    return p

def _write_status(job_id: str, phase: str, extra: Optional[Dict[str, Any]] = None) -> None:
    blob: Dict[str, Any] = {"phase": phase, "updated_at": datetime.utcnow().isoformat() + "Z"}
    if extra:
        blob.update(extra)
    _write_json(_job_dir(job_id) / "status_job.json", blob)

def _write_job_meta(job_id: str, target: str, notes: str) -> None:
    payload = {
        "job_id": job_id,
        "target": target,
        "notes": notes or "",
        "created_at": datetime.utcnow().isoformat() + "Z",
    }
    _write_json(_job_dir(job_id) / "job.json", payload)


# ------------------------------ models ------------------------------

class StartJobIn(BaseModel):
    target: str
    notes: str = ""


# ------------------------------ routes ------------------------------

@router.post("/job/start")
def start_job(body: StartJobIn):
    """
    Create a new job and return its job_id.

    - If DB is configured, insert a ScanJob row with phase=discovery.
    - Otherwise, create data/jobs/<job_id>/ with job.json + status_job.json.
    """
    job_id = str(uuid4())

    if SessionLocal and ScanJob and JobPhase:
        # DB-backed path
        try:
            with SessionLocal() as db:  # type: ignore
                row = ScanJob(
                    job_id=job_id,
                    target=body.target,
                    notes=body.notes,
                    phase=JobPhase.discovery,  # type: ignore
                    created_at=datetime.utcnow(),
                )
                db.add(row)
                db.commit()
        except Exception as e:
            # Fall back to FS if DB write fails for any reason
            _write_job_meta(job_id, body.target, body.notes)
            _write_status(job_id, "discovery", {"db_fallback": True, "error": str(e)})
    else:
        # Filesystem fallback
        _write_job_meta(job_id, body.target, body.notes)
        _write_status(job_id, "discovery")

    return {"job_id": job_id}


@router.post("/job/phase/{job_id}/{phase}")
def set_phase(job_id: str, phase: str):
    """
    Update job phase.

    - If DB is present, update the row (best-effort coercion to JobPhase).
    - Otherwise, update data/jobs/<job_id>/status_job.json.
    """
    updated = False

    if SessionLocal and ScanJob:
        try:
            with SessionLocal() as db:  # type: ignore
                row = db.query(ScanJob).filter_by(job_id=job_id).first()  # type: ignore[attr-defined]
                if not row:
                    raise HTTPException(404, "job not found")

                # Coerce phase string to JobPhase if possible; else set raw string
                new_phase = phase
                if JobPhase:
                    try:
                        # Try enum name first (e.g., "discovery")
                        new_phase = JobPhase[phase]  # type: ignore[index]
                    except Exception:
                        try:
                            # Try enum value constructor (e.g., "discovery" -> JobPhase("discovery"))
                            new_phase = JobPhase(phase)  # type: ignore[call-arg]
                        except Exception:
                            # Fallback to raw string; underlying model may accept it
                            new_phase = phase  # type: ignore[assignment]

                row.phase = new_phase  # type: ignore[assignment]
                # If your model has updated_at column:
                if hasattr(row, "updated_at"):
                    setattr(row, "updated_at", datetime.utcnow())
                db.commit()
                updated = True
        except HTTPException:
            raise
        except Exception as e:
            # DB update failed; fall through to FS
            _write_status(job_id, phase, {"db_fallback": True, "error": str(e)})
            return {"ok": True, "fallback": "fs"}

    if not updated:
        # Filesystem fallback (or DB not configured)
        _write_status(job_id, phase)

    return {"ok": True}


@router.get("/job/{job_id}")
def get_job(job_id: str):
    """
    Lightweight job info for debugging/UI (works with or without DB).
    """
    # Try DB first
    if SessionLocal and ScanJob:
        try:
            with SessionLocal() as db:  # type: ignore
                row = db.query(ScanJob).filter_by(job_id=job_id).first()  # type: ignore[attr-defined]
                if row:
                    return {
                        "job_id": job_id,
                        "target": getattr(row, "target", None),
                        "notes": getattr(row, "notes", ""),
                        "phase": getattr(row, "phase", None),
                        "created_at": getattr(row, "created_at", None),
                        "updated_at": getattr(row, "updated_at", None),
                        "source": "db",
                    }
        except Exception:
            pass

    # FS fallback
    job_p = _job_dir(job_id) / "job.json"
    status_p = _job_dir(job_id) / "status_job.json"
    out: Dict[str, Any] = {"job_id": job_id, "source": "fs"}
    if job_p.exists():
        try:
            out.update(json.loads(job_p.read_text(encoding="utf-8")))
        except Exception:
            pass
    if status_p.exists():
        try:
            st = json.loads(status_p.read_text(encoding="utf-8"))
            out["phase"] = st.get("phase")
            out["updated_at"] = st.get("updated_at")
        except Exception:
            pass
    return out
