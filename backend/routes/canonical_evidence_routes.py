from fastapi import APIRouter, HTTPException
from pathlib import Path
from backend.app_state import DATA_DIR
from backend.modules.evidence import read_evidence

router = APIRouter()

@router.get("/evidence/list/{job_id}")
async def list_evidence(job_id: str):
    """List available evidence files for a job (filename, family, decision)."""
    job_dir = DATA_DIR / "jobs" / job_id
    if not job_dir.exists():
        raise HTTPException(status_code=404, detail=f"Job not found: {job_id}")
    out = []
    for p in sorted(job_dir.glob("*_*.json")):
        try:
            import json
            with open(p, "r", encoding="utf-8") as f:
                d = json.load(f)
            out.append({
                "filename": p.name,
                "evidence_id": p.stem,
                "family": d.get("family", "unknown"),
                "decision": d.get("decision", "unknown")
            })
        except Exception:
            continue
    return out

@router.get("/evidence/{job_id}/{evidence_id}")
async def get_evidence(job_id: str, evidence_id: str):
    """
    Fetch evidence by job_id and evidence_id.
    Returns the full stored evidence JSON for the modal.
    """
    try:
        evidence = read_evidence(job_id, evidence_id)
        return evidence
    except FileNotFoundError:
        raise HTTPException(
            status_code=404,
            detail=f"Evidence not found: {evidence_id}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error reading evidence: {str(e)}"
        )
