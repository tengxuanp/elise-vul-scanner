from fastapi import APIRouter, HTTPException
from backend.modules.evidence import read_evidence

router = APIRouter()

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
