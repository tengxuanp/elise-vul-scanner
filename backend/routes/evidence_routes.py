# backend/routes/evidence_routes.py
from __future__ import annotations

import json
import time
from hashlib import sha1
from pathlib import Path
from typing import Optional, Dict, Any, List

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field

try:
    from ..db import get_db
    from ..models import Endpoint, TestCase, Evidence
except ImportError:  # fallback if run flat (not recommended)
    from db import get_db
    from models import Endpoint, TestCase, Evidence

router = APIRouter()

# ---------- Pydantic models ----------
class EndpointIn(BaseModel):
    method: str
    url: str
    param_locs: Dict[str, List[str]] = Field(default_factory=dict)
    auth_ctx_id: Optional[str] = None

class TestCaseIn(BaseModel):
    job_id: str
    param: str
    family: str
    payload_id: str

class EvidenceIn(BaseModel):
    job_id: str
    endpoint: EndpointIn
    test_case: TestCaseIn
    request_meta: Dict[str, Any]
    response_meta: Dict[str, Any]
    signals: Dict[str, Any] = Field(default_factory=dict)
    confidence: float = 0.0
    label: str = "benign"


# ---------- Internals ----------
def _commit_with_retry(db: Session, retries: int = 5, base_sleep: float = 0.05) -> None:
    for i in range(retries):
        try:
            db.commit()
            return
        except OperationalError as e:
            if "database is locked" in str(e).lower():
                db.rollback()
                time.sleep(base_sleep * (2 ** i))
                continue
            raise
    raise RuntimeError("DB commit failed after retries (database locked?)")

def _dedupe_marker(item: EvidenceIn) -> str:
    src = "|".join([
        item.job_id,
        item.endpoint.method.upper(),
        item.endpoint.url,
        item.test_case.param,
        item.test_case.family,
        item.test_case.payload_id,
        item.label,
    ])
    return sha1(src.encode("utf-8")).hexdigest()[:16]

def _artifact_path_from_row(row: Evidence) -> Optional[Path]:
    try:
        p = (row.response_meta or {}).get("output_file")
        return Path(p) if p else None
    except Exception:
        return None


# ---------- Create (idempotent) ----------
@router.post("/evidence/record")
def record_evidence(item: EvidenceIn, db: Session = Depends(get_db)):
    # get-or-create endpoint
    ep = (
        db.query(Endpoint)
        .filter(Endpoint.method == item.endpoint.method, Endpoint.url == item.endpoint.url)
        .first()
    )
    if not ep:
        ep = Endpoint(
            method=item.endpoint.method,
            url=item.endpoint.url,
            param_locs=item.endpoint.param_locs,
            auth_ctx_id=item.endpoint.auth_ctx_id,
        )
        db.add(ep)
        db.flush()

    # get-or-create testcase
    tc = (
        db.query(TestCase)
        .filter(
            TestCase.job_id == item.test_case.job_id,
            TestCase.endpoint_id == ep.id,
            TestCase.param == item.test_case.param,
            TestCase.family == item.test_case.family,
            TestCase.payload_id == item.test_case.payload_id,
        )
        .first()
    )
    if not tc:
        tc = TestCase(
            job_id=item.test_case.job_id,
            endpoint_id=ep.id,
            param=item.test_case.param,
            family=item.test_case.family,
            payload_id=item.test_case.payload_id,
        )
        db.add(tc)
        db.flush()

    # idempotency marker
    marker = (item.request_meta or {}).get("marker") or _dedupe_marker(item)
    item.request_meta["marker"] = marker

    # soft dedupe within last 100 rows for this testcase
    existing = (
        db.query(Evidence)
        .filter(Evidence.job_id == item.job_id, Evidence.test_case_id == tc.id)
        .order_by(Evidence.id.desc())
        .limit(100)
        .all()
    )
    for ev in existing:
        if (ev.request_meta or {}).get("marker") == marker:
            return {"endpoint_id": ep.id, "test_case_id": tc.id, "evidence_id": ev.id, "existing": True}

    ev = Evidence(
        job_id=item.job_id,
        test_case_id=tc.id,
        request_meta=item.request_meta,
        response_meta=item.response_meta,
        signals=item.signals,
        confidence=float(item.confidence),
        label=item.label,
    )
    db.add(ev)
    _commit_with_retry(db)
    return {"endpoint_id": ep.id, "test_case_id": tc.id, "evidence_id": ev.id, "existing": False}


# ---------- List (filter + pagination) ----------
@router.get("/evidence/by_job/{job_id}")
def list_evidence(
    job_id: str,
    label: Optional[str] = Query(None, description="Filter by label (e.g., xss, sqli, benign)"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    q = db.query(Evidence).filter(Evidence.job_id == job_id)
    if label:
        q = q.filter(Evidence.label == label)
    rows = q.order_by(Evidence.id.desc()).offset(offset).limit(limit).all()

    out = []
    for r in rows:
        s = r.signals or {}
        match_count = s.get("ffuf_match_count")
        if match_count is None:
            match_count = len(s.get("ffuf_matches", []))
        out.append({
            "id": r.id,
            "test_case_id": r.test_case_id,
            "confidence": r.confidence,
            "label": r.label,
            "signals": {
                "ffuf_match_count": match_count,
                "ffuf_first_three": (s.get("ffuf_first_three") or [])[:3],
                "ffuf_errors": s.get("ffuf_errors", []),
            },
            "response_meta": r.response_meta,
            "created_at": r.created_at.isoformat(),
        })
    return out


# ---------- Detail (+ parsed artifact head) ----------
@router.get("/evidence/{evidence_id}")
def get_evidence(evidence_id: int, db: Session = Depends(get_db)):
    r = db.query(Evidence).filter(Evidence.id == evidence_id).first()
    if not r:
        raise HTTPException(404, "evidence not found")

    # lightweight artifact preview
    artifact = None
    p = _artifact_path_from_row(r)
    if p and p.exists():
        try:
            with p.open() as f:
                j = json.load(f)
            results = j.get("results") or []
            artifact = {
                "path": str(p),
                "match_count": len(results),
                "first_three": [
                    {
                        "status": m.get("status"),
                        "length": m.get("length"),
                        "words": m.get("words"),
                        "lines": m.get("lines"),
                        "url": m.get("url"),
                    } for m in results[:3]
                ],
            }
        except Exception:
            artifact = {"path": str(p), "error": "failed to parse artifact JSON"}

    return {
        "id": r.id,
        "job_id": r.job_id,
        "test_case_id": r.test_case_id,
        "confidence": r.confidence,
        "label": r.label,
        "signals": r.signals,
        "response_meta": r.response_meta,
        "created_at": r.created_at.isoformat(),
        "artifact": artifact,
    }


# ---------- Raw artifact download ----------
@router.get("/evidence/{evidence_id}/artifact")
def download_artifact(evidence_id: int, db: Session = Depends(get_db)):
    r = db.query(Evidence).filter(Evidence.id == evidence_id).first()
    if not r:
        raise HTTPException(404, "evidence not found")
    p = _artifact_path_from_row(r)
    if not p or not p.exists():
        raise HTTPException(404, "artifact not found on disk")
    return FileResponse(path=str(p), media_type="application/json", filename=p.name)


# ---------- Summary for triage ----------
@router.get("/evidence/summary/{job_id}")
def evidence_summary(job_id: str, db: Session = Depends(get_db)):
    rows = (
        db.query(Evidence)
        .filter(Evidence.job_id == job_id)
        .order_by(Evidence.confidence.desc(), Evidence.id.desc())
        .all()
    )
    if not rows:
        return {"job_id": job_id, "total": 0, "by_label": {}, "top": []}

    by_label: Dict[str, int] = {}
    for r in rows:
        by_label[r.label] = by_label.get(r.label, 0) + 1

    top: List[Dict[str, Any]] = []
    for r in rows[:5]:
        s = r.signals or {}
        match_count = s.get("ffuf_match_count")
        if match_count is None:
            match_count = len(s.get("ffuf_matches", []))
        top.append({
            "id": r.id,
            "label": r.label,
            "confidence": r.confidence,
            "match_count": match_count,
            "first_match": (s.get("ffuf_first_three") or [{}])[:1],
            "artifact": (r.response_meta or {}).get("output_file"),
            "created_at": r.created_at.isoformat(),
        })

    return {
        "job_id": job_id,
        "total": len(rows),
        "by_label": by_label,
        "top": top,
    }
