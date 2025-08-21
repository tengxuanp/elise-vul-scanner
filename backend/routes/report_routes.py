# backend/routes/report_routes.py
from __future__ import annotations

from typing import Dict, Any, List
from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session
from ..db import get_db
from ..models import Evidence

router = APIRouter()

def _row(ev: Evidence) -> str:
    s = ev.signals or {}
    ver = (s.get("verify") or {}).get("verdict") or {}
    confirmed = "✅" if ver.get("confirmed") else "⚪"
    art = (ev.response_meta or {}).get("output_file") or ""
    return f"| {ev.id} | {ev.label} | {ev.confidence:.2f} | {confirmed} | {art} |"

@router.get("/report/{job_id}")
def report_job(job_id: str, db: Session = Depends(get_db)):
    rows: List[Evidence] = (
        db.query(Evidence)
        .filter(Evidence.job_id == job_id)
        .order_by(Evidence.confidence.desc(), Evidence.id.desc())
        .all()
    )
    total = len(rows)
    by_label: Dict[str, int] = {}
    for r in rows:
        by_label[r.label] = by_label.get(r.label, 0) + 1

    md = []
    md.append(f"# Scan Report — {job_id}")
    md.append("")
    md.append(f"- Total evidence: **{total}**")
    md.append("- By label:")
    for k, v in sorted(by_label.items(), key=lambda kv: kv[1], reverse=True):
        md.append(f"  - **{k}**: {v}")
    md.append("")
    md.append("| ID | Label | Confidence | Verified | Artifact |")
    md.append("|---:|:------|----------:|:--------:|:---------|")
    for r in rows[:100]:
        md.append(_row(r))
    body = "\n".join(md)
    return Response(content=body, media_type="text/markdown")
