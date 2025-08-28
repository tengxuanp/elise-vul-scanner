# backend/routes/report_routes.py
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Response

# File-first reporting (no DB required)
from ..services.report_builder import build_report, RESULTS_DIR

# Optional DB wiring — degrade gracefully if not configured
try:
    from sqlalchemy.orm import Session  # type: ignore
    from ..db import get_db  # type: ignore
    from ..models import Evidence  # type: ignore
except Exception:  # pragma: no cover
    Session = None  # type: ignore
    Evidence = None  # type: ignore
    get_db = None  # type: ignore

router = APIRouter()


# ----------------------------- file-based reports -----------------------------

@router.get("/report/{job_id}")
def report_job(job_id: str) -> Dict[str, Any]:
    """
    Build (or rebuild) and return the JSON report for the given job.
    Writes to data/results/<job_id>/report.json and report.md.
    """
    return build_report(job_id)


@router.get("/report/{job_id}/md")
def report_markdown(job_id: str):
    """
    Return the Markdown report. If it doesn't exist yet, build it first.
    """
    out_dir = RESULTS_DIR / job_id
    md_path = out_dir / "report.md"
    if not md_path.exists():
        # Build once, then read
        build_report(job_id)
    if not md_path.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    try:
        content = md_path.read_text(encoding="utf-8")
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to read report.md")
    return Response(content=content, media_type="text/markdown; charset=utf-8")


# ----------------------------- legacy DB view --------------------------------
# Kept for compatibility with older UI that read directly from the Evidence table.

def _is_verified(ev: "Evidence") -> bool:
    """
    Heuristic 'verified' toggle for legacy view:
      - open redirect oracle OR login success
      - JS-context reflection or SQL error
      - very high confidence
    """
    sig = (ev.signals or {}) if isinstance(getattr(ev, "signals", None), dict) else {}
    redir = sig.get("open_redirect") or {}
    login = sig.get("login") or {}
    refl = sig.get("reflection") or {}
    sqlerr = bool(sig.get("sql_error"))

    # Explicit verification verdict if present (newer pipeline)
    verify = sig.get("verify") or {}
    if isinstance(verify, dict) and verify.get("confirmed"):
        return True

    if isinstance(redir, dict) and redir.get("open_redirect"):
        return True
    if isinstance(login, dict) and login.get("login_success"):
        return True
    if isinstance(refl, dict) and refl.get("js_context"):
        return True
    if sqlerr:
        return True
    try:
        return float(ev.confidence or 0.0) >= 0.9
    except Exception:
        return False


def _artifact_path(ev: "Evidence") -> str:
    rm = ev.response_meta or {}
    for k in ("output_file", "artifact", "artifact_path"):
        v = rm.get(k)
        if isinstance(v, str) and v:
            return v
    return ""


def _row(ev: "Evidence") -> str:
    label = getattr(ev, "label", None) or getattr(ev, "family", None) or "n/a"
    try:
        conf = f"{float(getattr(ev, 'confidence', 0.0) or 0.0):.2f}"
    except Exception:
        conf = "0.00"
    confirmed = "✅" if _is_verified(ev) else "⚪"
    art = _artifact_path(ev)
    return f"| {ev.id} | {label} | {conf} | {confirmed} | {art} |"


@router.get("/report/{job_id}/db")
def report_job_db(job_id: str, db: "Session" = Depends(get_db)):  # type: ignore[valid-type]
    """
    Legacy DB-backed markdown table of evidence (top 100). Requires DB to be configured.
    """
    if Evidence is None or get_db is None:
        raise HTTPException(status_code=503, detail="Database is not configured on this deployment.")

    rows: List["Evidence"] = (
        db.query(Evidence)  # type: ignore[attr-defined]
        .filter(Evidence.job_id == job_id)  # type: ignore[attr-defined]
        .order_by(Evidence.confidence.desc(), Evidence.id.desc())  # type: ignore[attr-defined]
        .all()
    )

    total = len(rows)
    by_label: Dict[str, int] = {}
    for r in rows:
        key = (getattr(r, "label", None) or getattr(r, "family", None) or "n/a")
        by_label[key] = by_label.get(key, 0) + 1

    md: List[str] = []
    md.append(f"# Scan Report — {job_id}")
    md.append("")
    md.append(f"- Total evidence: **{total}**")
    if by_label:
        md.append("- By label:")
        for k, v in sorted(by_label.items(), key=lambda kv: kv[1], reverse=True):
            md.append(f"  - **{k}**: {v}")
    md.append("")
    md.append("| ID | Label | Confidence | Verified | Artifact |")
    md.append("|---:|:------|-----------:|:--------:|:---------|")
    for r in rows[:100]:
        md.append(_row(r))

    body = "\n".join(md)
    return Response(content=body, media_type="text/markdown; charset=utf-8")
