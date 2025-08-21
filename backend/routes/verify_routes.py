# backend/routes/verify_routes.py
from __future__ import annotations

import time
from pathlib import Path
from typing import Dict, Any, Optional
from urllib.parse import urlencode, urlparse, urlunparse, parse_qsl

import httpx
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Evidence

router = APIRouter()

def _inject_query(url: str, key: str, val: str) -> str:
    u = urlparse(url)
    q = parse_qsl(u.query, keep_blank_values=True)
    # replace or add
    q = [(k, v) for (k, v) in q if k != key] + [(key, val)]
    return urlunparse((u.scheme, u.netloc, u.path, u.params, urlencode(q), u.fragment))

def _read_payload(request_meta: Dict[str, Any]) -> str:
    p = request_meta.get("payload_path")
    if not p:
        raise ValueError("missing payload_path in request_meta")
    txt = Path(p).read_text(encoding="utf-8").strip()
    return txt

def _verify_reflection(resp_text: str, payload: str) -> bool:
    # naive but effective first pass
    return payload in (resp_text or "")

def _verify_timing(client: httpx.Client, method: str, url: str, param: str, slow_payload: str) -> Dict[str, Any]:
    # baseline
    fast_url = _inject_query(url, param, "baseline")
    t0 = time.perf_counter()
    r0 = client.request(method, fast_url, timeout=10)
    t1 = time.perf_counter()

    # slow
    slow_url = _inject_query(url, param, slow_payload)
    t2 = time.perf_counter()
    r1 = client.request(method, slow_url, timeout=20)
    t3 = time.perf_counter()

    base_ms = int((t1 - t0) * 1000)
    slow_ms = int((t3 - t2) * 1000)
    return {
        "baseline_ms": base_ms,
        "slow_ms": slow_ms,
        "delta_ms": slow_ms - base_ms,
        "baseline_status": r0.status_code,
        "slow_status": r1.status_code,
    }

@router.post("/verify/{evidence_id}")
def verify_evidence(evidence_id: int, db: Session = Depends(get_db)):
    ev: Optional[Evidence] = db.query(Evidence).filter(Evidence.id == evidence_id).first()
    if not ev:
        raise HTTPException(404, "evidence not found")

    req = ev.request_meta or {}
    resp_meta = ev.response_meta or {}
    method = (req.get("method") or "GET").upper()
    url = req.get("url")
    param = req.get("param")
    headers = req.get("headers") or {}
    if not url or not param:
        raise HTTPException(400, "evidence missing url/param in request_meta")

    payload = _read_payload(req)

    verdict = {"confirmed": False, "reason": "unknown"}
    details: Dict[str, Any] = {}

    with httpx.Client(headers=headers, follow_redirects=True) as client:
        if ev.label == "xss":
            test_url = _inject_query(url, param, payload)
            r = client.request(method, test_url, timeout=10)
            body = r.text or ""
            reflected = _verify_reflection(body, payload)
            verdict["confirmed"] = bool(reflected and r.status_code < 500)
            verdict["reason"] = "payload_reflected" if reflected else "not_reflected"
            details = {"status": r.status_code, "body_len": len(body)}
        elif ev.label == "sqli":
            # crude time-based check using your own time payload if present, else a default
            slow_payload = payload if "waitfor delay" in payload.lower() else "';WAITFOR DELAY '0:0:3'--"
            stats = _verify_timing(client, method, url, param, slow_payload)
            verdict["confirmed"] = stats["delta_ms"] >= 1500 and stats["slow_status"] < 500
            verdict["reason"] = "timing_delta" if verdict["confirmed"] else "no_timing_signal"
            details = stats
        else:
            verdict["reason"] = f"unhandled_label_{ev.label}"

    # write back into signals and bump confidence on confirm
    signals = ev.signals or {}
    signals["verify"] = {"label": ev.label, "verdict": verdict, "details": details}
    ev.signals = signals
    if verdict["confirmed"]:
        ev.confidence = max(ev.confidence, 0.8)
    db.commit()

    return {
        "evidence_id": ev.id,
        "label": ev.label,
        "confidence": ev.confidence,
        "verdict": verdict,
        "details": details,
        "artifact": resp_meta.get("output_file"),
    }
