# backend/modules/target_builder.py
from __future__ import annotations
from typing import List, Dict, Any, Tuple, Set

try:
    from ..db import SessionLocal
    from ..models import TestCase, Endpoint
except ImportError:
    from db import SessionLocal
    from models import TestCase, Endpoint

def build_fuzz_targets_for_job(job_id: str) -> List[Dict[str, Any]]:
    """Expand planned TestCase rows for a job into fuzz targets."""
    out: List[Dict[str, Any]] = []
    seen: Set[Tuple[str, str, str]] = set()
    with SessionLocal() as db:
        rows = (
            db.query(TestCase, Endpoint)
              .join(Endpoint, TestCase.endpoint_id == Endpoint.id)
              .filter(TestCase.job_id == job_id)
              .all()
        )
        for tc, ep in rows:
            key = (ep.method, ep.url, tc.param)
            if key in seen:
                continue
            seen.add(key)
            out.append({
                "job_id": job_id,
                "method": ep.method or "GET",
                "url": ep.url,
                "param": tc.param,
                "meta": {"family": tc.family, "payload_id": tc.payload_id},
            })
    return out
