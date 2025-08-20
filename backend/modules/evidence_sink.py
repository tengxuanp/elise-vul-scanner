from __future__ import annotations
import time
from typing import Any, Dict, Optional
from sqlalchemy.exc import OperationalError

try:
    from ..db import SessionLocal
    from ..models import Endpoint, TestCase, Evidence
except ImportError:
    from db import SessionLocal
    from models import Endpoint, TestCase, Evidence

def _commit_with_retry(db, retries: int = 5, base_sleep: float = 0.05):
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

def persist_evidence(
    *,
    job_id: str,
    method: str,
    url: str,
    param_locs: Optional[Dict[str, list]] = None,
    param: str,
    family: str,
    payload_id: str,
    request_meta: Dict[str, Any],
    response_meta: Dict[str, Any],
    signals: Optional[Dict[str, Any]] = None,
    confidence: float = 0.0,
    label: str = "benign",
) -> Dict[str, int]:
    """Atomically create/get endpoint, then create testcase and evidence."""
    with SessionLocal() as db:
        ep = db.query(Endpoint).filter(Endpoint.method == method, Endpoint.url == url).first()
        if not ep:
            ep = Endpoint(method=method, url=url, param_locs=param_locs or {})
            db.add(ep)
            db.flush()  # assigns ep.id

        tc = TestCase(
            job_id=job_id,
            endpoint_id=ep.id,
            param=param,
            family=family,
            payload_id=payload_id,
        )
        db.add(tc)
        db.flush()  # assigns tc.id

        ev = Evidence(
            job_id=job_id,
            test_case_id=tc.id,
            request_meta=request_meta,
            response_meta=response_meta,
            signals=signals or {},
            confidence=float(confidence),
            label=label,
        )
        db.add(ev)
        _commit_with_retry(db)
        return {"endpoint_id": ep.id, "test_case_id": tc.id, "evidence_id": ev.id}
