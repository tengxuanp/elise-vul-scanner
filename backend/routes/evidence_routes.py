# backend/routes/evidence_routes.py
from __future__ import annotations

import json
import time
from hashlib import sha1
from pathlib import Path
from typing import Optional, Dict, Any, List, Iterable

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


# ---------- Internals / utilities ----------
SENSITIVE_HEADERS = {
    "authorization", "cookie", "x-api-key", "x-auth-token", "set-cookie",
    "proxy-authorization", "x-amz-security-token", "x-forwarded-for",
}

MAX_STRING_LEN = 100_000
MAX_LIST_LEN = 5_000
MAX_OBJECT_KEYS = 5_000


def _commit_with_retry(db: Session, retries: int = 5, base_sleep: float = 0.05) -> None:
    """
    Commit with backoff to dodge sqlite 'database is locked' and common deadlocks/serialization failures.
    """
    for i in range(retries):
        try:
            db.commit()
            return
        except OperationalError as e:
            msg = str(e).lower()
            if ("database is locked" in msg) or ("deadlock detected" in msg) or ("could not serialize access" in msg):
                db.rollback()
                time.sleep(base_sleep * (2 ** i))
                continue
            db.rollback()
            raise
    raise RuntimeError("DB commit failed after retries (database locked/deadlock?)")


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


def _classify_type(sig: Dict[str, Any]) -> str:
    """
    Normalize signal dicts from the fuzzer into a simple row type.
    """
    redir = (sig.get("open_redirect") or {})
    login = (sig.get("login") or {})
    verify = (sig.get("verify") or {})

    if isinstance(verify, dict):
        # If a verifier has already made a call, respect it.
        if verify.get("confirmed"):
            label = verify.get("label")
            if label in {"open_redirect", "login_bypass", "sqli", "xss"}:
                return str(label)

    if redir.get("open_redirect"):
        return "open_redirect"
    if login.get("login_success"):
        return "login_bypass"
    if sig.get("sql_error") is True:
        return "sqli"
    refl = (sig.get("reflection") or {})
    if refl.get("raw") or refl.get("js_context"):
        return "xss_reflection"
    return "other"


def _safe_get_request_url(req: Dict[str, Any]) -> Optional[str]:
    # Prefer normalized fuzzer Core schema: request.url
    if isinstance(req.get("request"), dict):
        return req["request"].get("url") or req.get("url")
    return req.get("url")


def _safe_get_response_headers(row: Evidence) -> Dict[str, Any]:
    """
    Return a lower-cased subset of response headers that we care about.
    Supports either response_meta.response.headers or response_meta.headers.
    """
    resp = row.response_meta or {}
    headers = {}
    if isinstance(resp.get("response"), dict) and isinstance(resp["response"].get("headers"), dict):
        headers = resp["response"]["headers"]
    else:
        h = resp.get("headers")
        if isinstance(h, dict):
            headers = h
    out = {}
    for k, v in (headers or {}).items():
        lk = str(k).lower()
        if lk in {"content-type", "location", "set-cookie"}:
            out[lk] = v
    return out


def _redact_headers(headers: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in (headers or {}).items():
        key = str(k)
        if key.lower() in SENSITIVE_HEADERS:
            out[key] = "***redacted***"
        else:
            out[key] = v
    return out


def _bound_string(s: Any, limit: int = MAX_STRING_LEN) -> Any:
    if isinstance(s, (bytes, bytearray)):
        try:
            s = s.decode("utf-8", "ignore")
        except Exception:
            s = str(s)
    if isinstance(s, str) and len(s) > limit:
        return s[:limit] + f"...<truncated:{len(s)-limit}>"
    return s


def _json_safe(obj: Any) -> Any:
    """
    Convert arbitrary python objects to JSON-serializable shapes, trimming size.
    """
    if obj is None or isinstance(obj, (int, float, bool)):
        return obj
    if isinstance(obj, (bytes, bytearray)):
        return _bound_string(obj)
    if isinstance(obj, str):
        return _bound_string(obj)
    if isinstance(obj, (list, tuple, set)):
        seq = list(obj)
        truncated = False
        if len(seq) > MAX_LIST_LEN:
            seq = seq[:MAX_LIST_LEN]
            truncated = True
        mapped = [_json_safe(x) for x in seq]
        if truncated:
            mapped.append(f"...<truncated_list:{len(obj)-MAX_LIST_LEN}>")
        return mapped
    if isinstance(obj, dict):
        items = list(obj.items())
        truncated = False
        if len(items) > MAX_OBJECT_KEYS:
            items = items[:MAX_OBJECT_KEYS]
            truncated = True
        mapped = {str(k): _json_safe(v) for k, v in items}
        if truncated:
            mapped["__truncated_keys__"] = int(len(obj) - MAX_OBJECT_KEYS)
        return mapped
    try:
        return _bound_string(repr(obj))
    except Exception:
        return "<unserializable>"


def _sanitize_meta(meta: Optional[Dict[str, Any]], *, redact_header_keys: Iterable[str] = ()) -> Dict[str, Any]:
    """
    Redact sensitive headers and bound/normalize JSON-like structures.
    Adds len/sha1 helpers for body-like fields if present.
    """
    meta = dict(meta or {})

    # Heuristic header buckets
    for hk in ("headers", "request_headers", "response_headers"):
        if hk in meta and isinstance(meta[hk], dict):
            meta[hk] = _redact_headers(meta[hk])

    # Custom header dicts
    for k in redact_header_keys:
        if k in meta and isinstance(meta[k], dict):
            meta[k] = _redact_headers(meta[k])

    # Add tiny convenience fields if a raw body is present
    for body_key in ("body", "raw", "text", "response_body", "request_body"):
        if body_key in meta and isinstance(meta[body_key], (str, bytes, bytearray)):
            body_str = meta[body_key]
            body_str = body_str.decode("utf-8", "ignore") if isinstance(body_str, (bytes, bytearray)) else body_str
            meta[f"{body_key}_len"] = len(body_str)
            meta[f"{body_key}_sha1"] = sha1(body_str.encode("utf-8", "ignore")).hexdigest()
            meta[body_key] = _bound_string(body_str)

    return _json_safe(meta)


def _merge_param_locs(existing: Optional[Dict[str, List[str]]], new: Optional[Dict[str, List[str]]]) -> Dict[str, List[str]]:
    """
    Merge Endpoint.param_locs dictionaries by union of names, preserving buckets (query, form, json).
    """
    ex = existing or {}
    nw = new or {}
    buckets = {"query", "form", "json"}
    merged: Dict[str, List[str]] = {}
    for k in buckets:
        ex_list = ex.get(k) or []
        nw_list = nw.get(k) or []
        # Normalize possible dict/Param objects to strings if needed
        def _names(lst):
            out = []
            for item in lst:
                if isinstance(item, str):
                    out.append(item)
                elif isinstance(item, dict) and "name" in item:
                    out.append(str(item["name"]))
                else:
                    name = getattr(item, "name", None)
                    if name:
                        out.append(str(name))
            return out
        merged[k] = sorted(set(_names(ex_list) + _names(nw_list)))

    # Carry any unknown buckets through (conservatively JSON-safe)
    for k, v in ex.items():
        if k not in merged:
            merged[k] = _json_safe(v)
    for k, v in nw.items():
        if k not in merged:
            merged[k] = _json_safe(v)
    return merged


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
    else:
        # Merge param_locs if new info arrives
        try:
            if item.endpoint.param_locs:
                ep.param_locs = _merge_param_locs(ep.param_locs or {}, item.endpoint.param_locs or {})
        except Exception:
            # Don't block on param merge failures
            pass

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

    # idempotency marker (derive if none)
    marker = (item.request_meta or {}).get("marker") or _dedupe_marker(item)

    # Soft dedupe within last 100 rows for this testcase
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

    # Sanitize metas before persisting (redact + size bounds)
    req_meta = dict(item.request_meta or {})
    req_meta["marker"] = marker
    req_meta_s = _sanitize_meta(req_meta, redact_header_keys=("headers",))
    resp_meta_s = _sanitize_meta(item.response_meta or {}, redact_header_keys=("headers",))

    ev = Evidence(
        job_id=item.job_id,
        test_case_id=tc.id,
        request_meta=req_meta_s,
        response_meta=resp_meta_s,
        signals=_json_safe(item.signals or {}),
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
    label: Optional[str] = Query(None, description="Filter by label (e.g., xss, sqli, open_redirect, login_bypass, benign)"),
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
        # backward-compat ffuf info
        match_count = s.get("ffuf_match_count")
        if match_count is None:
            match_count = len(s.get("ffuf_matches", []))

        # canonicalized highlights
        row_type = _classify_type(s)
        req = r.request_meta or {}
        req_url = _safe_get_request_url(req)
        req_param = (req.get("param") or (req.get("request") or {}).get("param"))

        # popular oracles
        redir = (s.get("open_redirect") or {})
        login = (s.get("login") or {})
        verify = (s.get("verify") or {})
        refl = (s.get("reflection") or {})

        # response headers of interest
        hdrs = _safe_get_response_headers(r)
        location = hdrs.get("location")
        token_present = bool(login.get("token_present"))

        out.append({
            "id": r.id,
            "test_case_id": r.test_case_id,
            "confidence": r.confidence,
            "label": r.label,
            "type": row_type,
            "request_url": req_url,
            "request_param": req_param,
            "signals": {
                "open_redirect": bool(redir.get("open_redirect")),
                "redirect_host": redir.get("location_host"),
                "login_bypass": bool(login.get("login_success")),
                "token_present": token_present,
                "sql_error": bool(s.get("sql_error")),
                "xss_reflected": bool(refl.get("raw") or refl.get("js_context")),
                "verify": verify,  # pass-through structured verdict if present
                "ffuf_match_count": match_count,
                "ffuf_first_three": (s.get("ffuf_first_three") or [])[:3],
                "ffuf_errors": s.get("ffuf_errors", []),
            },
            "response_headers": {
                "content_type": hdrs.get("content-type"),
                "location": location,
                "set_cookie": hdrs.get("set-cookie"),
            },
            "response_meta": r.response_meta,  # full for deep dive
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

    # normalize request/response highlights
    s = r.signals or {}
    req = r.request_meta or {}
    req_url = _safe_get_request_url(req)
    req_body = (req.get("request") or {}).get("body") or req.get("body")
    req_headers = (req.get("request") or {}).get("headers") or req.get("headers") or {}

    hdrs = _safe_get_response_headers(r)
    redir = (s.get("open_redirect") or {})
    verify = (s.get("verify") or {})

    return {
        "id": r.id,
        "job_id": r.job_id,
        "test_case_id": r.test_case_id,
        "confidence": r.confidence,
        "label": r.label,
        "type": _classify_type(s),
        "signals": r.signals,
        "verify": verify,
        "request_meta": {
            "url": req_url,
            "param": req.get("param") or (req.get("request") or {}).get("param"),
            "method": req.get("method") or (req.get("request") or {}).get("method"),
            "headers": req_headers,
            "body": req_body,
        },
        "response_meta": r.response_meta,
        "response_headers": {
            "content_type": hdrs.get("content-type"),
            "location": hdrs.get("location"),
            "set_cookie": hdrs.get("set-cookie"),
            "redirect_host": redir.get("location_host"),
        },
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
    by_type: Dict[str, int] = {}
    for r in rows:
        by_label[r.label] = by_label.get(r.label, 0) + 1
        rtype = _classify_type(r.signals or {})
        by_type[rtype] = by_type.get(rtype, 0) + 1

    top: List[Dict[str, Any]] = []
    for r in rows[:5]:
        s = r.signals or {}
        req_url = _safe_get_request_url(r.request_meta or {})
        top.append({
            "id": r.id,
            "label": r.label,
            "type": _classify_type(s),
            "confidence": r.confidence,
            "request_url": req_url,
            "redirect": (s.get("open_redirect") or {}).get("location"),
            "login_bypass": (s.get("login") or {}).get("login_success"),
            "sql_error": s.get("sql_error"),
            "xss_reflected": (s.get("reflection") or {}).get("raw"),
            "artifact": (r.response_meta or {}).get("output_file"),
            "created_at": r.created_at.isoformat(),
        })

    return {
        "job_id": job_id,
        "total": len(rows),
        "by_label": by_label,
        "by_type": by_type,
        "top": top,
    }
