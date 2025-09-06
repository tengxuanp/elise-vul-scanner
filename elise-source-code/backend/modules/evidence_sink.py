# backend/modules/evidence_sink.py
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Dict, Optional, Iterable

from sqlalchemy.exc import OperationalError

# Lazy relative/absolute imports to work in both module/run contexts
try:
    from ..db import SessionLocal
    from ..models import Endpoint, TestCase, Evidence
except ImportError:  # pragma: no cover
    from db import SessionLocal  # type: ignore
    from models import Endpoint, TestCase, Evidence  # type: ignore

# ============================== filesystem fallback ===========================

REPO_ROOT = Path(__file__).resolve().parents[2]
FALLBACK_DIR = REPO_ROOT / "data" / "results"
FALLBACK_DIR.mkdir(parents=True, exist_ok=True)
FALLBACK_NDJSON = FALLBACK_DIR / "evidence_fallback.ndjson"

def _append_ndjson(path: Path, obj: Dict[str, Any]) -> None:
    try:
        line = json.dumps(obj, ensure_ascii=False)
        with path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        # last-resort: swallow—never break caller on logging failure
        pass


# ============================== constants ====================================

SENSITIVE_HEADERS = {
    "authorization", "cookie", "x-api-key", "x-auth-token", "set-cookie",
    "proxy-authorization", "x-amz-security-token", "x-forwarded-for",
}

# Bound extremely large blobs so you don't wedge JSON columns / sqlite pages.
MAX_STRING_LEN = 100_000          # characters per string field
MAX_LIST_LEN = 5_000              # items per list before truncation
MAX_OBJECT_KEYS = 5_000           # keys per dict before truncation


# ============================== utils ========================================

def _sha1(s: str) -> str:
    return hashlib.sha1((s or "").encode("utf-8", "ignore")).hexdigest()


def _redact_headers(headers: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Redact sensitive header values case-insensitively. Keeps keys intact.
    """
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


def _json_safe(obj: Any, depth: int = 0) -> Any:
    """
    Convert arbitrary python objects to JSON-serializable shapes, trimming size.
    Depth is bounded implicitly by the size limits; we don't recurse infinitely.
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
        mapped = [_json_safe(x, depth + 1) for x in seq]
        if truncated:
            mapped.append(f"...<truncated_list:{len(obj)-MAX_LIST_LEN}>")
        return mapped

    if isinstance(obj, dict):
        # Respect key order where possible but cap total keys
        items = list(obj.items())
        truncated = False
        if len(items) > MAX_OBJECT_KEYS:
            items = items[:MAX_OBJECT_KEYS]
            truncated = True
        mapped = {str(k): _json_safe(v, depth + 1) for k, v in items}
        if truncated:
            mapped["__truncated_keys__"] = int(len(obj) - MAX_OBJECT_KEYS)
        return mapped

    # Fallback to repr
    try:
        return _bound_string(repr(obj))
    except Exception:
        return "<unserializable>"


def _sanitize_meta(meta: Optional[Dict[str, Any]], *, redact_header_keys: Iterable[str] = ()) -> Dict[str, Any]:
    """
    Make metadata JSON-safe and size-bounded; redact sensitive headers.
    Also computes SHA1 and length for large text/blob fields where common keys are used.
    """
    meta = dict(meta or {})
    # Best-effort header redaction under common names
    for hk in ("headers", "request_headers", "response_headers"):
        if hk in meta and isinstance(meta[hk], dict):
            meta[hk] = _redact_headers(meta[hk])

    # Also redact any provided header dicts by custom names
    for k in redact_header_keys:
        if k in meta and isinstance(meta[k], dict):
            meta[k] = _redact_headers(meta[k])

    # Add tiny convenience fields if a raw body is present
    for body_key in ("body", "raw", "text", "response_body", "request_body"):
        if body_key in meta and isinstance(meta[body_key], (str, bytes, bytearray)):
            body_str = meta[body_key]
            body_str = body_str.decode("utf-8", "ignore") if isinstance(body_str, (bytes, bytearray)) else body_str
            meta[f"{body_key}_len"] = len(body_str)
            meta[f"{body_key}_sha1"] = _sha1(body_str)
            meta[body_key] = _bound_string(body_str)

    return _json_safe(meta)  # final pass guarantees JSON safety


def _merge_param_locs(existing: Optional[Dict[str, list]], new: Optional[Dict[str, list]]) -> Dict[str, list]:
    """
    Merge Endpoint.param_locs dictionaries by union of names, preserving buckets.
    Buckets: 'query', 'form', 'json'. Values may be list[Param] or list[str].
    We normalize to list[str].
    """
    def _names(v: Any) -> Iterable[str]:
        if isinstance(v, list):
            out = []
            for item in v:
                if isinstance(item, str):
                    out.append(item)
                elif isinstance(item, dict) and "name" in item:
                    out.append(str(item["name"]))
                else:
                    try:
                        # Pydantic models with .name attribute
                        name = getattr(item, "name", None)
                        if name:
                            out.append(str(name))
                    except Exception:
                        pass
            return out
        return []

    ex = existing or {}
    nw = new or {}
    keys = {"query", "form", "json"}
    merged: Dict[str, list] = {}
    for k in keys:
        s = set(_names(ex.get(k)) + _names(nw.get(k)))
        merged[k] = sorted(s)
    # Carry any unknown buckets through conservatively
    for k, v in ex.items():
        if k not in keys:
            merged[k] = _json_safe(v)
    for k, v in nw.items():
        if k not in keys and k not in merged:
            merged[k] = _json_safe(v)
    return merged


def _commit_with_retry(db, retries: int = 5, base_sleep: float = 0.05) -> None:
    """
    Commit with backoff to ride over SQLite's 'database is locked' and similar transient errors.
    """
    for i in range(retries):
        try:
            db.commit()
            return
        except OperationalError as e:
            msg = str(e).lower()
            # sqlite: "database is locked" | postgres: serialization failures could be handled too
            if "database is locked" in msg or "deadlock detected" in msg or "could not serialize access" in msg:
                db.rollback()
                time.sleep(base_sleep * (2 ** i))
                continue
            db.rollback()
            raise
    raise RuntimeError("DB commit failed after retries (database locked/deadlock?)")


# ============================== core API =====================================

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
    """
    Atomically ensure Endpoint exists, create TestCase and Evidence rows,
    sanitize/trim bulky JSON fields, and merge param_locs into the Endpoint.

    Returns: {"endpoint_id": int, "test_case_id": int, "evidence_id": int}

    If the database is unavailable or errors out, we write a best-effort NDJSON
    record to data/results/evidence_fallback.ndjson and return sentinel IDs -1.
    """
    # Sanitize metas up-front (avoid exploding JSON columns)
    req_meta_s = _sanitize_meta(request_meta, redact_header_keys=("headers",))
    resp_meta_s = _sanitize_meta(response_meta, redact_header_keys=("headers",))
    sigs_s = _json_safe(signals or {})

    try:
        with SessionLocal() as db:
            # Upsert endpoint by (method, url)
            ep = (
                db.query(Endpoint)
                .filter(Endpoint.method == method, Endpoint.url == url)
                .first()
            )
            if not ep:
                ep = Endpoint(method=method, url=url, param_locs=param_locs or {})
                db.add(ep)
                db.flush()  # assigns ep.id
            else:
                # Merge param_locs if new info arrives
                try:
                    if param_locs:
                        merged = _merge_param_locs(ep.param_locs or {}, param_locs)
                        ep.param_locs = merged
                except Exception:
                    # Best-effort; don't block evidence on param merge failure
                    pass

            # Create the testcase
            tc = TestCase(
                job_id=job_id,
                endpoint_id=ep.id,
                param=param,
                family=family,
                payload_id=payload_id,
            )
            db.add(tc)
            db.flush()  # assigns tc.id

            # Create the evidence
            ev = Evidence(
                job_id=job_id,
                test_case_id=tc.id,
                request_meta=req_meta_s,
                response_meta=resp_meta_s,
                signals=sigs_s,
                confidence=float(confidence),
                label=label,
            )
            db.add(ev)
            _commit_with_retry(db)

            return {"endpoint_id": ep.id, "test_case_id": tc.id, "evidence_id": ev.id}

    except Exception as e:
        # Fallback to NDJSON so we never lose findings
        fallback_obj = _json_safe({
            "ts": int(time.time()),
            "job_id": job_id,
            "method": method,
            "url": url,
            "param": param,
            "family": family,
            "payload_id": payload_id,
            "request_meta": req_meta_s,
            "response_meta": resp_meta_s,
            "signals": sigs_s,
            "confidence": float(confidence),
            "label": label,
            "error": f"db-persist-failed: {type(e).__name__}: {str(e)}",
        })
        _append_ndjson(FALLBACK_NDJSON, fallback_obj)  # non-fatal
        return {"endpoint_id": -1, "test_case_id": -1, "evidence_id": -1}


# ============================== maintenance ==================================

def update_evidence_label(
    *,
    evidence_id: int,
    label: Optional[str] = None,
    confidence: Optional[float] = None,
) -> bool:
    """
    Update label and/or confidence for an existing Evidence row.
    Returns True if a row was updated. Returns False on any error.
    """
    if label is None and confidence is None:
        return False
    try:
        with SessionLocal() as db:
            ev = db.query(Evidence).filter(Evidence.id == evidence_id).first()
            if not ev:
                return False
            if label is not None:
                ev.label = label
            if confidence is not None:
                ev.confidence = float(confidence)
            _commit_with_retry(db)
            return True
    except Exception:
        return False


def relabel_by_testcase(
    *,
    test_case_id: int,
    label: Optional[str] = None,
    confidence: Optional[float] = None,
) -> int:
    """
    Bulk update all Evidence rows for a given test case.
    Returns the count of updated rows. Returns 0 on any error.
    """
    if label is None and confidence is None:
        return 0
    try:
        with SessionLocal() as db:
            q = db.query(Evidence).filter(Evidence.test_case_id == test_case_id)
            count = 0
            for ev in q:
                if label is not None:
                    ev.label = label
                if confidence is not None:
                    ev.confidence = float(confidence)
                count += 1
            if count:
                _commit_with_retry(db)
            return count
    except Exception:
        return 0
