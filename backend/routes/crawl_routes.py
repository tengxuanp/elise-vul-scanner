# backend/routes/crawl_routes.py
from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Dict, Any, List, Optional, Literal
from urllib.parse import urlparse, parse_qs, parse_qsl

from fastapi import APIRouter, HTTPException
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, Field

from ..modules.playwright_crawler import crawl_site
from ..modules.categorize_endpoints import process_crawl_results

# --- DB (optional; do not hard-crash if absent) ---
try:
    from ..db import SessionLocal  # type: ignore
    from ..models import Endpoint, TestCase, ScanJob, JobPhase  # type: ignore
except Exception:  # pragma: no cover
    SessionLocal, Endpoint, TestCase, ScanJob, JobPhase = None, None, None, None, None

router = APIRouter()

REPO_ROOT   = Path(__file__).resolve().parents[2]
DATA_DIR    = REPO_ROOT / "data"
JOBS_DIR    = DATA_DIR / "jobs"
RESULTS_DIR = DATA_DIR / "results"
JOBS_DIR.mkdir(parents=True, exist_ok=True)
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

# Track status per job (not a global mutex)
_job_status: Dict[str, str] = {}  # job_id -> "starting|running|completed|error"

# -------------------- models --------------------

class AuthConfig(BaseModel):
    mode: Literal["none", "cookie", "bearer", "form", "manual"] = "none"
    # cookie/bearer
    cookie: Optional[str] = None
    bearer_token: Optional[str] = None
    # form/manual (optional selectors)
    login_url: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    username_selector: Optional[str] = Field(default="input[type=email], #email, input[name=email]")
    password_selector: Optional[str] = Field(default="input[type=password], #password, input[name=password]")
    submit_selector:  Optional[str] = Field(default="button[type=submit], button#loginButton")
    wait_after_ms: Optional[int] = 1500
    # pass-through extra headers for Playwright context (supported by crawler)
    extra_headers: Optional[Dict[str, str]] = None

class CrawlRequest(BaseModel):
    job_id: str
    target_url: str
    max_depth: int = 2
    max_pages: int = 200
    auth: Optional[AuthConfig] = None


# -------------------- helpers --------------------

def _as_plain(x: Any) -> Any:
    """Coerce Pydantic models (v1/v2) to plain dicts; pass dicts and other types through."""
    if isinstance(x, BaseModel):
        return x.model_dump() if hasattr(x, "model_dump") else x.dict()
    if hasattr(x, "model_dump"):  # pydantic v2 objects
        try:
            return x.model_dump()
        except Exception:
            pass
    if hasattr(x, "dict"):  # pydantic v1 objects
        try:
            return x.dict()
        except Exception:
            pass
    return x

def _canon_method(v: Any) -> str:
    """Accept enums/strings like 'HTTPMETHOD.GET' and return 'GET'."""
    s = str(v or "GET")
    if "." in s:
        s = s.rsplit(".", 1)[-1]
    return s.upper()

def _names(xs) -> List[str]:
    """Extract parameter names from a list of strings or {name:...} dicts or objects with .name."""
    out: List[str] = []
    for x in (xs or []):
        if isinstance(x, str):
            if x:
                out.append(x)
        elif isinstance(x, dict) and x.get("name"):
            out.append(str(x["name"]))
        else:
            n = getattr(x, "name", None)
            if n:
                out.append(str(n))
    return out

def _map_param_locs_from_crawler(req: Dict[str, Any]) -> Optional[Dict[str, List[str]]]:
    """
    If the crawler provided canonical param_locs (query/form/json/body) and (optionally) content_type,
    map them into the DB's schema (query/form/json). Return None if not available.
    """
    pl = req.get("param_locs")
    if not isinstance(pl, dict):
        return None

    q = sorted(set(_names(pl.get("query"))))
    f = sorted(set(_names(pl.get("form"))))
    j = sorted(set(_names(pl.get("json"))))
    legacy_body = sorted(set(_names(pl.get("body"))))

    # Prefer explicit content_type; fallback to headers or body_type
    ct = (req.get("content_type") or req.get("content_type_hint") or "").lower()
    if not ct:
        hdrs = req.get("headers") or {}
        ct = (hdrs.get("content-type") or hdrs.get("Content-Type") or "").lower()
    if not ct:
        ct = (req.get("body_type") or "").lower()  # "json" | "form" | "" -> map below

    # If only legacy body is present, place it based on content-type hints
    if legacy_body:
        if "json" in ct:
            j = sorted(set(j or legacy_body))
        elif "x-www-form-urlencoded" in ct or "form" in ct:
            f = sorted(set(f or legacy_body))
        else:
            # unknown → treat as form by default (safer for DB/UI)
            f = sorted(set(f) | set(legacy_body))

    return {"query": q, "form": f, "json": j}

def _infer_param_locs_fallback(
    method: str,
    url: str,
    headers: Optional[Dict[str, str]] = None,
    post_data: Optional[Any] = None,
) -> Dict[str, List[str]]:
    """Heuristically infer query/form/json param keys from a request."""
    headers = headers or {}
    ct = (headers.get("content-type") or headers.get("Content-Type") or "").lower()

    out: Dict[str, List[str]] = {"query": [], "form": [], "json": []}

    # Query params from URL
    qs = parse_qs(urlparse(url).query)
    if qs:
        out["query"] = sorted(set(qs.keys()))

    # Body params
    if post_data:
        if isinstance(post_data, dict):
            out["json"] = sorted(post_data.keys())
        elif isinstance(post_data, str):
            s = post_data.strip()
            # Try JSON
            if s.startswith("{") or s.startswith("["):
                try:
                    obj = json.loads(s)
                    if isinstance(obj, dict):
                        out["json"] = sorted(obj.keys())
                except Exception:
                    pass
            # Try form-encoded
            if "application/x-www-form-urlencoded" in ct or ("=" in s and "&" in s):
                keys = {k for k, _ in parse_qsl(s, keep_blank_values=True)}
                out["form"] = sorted(keys)

    # prune empties
    return {k: v for k, v in out.items() if v}

def _derive_param_locs(req: Dict[str, Any]) -> Dict[str, List[str]]:
    """
    Prefer the crawler's canonical param_locs mapping; otherwise infer heuristically.
    """
    mapped = _map_param_locs_from_crawler(req)
    if mapped is not None:
        return mapped
    return _infer_param_locs_fallback(
        method=_canon_method(req.get("method")),
        url=(req.get("url") or ""),
        headers=(req.get("headers") or {}),
        post_data=req.get("post_data"),
    )

def _write_json(path: Path, payload: Any) -> Path:
    """
    JSON writer that won't choke on Pydantic types (e.g., HttpUrl, UUID).
    """
    enc = jsonable_encoder(payload)
    path.write_text(json.dumps(enc, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    return path

def _write_job_crawl(job_id: str, payload: Dict[str, Any]) -> Path:
    job_dir = JOBS_DIR / job_id
    job_dir.mkdir(parents=True, exist_ok=True)
    out = job_dir / "crawl_result.json"
    return _write_json(out, payload)

def _write_status(job_id: str, phase: str, extra: Optional[Dict[str, Any]] = None) -> None:
    _job_status[job_id] = phase
    job_dir = JOBS_DIR / job_id
    job_dir.mkdir(parents=True, exist_ok=True)
    p = job_dir / "status_crawl.json"
    blob = {"phase": phase}
    if extra:
        blob.update(extra)
    try:
        _write_json(p, blob)
    except Exception:
        pass

def _validate_target_url(target: str) -> None:
    """Hard fail if target_url lacks http/https scheme."""
    try:
        u = urlparse(target)
        if u.scheme not in {"http", "https"}:
            raise ValueError
        if not u.netloc:
            raise ValueError
    except Exception:
        raise HTTPException(status_code=400, detail="target_url must be an absolute http(s) URL")


def _persist_endpoint_and_plan(job_id: str, req: Dict[str, Any]) -> None:
    """Upsert Endpoint and create planned TestCase rows per param for this job."""
    if not (SessionLocal and Endpoint and TestCase):
        return  # DB not available

    method = _canon_method(req.get("method"))
    url = str(req.get("url") or "")

    param_locs: Dict[str, List[str]] = _derive_param_locs(req)

    with SessionLocal() as db:
        ep = (
            db.query(Endpoint)
              .filter(Endpoint.method == method, Endpoint.url == url)
              .first()
        )
        if not ep:
            ep = Endpoint(method=method, url=url, param_locs=param_locs)
            db.add(ep)
            db.flush()
        else:
            # merge newly derived params into existing record
            merged = dict(ep.param_locs or {})
            for k, v in (param_locs or {}).items():
                # Always treat as set union of names; store back as sorted list
                left  = set(merged.get(k, []) or [])
                right = set(v or [])
                merged[k] = sorted(left | right)
            ep.param_locs = merged

        def _ensure_tc(param: str, family: str = "plan", payload_id: str = "n/a"):
            exists = (
                db.query(TestCase)
                  .filter(
                      TestCase.job_id == job_id,
                      TestCase.endpoint_id == ep.id,
                      TestCase.param == param,
                      TestCase.family == family,
                      TestCase.payload_id == payload_id,
                  )
                  .first()
            )
            if not exists:
                db.add(TestCase(
                    job_id=job_id,
                    endpoint_id=ep.id,
                    param=param,
                    family=family,
                    payload_id=payload_id
                ))

        for param in (ep.param_locs or {}).get("query", []):
            _ensure_tc(param)
        for param in (ep.param_locs or {}).get("form", []):
            _ensure_tc(param)
        for param in (ep.param_locs or {}).get("json", []):
            _ensure_tc(param)

        db.commit()


# -------------------- routes --------------------

@router.post("/crawl/start")
def start_crawl(body: CrawlRequest):
    """
    Starts a per-job crawl in a background thread.
    Saves to data/jobs/<job_id>/crawl_result.json
    Persists Endpoint + TestCase plans into DB.
    """
    job_id = body.job_id.strip()
    target = body.target_url.strip()
    _validate_target_url(target)

    # Flatten auth (keep None if not provided)
    auth = (body.auth.model_dump() if getattr(body.auth, "model_dump", None) else body.auth.dict()) if body.auth else None
    max_depth = int(body.max_depth or 2)
    max_pages = int(body.max_pages or 200)

    # Prevent duplicate concurrent runs for the same job
    if _job_status.get(job_id) in {"starting", "running"}:
        raise HTTPException(status_code=400, detail=f"Job {job_id} crawl already in progress.")

    _write_status(job_id, "starting")

    # set job phase -> discovery (best-effort)
    if SessionLocal and ScanJob and JobPhase:
        try:
            with SessionLocal() as db:
                row = db.query(ScanJob).filter_by(job_id=job_id).first()
                if row:
                    row.phase = JobPhase.discovery
                    db.commit()
        except Exception:
            pass

    def run_crawl():
        try:
            _write_status(job_id, "running")

            # Run crawler with proper kwargs
            endpoints_raw, captured_raw = crawl_site(
                target_url=target,
                max_depth=max_depth,
                auth=auth,
                job_dir=str(JOBS_DIR / job_id),
                max_pages=max_pages,
            )

            # --- Coerce to plain dicts and normalize without mutating models ---
            endpoints: List[Dict[str, Any]] = []
            for ep in (endpoints_raw or []):
                epd = _as_plain(ep)
                if not isinstance(epd, dict):
                    # last-ditch: JSON round-trip, else skip
                    try:
                        epd = json.loads(json.dumps(epd, default=str))
                    except Exception:
                        continue

                # canonicalize method
                epd["method"] = _canon_method(epd.get("method"))

                # keep original param_locs shape (may contain dict objects with "name")
                pl = epd.get("param_locs")
                epd["param_locs"] = pl if isinstance(pl, dict) else {}

                # lightweight defaults
                epd["csrf_params"] = [p for p in (epd.get("csrf_params") or []) if p]
                epd["is_login"] = bool(epd.get("is_login", False))

                endpoints.append(epd)

            captured_requests: List[Dict[str, Any]] = []
            for r in (captured_raw or []):
                rd = _as_plain(r)
                if isinstance(rd, dict):
                    captured_requests.append(rd)
                else:
                    try:
                        captured_requests.append(json.loads(json.dumps(rd, default=str)))
                    except Exception:
                        # skip non-serializable
                        pass

            # Persist raw crawl (job-scoped)
            blob = {
                "target": target,
                "auth_mode": auth["mode"] if auth else "none",
                "endpoints": endpoints,
                "captured_requests": captured_requests
            }
            # If crawler wrote storage_state.json, record its path
            state_path = JOBS_DIR / job_id / "storage_state.json"
            if state_path.exists():
                blob["session_state_path"] = str(state_path)

            job_file = _write_job_crawl(job_id, blob)

            # Optional categorization pass (doesn't affect DB)
            try:
                process_crawl_results(
                    input_path=job_file,
                    output_dir=RESULTS_DIR,
                    target_url=target
                )
            except Exception:
                # don't let categorization failure kill crawl
                pass

            # Persist plans from endpoints
            for ep in endpoints:
                try:
                    _persist_endpoint_and_plan(job_id, ep)
                except Exception as e:
                    m = _canon_method(ep.get("method"))
                    u = str(ep.get("url") or "")
                    print(f"[WARN] persist endpoint failed: {m} {u} – {type(e).__name__}: {e}")

            # Persist plans from captured requests (richer: headers/body_type/body_parsed)
            for req in captured_requests or []:
                try:
                    _persist_endpoint_and_plan(job_id, req)
                except Exception as e:
                    m = _canon_method(req.get("method"))
                    u = str(req.get("url") or "")
                    print(f"[WARN] persist request failed: {m} {u} – {type(e).__name__}: {e}")

            _write_status(job_id, "completed")

            # advance phase → fuzzing (next step in pipeline)
            if SessionLocal and ScanJob and JobPhase:
                try:
                    with SessionLocal() as db:
                        row = db.query(ScanJob).filter_by(job_id=job_id).first()
                        if row:
                            row.phase = JobPhase.fuzzing
                            db.commit()
                except Exception:
                    pass

        except Exception as e:
            _write_status(job_id, "error", {"error": str(e)})
            print(f"[ERROR] Crawl failed for {job_id}: {type(e).__name__}: {e}")

    threading.Thread(target=run_crawl, daemon=True).start()
    return {
        "status": "started",
        "job_id": job_id,
        "target_url": target,
        "auth_mode": (auth["mode"] if auth else "none"),
        "max_depth": max_depth,
        "max_pages": max_pages,
    }


@router.get("/crawl/status/{job_id}")
def crawl_status(job_id: str):
    status = _job_status.get(job_id) or "unknown"
    # Prefer persisted status if present
    p = JOBS_DIR / job_id / "status_crawl.json"
    if p.exists():
        try:
            blob = json.loads(p.read_text("utf-8"))
            status = blob.get("phase", status)
        except Exception:
            pass
    return {"job_id": job_id, "status": status}


@router.get("/crawl/result/{job_id}")
def get_crawl_result(job_id: str):
    """
    Returns the raw crawl blob for the given job if present.
    """
    job_file = JOBS_DIR / job_id / "crawl_result.json"
    status = _job_status.get(job_id) or ("completed" if job_file.exists() else "unknown")

    if not job_file.exists():
        return {"job_id": job_id, "status": status, "endpoints": [], "captured_requests": []}

    try:
        blob = json.loads(job_file.read_text(encoding="utf-8"))
    except Exception:
        return {"job_id": job_id, "status": status, "endpoints": [], "captured_requests": []}

    return {"job_id": job_id, "status": status, **blob}


# --- legacy compatibility (avoid breaking old callers) ---

@router.get("/crawl/result")
def get_crawl_result_legacy():
    return {"error": "Specify job_id: GET /api/crawl/result/{job_id}"}
