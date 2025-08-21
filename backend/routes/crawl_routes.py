# backend/routes/crawl_routes.py
from __future__ import annotations

import json
import threading
import inspect
from pathlib import Path
from typing import Dict, Any, List, Optional, Literal
from urllib.parse import urlparse, parse_qs, parse_qsl

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from ..modules.playwright_crawler import crawl_site
from ..modules.categorize_endpoints import process_crawl_results
from ..db import SessionLocal
from ..models import Endpoint, TestCase, ScanJob, JobPhase

router = APIRouter()

REPO_ROOT  = Path(__file__).resolve().parents[2]
DATA_DIR   = REPO_ROOT / "data"
JOBS_DIR   = DATA_DIR / "jobs"
RESULTS_DIR= DATA_DIR / "results"
JOBS_DIR.mkdir(parents=True, exist_ok=True)
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

# Track status per job (not a global mutex)
_job_status: Dict[str, str] = {}  # job_id -> "running|completed|error"

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

class CrawlRequest(BaseModel):
    job_id: str
    target_url: str
    auth: Optional[AuthConfig] = None


# -------------------- helpers --------------------

def _infer_param_locs(
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

def _persist_endpoint_and_plan(job_id: str, req: Dict[str, Any]) -> None:
    """Upsert Endpoint and create planned TestCase rows per param for this job."""
    method = (req.get("method") or "GET").upper()
    url = req.get("url") or ""
    headers: Dict[str, str] = req.get("headers") or {}
    post_data = req.get("post_data")

    # prefer explicit param_locs if provided by crawler, else infer
    param_locs: Dict[str, List[str]] = req.get("param_locs") or _infer_param_locs(method, url, headers, post_data)

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
            # merge newly inferred params into existing record
            merged = dict(ep.param_locs or {})
            for k, v in (param_locs or {}).items():
                merged.setdefault(k, [])
                merged[k] = sorted(set(merged[k]) | set(v))
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

def _write_job_crawl(job_id: str, payload: Dict[str, Any]) -> Path:
    job_dir = JOBS_DIR / job_id
    job_dir.mkdir(parents=True, exist_ok=True)
    out = job_dir / "crawl_result.json"
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return out


# -------------------- routes --------------------

@router.post("/crawl")
def start_crawl(body: CrawlRequest):
    """
    Starts a per-job crawl in a background thread.
    Saves to data/jobs/<job_id>/crawl_result.json
    Persists Endpoint + TestCase plans into DB.
    """
    job_id = body.job_id
    target = body.target_url
    auth  = body.auth.dict() if body.auth else None

    if _job_status.get(job_id) == "running":
        raise HTTPException(status_code=400, detail=f"Job {job_id} crawl already running.")

    _job_status[job_id] = "running"

    # set job phase -> discovery
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
            # Robust call: pass auth/job_dir only if crawler supports them
            kwargs: Dict[str, Any] = {}
            sig = inspect.signature(crawl_site)
            if "auth" in sig.parameters and auth:
                # pass job_dir to let crawler persist storage_state.json if it wishes
                kwargs["auth"] = {**auth, "job_dir": str(JOBS_DIR / job_id)}
            if "job_dir" in sig.parameters:
                kwargs["job_dir"] = str(JOBS_DIR / job_id)

            result = crawl_site(target, **kwargs)  # type: ignore[arg-type]
            # Support (endpoints, captured_requests) or (endpoints, captured_requests, extras)
            if isinstance(result, tuple) and len(result) >= 2:
                endpoints, captured_requests = result[0], result[1]
            else:
                raise RuntimeError("crawl_site returned unexpected result")

            # Ensure minimal fields for endpoints
            for ep in endpoints:
                ep.setdefault("method", "GET")
                ep.setdefault("param_locs", {})  # builder may fill this later

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

            # Persist plans from forms/endpoints
            for ep in endpoints:
                try:
                    _persist_endpoint_and_plan(job_id, ep)
                except Exception as e:
                    print(f"[WARN] persist endpoint failed: {e}")

            # Persist plans from concrete captured requests (richer: headers/body_type/body_parsed)
            for req in captured_requests or []:
                try:
                    _persist_endpoint_and_plan(job_id, req)
                except Exception as e:
                    print(f"[WARN] persist request failed: {e}")

            _job_status[job_id] = "completed"

            # advance phase → fuzzing (next step in pipeline)
            try:
                with SessionLocal() as db:
                    row = db.query(ScanJob).filter_by(job_id=job_id).first()
                    if row:
                        row.phase = JobPhase.fuzzing
                        db.commit()
            except Exception:
                pass

        except Exception as e:
            _job_status[job_id] = "error"
            print(f"[ERROR] Crawl failed for {job_id}: {e}")

    threading.Thread(target=run_crawl, daemon=True).start()
    return {"status": "started", "job_id": job_id, "target_url": target, "auth_mode": (auth["mode"] if auth else "none")}


@router.get("/crawl/status/{job_id}")
def crawl_status(job_id: str):
    status = _job_status.get(job_id) or "unknown"
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
