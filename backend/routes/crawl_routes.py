# backend/routes/crawl_routes.py
from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse, parse_qs, parse_qsl

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ..modules.playwright_crawler import crawl_site
from ..modules.categorize_endpoints import process_crawl_results
from ..db import SessionLocal
from ..models import Endpoint, TestCase

router = APIRouter()

DATA_PATH = Path(__file__).resolve().parents[2] / "data"
CRAWL_RESULT_FILE = DATA_PATH / "crawl_result.json"
crawl_status = {"status": "idle"}

class CrawlRequest(BaseModel):
    job_id: str
    target_url: str

def _infer_param_locs(method: str, url: str,
                      headers: Optional[Dict[str, str]] = None,
                      post_data: Optional[Any] = None) -> Dict[str, List[str]]:
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

@router.post("/crawl")
def start_crawl(body: CrawlRequest):
    if crawl_status["status"] == "running":
        raise HTTPException(status_code=400, detail="Crawl already running.")
    crawl_status["status"] = "running"
    DATA_PATH.mkdir(parents=True, exist_ok=True)

    def run_crawl():
        try:
            endpoints, captured_requests = crawl_site(body.target_url)

            # Normalize and persist from both sources
            for ep in endpoints:
                ep.setdefault("method", "GET")
                ep.setdefault("param_locs", {})
            CRAWL_RESULT_FILE.write_text(
                json.dumps({"endpoints": endpoints, "captured_requests": captured_requests}, indent=2),
                encoding="utf-8"
            )

            # Optional categorization pass (doesn't affect DB)
            try:
                process_crawl_results(
                    input_path=CRAWL_RESULT_FILE,
                    output_dir=DATA_PATH / "results",
                    target_url=body.target_url
                )
            except Exception:
                pass

            # Persist plans from endpoint list
            for ep in endpoints:
                _persist_endpoint_and_plan(body.job_id, ep)

            # Persist plans from concrete captured requests (often richer)
            for req in captured_requests or []:
                _persist_endpoint_and_plan(body.job_id, req)

            crawl_status["status"] = "completed"
        except Exception as e:
            crawl_status["status"] = "error"
            print(f"[ERROR] Crawl failed: {e}")

    threading.Thread(target=run_crawl, daemon=True).start()
    return {"status": "started", "job_id": body.job_id}

@router.get("/crawl/result")
def get_crawl_result():
    if crawl_status["status"] == "running":
        return {"status": "pending"}
    if not CRAWL_RESULT_FILE.exists():
        return {"status": "completed", "endpoints": [], "captured_requests": []}
    return json.loads(CRAWL_RESULT_FILE.read_text(encoding="utf-8"))
