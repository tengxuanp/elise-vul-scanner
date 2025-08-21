from __future__ import annotations

import logging, uuid
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple
import httpx
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from ..modules.fuzzer_ffuf import run_ffuf, _url_with_replaced_param  # uses your fixed wrapper
from ..modules.feature_extractor import FeatureExtractor
from ..modules.recommender import Recommender
from ..modules.target_builder import build_fuzz_targets_for_job
from ..modules.ml.family_router import choose_family, default_payloads_by_family
from ..modules.ml.delta_scorer import DeltaScorer

from ..db import SessionLocal
from ..models import ScanJob, JobPhase

REPO_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = REPO_ROOT / "data" / "results" / "ffuf"
DATA_DIR.mkdir(parents=True, exist_ok=True)

try:
    from ..modules.evidence_sink import persist_evidence  # type: ignore
except Exception:
    def persist_evidence(**kwargs):  # type: ignore
        return {"endpoint_id": None, "test_case_id": None, "evidence_id": None}

router = APIRouter()
fe = FeatureExtractor()
DELTA = DeltaScorer()
try: DELTA.load()
except Exception: pass

LATEST_RESULTS: Dict[str, List[Dict[str, Any]]] = {}

class FuzzTarget(BaseModel):
    url: str
    param: str
    method: str = "GET"
    job_id: Optional[str] = None
    headers: Dict[str, str] = Field(default_factory=dict)
    meta: Dict[str, Any] = Field(default_factory=dict)

class EndpointShape(BaseModel):
    method: str
    url: str
    params: Optional[List[str]] = None
    body_keys: Optional[List[str]] = None

class FuzzByJobPayload(BaseModel):
    selection: Optional[List[EndpointShape]] = None
    top_n: int = 3
    threshold: float = 0.2

def _key(method: str, url: str) -> str:
    return f"{(method or 'GET').upper()} {url or ''}"

def _merge_headers(h1: Optional[Dict[str, str]], h2: Optional[Dict[str, str]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for src in (h1 or {}), (h2 or {}):
        for k, v in src.items():
            out[k] = v
    return out

def _build_request_with_value(t: FuzzTarget, value: str):
    method = (t.method or "GET").upper()
    headers = dict((t.meta or {}).get("headers") or {})
    body = (t.meta or {}).get("body")
    body_type = (t.meta or {}).get("body_type")
    if method == "GET":
        url = _url_with_replaced_param(t.url, t.param, value)
        return method, url, headers, None, None
    if body_type == "json":
        b = dict(body or {}); b[t.param] = value
        return method, t.url, headers, None, b
    if body_type == "form":
        b = dict(body or {}); b[t.param] = value
        return method, t.url, headers, b, None
    # default fallback: treat as query
    url = _url_with_replaced_param(t.url, t.param, value)
    return method, url, headers, None, None

def _send_once(method, url, headers, data=None, json=None, follow_redirects=False):
    with httpx.Client(follow_redirects=follow_redirects, timeout=15.0) as cli:
        r = cli.request(method, url, headers=headers, data=data, json=json)
        return {"status": r.status_code, "length": len(r.content or b""), "location": r.headers.get("location")}

def _is_external_redirect(base_url: str, location: str | None) -> bool:
    if not location: return False
    if location.startswith("http://") or location.startswith("https://") or location.startswith("//"):
        try:
            b = urlparse(base_url); l = urlparse(location if "://" in location else f"{b.scheme}:{location}")
            return (l.netloc and l.netloc != b.netloc)
        except Exception:
            return False
    return False

def _delta(a: dict, b: dict) -> dict:
    return {
        "status_changed": int(a["status"] != b["status"]) if (a and b) else 0,
        "len_delta": (b["length"] - a["length"]) if (a and b) else 0,
        "len_ratio": (0.0 if not a or a["length"] == 0 else (b["length"] / max(1, a["length"]))) if (a and b) else 1.0,
        "is_5xx": int(500 <= (b or {}).get("status", 0) <= 599),
        "is_4xx": int(400 <= (b or {}).get("status", 0) <= 499),
    }

def get_recommender(request: Request) -> Optional[Recommender]:
    obj = getattr(request.app.state, "reco", None)
    if obj is not None: return obj
    try:
        r = Recommender()
        load = getattr(r, "load", None)
        if callable(load): r.load()
        request.app.state.reco = r
        return r
    except Exception:
        return None

def _filter_targets_by_selection(raw_targets: List[Dict[str, Any]], selection: Optional[List[EndpointShape]]) -> List[Dict[str, Any]]:
    if not selection: return raw_targets
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for t in raw_targets:
        grouped.setdefault(_key(t.get("method","GET"), t["url"]), []).append(t)
    chosen: List[Dict[str, Any]] = []
    for sel in selection:
        key = _key(sel.method, sel.url); cand = grouped.get(key, [])
        if not cand: continue
        if sel.params:
            allowed = set(sel.params); chosen.extend([t for t in cand if t.get("param") in allowed])
        else:
            chosen.extend(cand)
    seen = set(); unique = []
    for t in chosen:
        sig = (t.get("method","GET").upper(), t["url"], t.get("param",""))
        if sig in seen: continue
        seen.add(sig); unique.append(t)
    return unique

# ---------------- core ----------------
def _fuzz_targets(targets: List[FuzzTarget], reco: Optional[Recommender], top_n: int = 3, threshold: float = 0.2) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []

    for t in targets:
        # Baseline with seed
        seed = (t.meta or {}).get("seed", {}).get("value")
        baseline_meta = None
        if seed is not None:
            try:
                m,u,h,d,j = _build_request_with_value(t, str(seed))
                baseline_meta = _send_once(m,u,h,d,j, follow_redirects=False)
            except Exception:
                logging.exception("baseline failed for %s %s", t.url, t.param)

        # Feature extraction (best effort)
        try:
            feats = fe.extract_features(t.url, t.param, payload="' OR 1=1 --", method=t.method)
        except Exception:
            logging.exception("feature_extractor failed for %s %s", t.url, t.param)
            feats = None

        # Choose family and payloads
        h_lower = {k.lower(): v for k,v in (t.meta or {}).get("headers", {}).items()}
        family = choose_family(t.method, t.url, t.param, h_lower.get("content-type"))
        try:
            if reco is not None and feats is not None:
                pairs = reco.recommend(feats, top_n=top_n, threshold=threshold, family=family)
                candidates = [(p, float(conf)) for p, conf in pairs] or [(p, 0.0) for p in default_payloads_by_family(family)]
            else:
                candidates = [(p, 0.0) for p in default_payloads_by_family(family)]
        except Exception:
            logging.exception("recommender failed; falling back")
            candidates = [(p, 0.0) for p in default_payloads_by_family(family)]

        # Execute candidates
        for payload, base_conf in candidates:
            try:
                ffuf_out = run_ffuf(
                    url=t.url, param=t.param, payload_file=payload if payload.endswith(".txt") else _tmp_payload_file(payload),
                    method=t.method, headers=_merge_headers((t.meta or {}).get("headers"), t.headers),
                    body=(t.meta or {}).get("body"), body_type=(t.meta or {}).get("body_type"),
                    output_dir=str(DATA_DIR),
                )
            except Exception as e:
                logging.exception("ffuf failed for %s %s", t.url, t.param)
                results.append({"url": t.url, "param": t.param, "method": t.method, "payload": payload,
                                "status": "error", "stage": "ffuf", "error": str(e), "meta": t.meta})
                continue

            # Verify request (for redirect header / status/length deltas)
            verify_meta = None
            try:
                m,u,h,d,j = _build_request_with_value(t, payload)
                verify_meta = _send_once(m,u,h,d,j, follow_redirects=False)
            except Exception:
                logging.exception("verify failed for %s %s", t.url, t.param)

            external_redirect = bool(verify_meta and _is_external_redirect(t.url, verify_meta.get("location")))
            delta = _delta(baseline_meta, verify_meta)

            # ML confidence
            features = {
                "status_changed": delta.get("status_changed", 0),
                "len_ratio": delta.get("len_ratio", 1.0),
                "is_5xx": delta.get("is_5xx", 0),
                "is_4xx": delta.get("is_4xx", 0),
                "external_redirect": 1 if external_redirect else 0,
            }
            derived_conf = max(float(base_conf or 0.0), float(DELTA.score(features)))

            # Aggregate
            one = {
                "url": t.url, "param": t.param, "method": t.method, "family": family,
                "payload": payload, "confidence": derived_conf, "status": "ok",
                "ffuf": {
                    "matches": len((ffuf_out or {}).get("matches") or []),
                    "elapsed_ms": (ffuf_out or {}).get("elapsed_ms"),
                    "errors": (ffuf_out or {}).get("errors"),
                },
                "baseline": baseline_meta, "verify": verify_meta, "delta": delta,
                "signals": {"external_redirect": external_redirect},
                "meta": t.meta,
            }
            results.append(one)

            # Persist evidence (best-effort)
            if t.job_id:
                try:
                    param_in_body = isinstance((t.meta or {}).get("body"), dict) and t.param in (t.meta or {}).get("body", {})
                    param_locs = {"body": [t.param]} if (t.method.upper() != "GET" and param_in_body) else {"query": [t.param]}
                    persist_evidence(
                        job_id=t.job_id, method=t.method, url=t.url, param_locs=param_locs, param=t.param,
                        family=family, payload_id="auto",
                        request_meta={"method": t.method, "url": t.url, "param": t.param, "headers": (t.meta or {}).get("headers"), "body_type": (t.meta or {}).get("body_type")},
                        response_meta={"status": (verify_meta or {}).get("status"), "len": (verify_meta or {}).get("length")},
                        signals={"external_redirect": external_redirect, "ffuf_match_count": one["ffuf"]["matches"]},
                        confidence=derived_conf, label=family,
                    )
                except Exception:
                    logging.exception("persist_evidence failed")

    return results

# tiny helper for inline payloads: write to temp file for ffuf -w
def _tmp_payload_file(payload: str) -> str:
    p = (DATA_DIR / f"inline_{uuid.uuid4().hex}.txt")
    p.write_text(payload.strip() + "\n", encoding="utf-8")
    return str(p)

@router.post("/fuzz")
def fuzz_many(targets: List[FuzzTarget], reco: Optional[Recommender] = Depends(get_recommender)):
    results = _fuzz_targets(targets, reco=reco)
    job_ids = {t.job_id for t in targets if t.job_id}
    if len(job_ids) == 1:
        LATEST_RESULTS[next(iter(job_ids))] = results
    return {"results": results}

@router.post("/fuzz/by_job/{job_id}")
def fuzz_by_job(job_id: str, payload: Optional[FuzzByJobPayload] = None, reco: Optional[Recommender] = Depends(get_recommender)):
    raw = build_fuzz_targets_for_job(job_id)
    if payload and payload.selection:
        raw = _filter_targets_by_selection(raw, payload.selection)
    targets = [FuzzTarget(**{**t, "job_id": job_id}) for t in raw]
    results = _fuzz_targets(targets, reco=reco, top_n=(payload.top_n if payload else 3), threshold=(payload.threshold if payload else 0.2))
    LATEST_RESULTS[job_id] = results
    with SessionLocal() as db:
        row = db.query(ScanJob).filter_by(job_id=job_id).first()
        if row: row.phase = JobPhase.triage; db.commit()
    return {"job_id": job_id, "count": len(results), "results": results}

@router.get("/fuzz/result/{job_id}")
def get_fuzz_result(job_id: str):
    return {"job_id": job_id, "results": LATEST_RESULTS.get(job_id, [])}
