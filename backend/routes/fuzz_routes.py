# backend/routes/fuzz_routes.py
from __future__ import annotations

import json
import logging
import uuid
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from urllib.parse import urlparse

# ---- engines ----
from ..modules.fuzzer_core import run_fuzz                           # primary (verification-first)
try:
    # optional, legacy ffuf runner used inside _fuzz_targets_ffuf()
    from ..modules.fuzzer_ffuf import run_ffuf                       # type: ignore
except Exception:  # pragma: no cover
    run_ffuf = None  # type: ignore

# ---- builders ----
# New builder that consumes merged endpoints from crawl_result.json
from ..modules.target_builder import build_targets                    # type: ignore

# ---- optional ML/feature plumbing (safe fallbacks) ----
try:
    from ..modules.feature_extractor import FeatureExtractor          # type: ignore
except Exception:  # pragma: no cover
    class FeatureExtractor:  # minimal stub
        def extract_features(self, *a, **kw): return {}
try:
    from ..modules.recommender import Recommender                     # type: ignore
except Exception:  # pragma: no cover
    class Recommender:  # minimal stub
        def load(self): ...
        def recommend(self, *a, **kw): return []

# ---- DB (optional) ----
try:
    from ..db import SessionLocal                                     # type: ignore
    from ..models import ScanJob, JobPhase                             # type: ignore
except Exception:  # pragma: no cover
    SessionLocal, ScanJob, JobPhase = None, None, None

# ---- filesystem layout ----
REPO_ROOT  = Path(__file__).resolve().parents[2]
DATA_DIR   = REPO_ROOT / "data"
JOBS_DIR   = DATA_DIR / "jobs"
RESULTS_DIR= DATA_DIR / "results"
FFUF_TMP   = DATA_DIR / "results" / "ffuf"
for _p in (JOBS_DIR, RESULTS_DIR, FFUF_TMP):
    _p.mkdir(parents=True, exist_ok=True)

# ---- optional evidence sink ----
try:
    from ..modules.evidence_sink import persist_evidence              # type: ignore
except Exception:  # pragma: no cover
    def persist_evidence(**kwargs):                                   # type: ignore
        return {"endpoint_id": None, "test_case_id": None, "evidence_id": None}

router = APIRouter()
fe = FeatureExtractor()

# Cache latest results by job for simple polling
LATEST_RESULTS: Dict[str, List[Dict[str, Any]]] = {}


# =========================
# Models / Schemas
# =========================
class FuzzTarget(BaseModel):
    url: str
    param: str
    method: str = "GET"
    job_id: Optional[str] = None
    headers: Dict[str, str] = Field(default_factory=dict)  # optional passthrough
    meta: Dict[str, Any] = Field(default_factory=dict)     # may contain body/body_type/headers/seed


class EndpointShape(BaseModel):
    """High-level endpoint selector from the UI."""
    method: str
    url: str
    params: Optional[List[str]] = None     # if provided, restrict to these param names
    body_keys: Optional[List[str]] = None  # informational; we match by param


class FuzzByJobPayload(BaseModel):
    # Selection applies to both engines.
    selection: Optional[List[EndpointShape]] = None
    # ffuf-only knobs (ignored by core)
    top_n: int = 3
    threshold: float = 0.2
    # engine: "core" | "ffuf" | "hybrid"
    engine: str = "core"
    # optional bearer for APIs (core engine uses this; cookies come from storage_state.json)
    bearer_token: Optional[str] = None
    # optional additional headers (sent by ffuf + used for verify/baseline); keys are case-sensitive
    extra_headers: Optional[Dict[str, str]] = None


# =========================
# Common helpers
# =========================
def _key(method: str, url: str) -> str:
    return f"{(method or 'GET').upper()} {url}"


def _load_crawl(job_id: str) -> Dict[str, Any]:
    p = JOBS_DIR / job_id / "crawl_result.json"
    if not p.exists():
        raise HTTPException(404, f"crawl_result.json not found for job '{job_id}'")
    return json.loads(p.read_text("utf-8"))


def _filter_endpoints_by_selection(
    endpoints: List[Dict[str, Any]],
    selection: Optional[List[EndpointShape]],
) -> List[Dict[str, Any]]:
    """Filter merged endpoints (from crawler) by method+url and optional param list (affects param_locs)."""
    if not selection:
        return endpoints
    # Build a map of (METHOD URL)-> allowed params set or None (means all)
    allow: Dict[str, Optional[set]] = {}
    for s in selection:
        key = _key(s.method, s.url)
        allow[key] = set(s.params) if s.params else None

    filtered: List[Dict[str, Any]] = []
    for ep in endpoints:
        key = _key(ep.get("method", "GET"), ep.get("url", ""))
        if key not in allow:
            continue
        allowed = allow[key]
        if allowed is None:
            filtered.append(ep)
            continue
        # Shallow copy and trim param_locs/query/body keys to allowed set
        ep2 = dict(ep)
        locs = dict(ep2.get("param_locs") or {})
        q = [p for p in (locs.get("query") or []) if p in allowed]
        b = [p for p in (locs.get("body") or []) if p in allowed]
        if not q and not b:
            continue
        ep2["param_locs"] = {"query": q, "body": b, "header": [], "cookie": []}
        ep2["query_keys"] = q
        ep2["body_keys"] = b
        filtered.append(ep2)
    return filtered


def _read_evidence(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    out: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except Exception:
                continue
    return out


def _normalize_bearer(token_or_header: Optional[str]) -> Optional[str]:
    """Accept raw JWT, 'Bearer <jwt>', or 'Authorization: Bearer <jwt>' → return 'Bearer <jwt>' or None."""
    if not token_or_header:
        return None
    tok = token_or_header.strip()
    low = tok.lower()
    if low.startswith("authorization:"):
        tok = tok.split(":", 1)[1].strip()
        low = tok.lower()
    if not low.startswith("bearer "):
        tok = f"Bearer {tok}"
    return tok


def _build_global_headers(payload: Optional[FuzzByJobPayload]) -> Dict[str, str]:
    """Build global headers for the ffuf/verify path only (core gets bearer separately)."""
    gh: Dict[str, str] = {}
    if not payload:
        return gh
    norm = _normalize_bearer(payload.bearer_token)
    if norm:
        gh["Authorization"] = norm
    for k, v in (payload.extra_headers or {}).items():
        # last-write-wins; explicit extras override Authorization if they choose to
        gh[k] = v
    return gh


# =========================
# Legacy ffuf-based flow
# =========================
import httpx
from urllib.parse import urlparse as _urlparse, parse_qsl, urlencode, urlunparse

def _merge_headers(h1: Optional[Dict[str, str]], h2: Optional[Dict[str, str]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for src in (h1 or {}), (h2 or {}):
        for k, v in src.items():
            out[k] = v
    return out

def _url_with_replaced_param(url: str, param: str, value: str) -> str:
    p = _urlparse(url)
    q = [(k, v) for (k, v) in parse_qsl(p.query, keep_blank_values=True) if k != param]
    q.append((param, value))
    new_q = urlencode(q, doseq=True)
    return urlunparse((p.scheme, p.netloc, p.path, p.params, new_q, p.fragment))

def _build_request_with_value(
    t: "FuzzTarget",
    value: str,
    global_headers: Optional[Dict[str, str]] = None,      # NEW
) -> Tuple[str, str, Dict[str, str], Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    method = (t.method or "GET").upper()
    headers = _merge_headers((t.meta or {}).get("headers") or {}, t.headers)
    headers = _merge_headers(headers, global_headers or {})            # NEW
    body = (t.meta or {}).get("body")
    body_type = (t.meta or {}).get("body_type")
    if method == "GET":
        url = _url_with_replaced_param(t.url, t.param, value)
        return method, url, headers, None, None
    else:
        if body_type == "json":
            b = dict(body or {})
            b[t.param] = value
            return method, t.url, headers, None, b
        elif body_type == "form":
            b = dict(body or {})
            b[t.param] = value
            return method, t.url, headers, b, None
        else:
            url = _url_with_replaced_param(t.url, t.param, value)
            return method, url, headers, None, None

def _send_once(
    method: str,
    url: str,
    headers: Dict[str, str],
    data: Optional[Dict[str, Any]] = None,
    json_: Optional[Dict[str, Any]] = None,
    follow_redirects: bool = False
) -> Dict[str, Any]:
    with httpx.Client(follow_redirects=follow_redirects, timeout=15.0) as cli:
        r = cli.request(method, url, headers=headers, data=data, json=json_)
        return {
            "status": r.status_code,
            "length": len(r.content or b""),
            "location": r.headers.get("location"),
        }

def _is_external_redirect(base_url: str, location: Optional[str]) -> bool:
    if not location:
        return False
    if location.startswith(("http://", "https://", "//")):
        try:
            b = _urlparse(base_url)
            l = _urlparse(location if "://" in location else f"{b.scheme}:{location}")
            return bool(l.netloc and l.netloc != b.netloc)
        except Exception:
            return False
    return False

def _delta(a: Optional[Dict[str, Any]], b: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not a or not b:
        return None
    return {
        "status_changed": int(a["status"] != b["status"]),
        "len_delta": (b["length"] - a["length"]),
        "len_ratio": (0.0 if a["length"] == 0 else (b["length"] / max(1, a["length"]))),
        "is_5xx": int(500 <= b["status"] <= 599),
        "is_4xx": int(400 <= b["status"] <= 499),
    }

def _fallback_payloads_for_family(family: str) -> List[str]:
    f = (family or "").lower()
    if f == "redirect":
        return ["https://example.org/", "//evil.tld", "https:%2F%2Fattacker.tld", "/\\evil.tld"]
    if f == "xss":
        return ["\"/><script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
    return ["' OR 1=1--", "' OR 'a'='b'--", "\" OR \"a\"=\"a\" --"]

def _guess_label(payload: str) -> str:
    s = (payload or "").lower()
    if any(x in s for x in ("<script", "onerror=", "onload=", "alert(")): return "xss"
    if any(x in s for x in ("http://", "https://", "//")): return "redirect"
    if any(x in s for x in (" or 1=1", "'--", "\"--")): return "sqli"
    return "benign"

# optional ML delta scorer
try:
    from ..modules.ml.delta_scorer import DeltaScorer                # type: ignore
    DELTA_SCORER: Optional[DeltaScorer] = DeltaScorer()
    try:
        DELTA_SCORER.load()
    except Exception:
        DELTA_SCORER = None
except Exception:
    DELTA_SCORER = None

def _derive_confidence_fallback(base_conf: float, match_count: int, external_redirect: bool) -> float:
    if external_redirect: return 0.8
    if base_conf and base_conf > 0: return float(base_conf)
    return min(1.0, 0.2 + 0.2 * match_count)

def _choose_family(method: str, url: str, param: str, content_type: Optional[str]) -> str:
    # tiny heuristic; keeps compatibility with your previous flow
    p = (param or "").lower()
    u = (url or "").lower()
    if p in {"to", "return_to", "redirect", "url", "next", "callback", "continue"} or "redirect" in u:
        return "redirect"
    if p in {"q", "search", "comment", "message", "content"} and (not content_type or "html" in (content_type or "").lower()):
        return "xss"
    if p in {"id", "uid", "pid", "productid", "order", "page", "sort", "filter"}:
        return "sqli"
    return "sqli"

def _create_payload_file(payload: str, directory: Optional[Path] = None) -> Path:
    directory = directory or (REPO_ROOT / "payloads" / "temp")
    directory.mkdir(parents=True, exist_ok=True)
    p = directory / f"{uuid.uuid4()}.txt"
    p.write_text((payload or "").strip() + "\n", encoding="utf-8")
    return p

def _filter_targets_by_selection(raw_targets: List[Dict[str, Any]], selection: Optional[List[EndpointShape]]) -> List[Dict[str, Any]]:
    if not selection:
        return raw_targets
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for t in raw_targets:
        grouped.setdefault(_key(t.get("method", "GET"), t["url"]), []).append(t)
    chosen: List[Dict[str, Any]] = []
    for sel in selection:
        key = _key(sel.method, sel.url)
        candidates = grouped.get(key, [])
        if not candidates:
            continue
        if sel.params:
            allowed = set(sel.params)
            chosen.extend([t for t in candidates if t.get("param") in allowed])
        else:
            chosen.extend(candidates)
    seen: set[Tuple[str, str, str]] = set()
    unique: List[Dict[str, Any]] = []
    for t in chosen:
        sig = (t.get("method", "GET").upper(), t["url"], t.get("param", ""))
        if sig in seen:
            continue
        seen.add(sig)
        unique.append(t)
    return unique

def _fuzz_targets_ffuf(
    targets: List[FuzzTarget],
    reco: Optional[Recommender],
    top_n: int = 3,
    threshold: float = 0.2,
    global_headers: Optional[Dict[str, str]] = None,   # NEW
) -> List[Dict[str, Any]]:
    """Legacy ffuf-based fuzz. Keep for compatibility; prefer core engine."""
    if run_ffuf is None:
        raise HTTPException(400, "ffuf engine not available on this deployment")

    results: List[Dict[str, Any]] = []

    for t in targets:
        # feature extraction (best-effort; does not block)
        try:
            feats = fe.extract_features(t.url, t.param, payload="' OR 1=1 --", method=t.method)
        except Exception:
            logging.exception("feature_extractor failed for %s %s", t.url, t.param)
            feats = None

        # payload selection (ML or fallback)
        try:
            if reco is not None and feats is not None:
                try:
                    pairs = reco.recommend(feats, top_n=top_n, threshold=threshold)  # [(payload, prob), ...]
                except TypeError:
                    pairs = reco.recommend(feats, top_n=top_n)  # legacy signature
                candidates = [(p, float(conf)) for p, conf in (pairs or [])]
            else:
                candidates = []
        except Exception:
            logging.exception("recommender failed; falling back")
            candidates = []

        if not candidates:
            family = _choose_family(t.method, t.url, t.param, (t.meta or {}).get("headers", {}).get("Content-Type"))
            for p in _fallback_payloads_for_family(family):
                candidates.append((p, 0.0))

        # baseline request (seed if available)
        baseline_meta = None
        try:
            seed_val = (t.meta.get("seed") or {}).get("value") if t.meta else None
            if seed_val is not None:
                m, u, h, d, j = _build_request_with_value(t, str(seed_val), global_headers=global_headers)
                baseline_meta = _send_once(m, u, h, d, j, follow_redirects=False)
        except Exception:
            logging.exception("baseline request failed for %s %s", t.url, t.param)

        # per-payload ffuf
        for payload, base_conf in candidates:
            payload_file = _create_payload_file(payload, FFUF_TMP)
            try:
                # headers for ffuf subprocess
                eff_headers = _merge_headers((t.meta or {}).get("headers") or {}, t.headers)
                eff_headers = _merge_headers(eff_headers, global_headers or {})   # NEW

                ffuf_out = run_ffuf(  # type: ignore
                    url=t.url,
                    param=t.param,
                    payload_file=str(payload_file),
                    method=t.method,
                    headers=eff_headers or None,
                    body=(t.meta or {}).get("body"),
                    body_type=(t.meta or {}).get("body_type"),
                    output_dir=str(FFUF_TMP),
                )
                # verify single request with payload to derive deltas/redirects
                verify_meta = None
                try:
                    m, u, h, d, j = _build_request_with_value(t, payload, global_headers=global_headers)
                    verify_meta = _send_once(m, u, h, d, j, follow_redirects=False)
                except Exception:
                    logging.exception("verify request failed for %s %s", t.url, t.param)

                external_redirect = bool(verify_meta and _is_external_redirect(t.url, verify_meta.get("location")))
                delta = _delta(baseline_meta, verify_meta)

                try:
                    features = {
                        "status_changed": (delta or {}).get("status_changed", 0),
                        "len_ratio": (delta or {}).get("len_ratio", 1.0),
                        "is_5xx": (delta or {}).get("is_5xx", 0),
                        "is_4xx": (delta or {}).get("is_4xx", 0),
                        "external_redirect": 1 if external_redirect else 0,
                    }
                    if DELTA_SCORER is not None:
                        derived_conf = max(float(base_conf or 0.0), float(DELTA_SCORER.score(features)))  # type: ignore
                    else:
                        derived_conf = _derive_confidence_fallback(float(base_conf or 0.0), len(ffuf_out.get("matches") or []), external_redirect)
                except Exception:
                    derived_conf = _derive_confidence_fallback(float(base_conf or 0.0), len(ffuf_out.get("matches") or []), external_redirect)

                matches = ffuf_out.get("matches") or []
                one = {
                    "url": t.url,
                    "param": t.param,
                    "method": t.method,
                    "payload": payload,
                    "confidence": float(min(1.0, max(0.0, derived_conf))),
                    "status": "ok",
                    "verify": verify_meta,
                    "baseline": baseline_meta,
                    "delta": delta,
                    "signals": {"external_redirect": external_redirect},
                    "ffuf": {
                        "match_count": len(matches),
                        "errors": ffuf_out.get("errors"),
                        "elapsed_ms": ffuf_out.get("elapsed_ms"),
                        "response_length": ffuf_out.get("response_length"),
                        "status": ffuf_out.get("status"),
                        "first_matches": [
                            {
                                "status": m.get("status"),
                                "length": m.get("length"),
                                "words": m.get("words"),
                                "lines": m.get("lines"),
                                "url": m.get("url"),
                            } for m in matches[:3]
                        ],
                    },
                }
                results.append(one)

                # optional: persist to your evidence sink
                if t.job_id:
                    try:
                        label = _guess_label(payload)
                        persist_evidence(
                            job_id=t.job_id,
                            method=t.method,
                            url=t.url,
                            param_locs={"body": [t.param]} if ((t.meta or {}).get("body_type") in {"json","form"}) else {"query": [t.param]},
                            param=t.param,
                            family=label,
                            payload_id="ffuf",
                            request_meta={"headers": eff_headers},
                            response_meta={"verify": verify_meta, "baseline": baseline_meta, "delta": delta},
                            signals={"external_redirect": external_redirect, "ffuf_match_count": len(matches)},
                            confidence=float(min(1.0, max(0.0, derived_conf))),
                            label=label,
                        )
                    except Exception:
                        logging.exception("persist_evidence failed")

            except Exception as e:
                logging.exception("ffuf run failed for %s %s", t.url, t.param)
                results.append({
                    "url": t.url,
                    "param": t.param,
                    "method": t.method,
                    "payload": payload,
                    "status": "error",
                    "stage": "ffuf",
                    "error": str(e),
                    "meta": t.meta,
                })
            finally:
                try:
                    payload_file.unlink(missing_ok=True)
                except Exception:
                    pass
    return results


# =========================
# Core engine (primary)
# =========================
def _run_core_engine(job_id: str, selection: Optional[List[EndpointShape]], bearer_token: Optional[str]) -> List[Dict[str, Any]]:
    job_dir = JOBS_DIR / job_id
    blob = _load_crawl(job_id)
    eps = blob.get("endpoints") or []
    if not isinstance(eps, list):
        raise HTTPException(400, "crawl_result.json missing 'endpoints' list")

    if selection:
        eps = _filter_endpoints_by_selection(eps, selection)
        if not eps:
            return []

    # Normalize bearer before handing to builder (builder will set header)
    norm = _normalize_bearer(bearer_token)
    # build_targets writes targets.json and returns its path
    targets_path = build_targets(eps, job_dir, bearer_token=(norm.split(" ", 1)[1] if norm else None))  # pass raw token if builder expects it
    evidence_path = run_fuzz(job_dir, targets_path, out_dir=job_dir / "results")
    return _read_evidence(evidence_path)


# =========================
# API endpoints
# =========================
@router.post("/fuzz")
def fuzz_many(
    targets: List[FuzzTarget],
    reco: Optional[Recommender] = Depends(lambda: Recommender() if Recommender else None),  # keep legacy dep
):
    """
    Legacy endpoint: fuzz an explicit list of FuzzTarget items via ffuf flow.
    Prefer /fuzz/by_job with engine="core".
    """
    results = _fuzz_targets_ffuf(targets, reco=reco)
    job_ids = {t.job_id for t in targets if t.job_id}
    if len(job_ids) == 1:
        LATEST_RESULTS[next(iter(job_ids))] = results
    return {"results": results}


@router.post("/fuzz/by_job/{job_id}")
def fuzz_by_job(
    job_id: str,
    payload: Optional[FuzzByJobPayload] = None,
    reco: Optional[Recommender] = Depends(lambda: Recommender() if Recommender else None),
):
    """
    Run fuzzing for a job. Engines:
      - "core"  : verification-first engine (recommended)
      - "ffuf"  : legacy ffuf-based engine
      - "hybrid": ffuf first (best-effort), then core

    Body (optional):
    {
      "engine": "core",
      "selection": [{ "method":"GET","url":"/api/search","params":["q","size"] }],
      "top_n": 3,
      "threshold": 0.2,
      "bearer_token": "<jwt or 'Bearer ...' or 'Authorization: Bearer ...'>",
      "extra_headers": { "X-Trace": "1" }
    }
    """
    engine = (payload.engine if payload else "core").lower()
    bearer = payload.bearer_token if payload else None
    global_headers = _build_global_headers(payload)

    if engine not in {"core", "ffuf", "hybrid"}:
        raise HTTPException(400, "engine must be one of: core, ffuf, hybrid")

    results: List[Dict[str, Any]] = []

    if engine in {"ffuf", "hybrid"}:
        # Build legacy per-param targets from captured traffic (query-only fallback)
        blob = _load_crawl(job_id)
        base_host = urlparse(blob.get("target") or blob.get("target_url") or "").netloc
        raw_targets = blob.get("captured_requests") or []
        tmp_targets: List[FuzzTarget] = []
        for r in raw_targets:
            url = r.get("url") or ""
            method = (r.get("method") or "GET").upper()
            if not url or urlparse(url).netloc != base_host:
                continue
            if method == "GET":
                from urllib.parse import parse_qs
                for param in sorted(parse_qs(urlparse(url).query, keep_blank_values=True).keys()):
                    tmp_targets.append(
                        FuzzTarget(
                            url=url,
                            param=param,
                            method=method,
                            job_id=job_id,
                            headers=global_headers,                # inject global headers here
                            meta={"headers": (r.get("headers") or {})},
                        )
                    )
        if payload and payload.selection:
            tmp_targets = [FuzzTarget(**t.dict()) for t in _filter_targets_by_selection([t.dict() for t in tmp_targets], payload.selection)]
        results_ffuf = _fuzz_targets_ffuf(
            tmp_targets,
            reco=reco,
            top_n=(payload.top_n if payload else 3),
            threshold=(payload.threshold if payload else 0.2),
            global_headers=global_headers,                               # NEW
        )
        results.extend(results_ffuf)

    if engine in {"core", "hybrid"}:
        results_core = _run_core_engine(job_id, payload.selection if payload else None, bearer_token=bearer)
        results.extend(results_core)

    # cache for polling
    LATEST_RESULTS[job_id] = results

    # auto-advance phase (best-effort)
    if SessionLocal and ScanJob and JobPhase:
        try:
            with SessionLocal() as db:
                row = db.query(ScanJob).filter_by(job_id=job_id).first()
                if row:
                    row.phase = JobPhase.triage
                    db.commit()
        except Exception:
            logging.exception("DB update failed")

    return {"job_id": job_id, "count": len(results), "results": results}


@router.get("/fuzz/result/{job_id}")
def get_fuzz_result(job_id: str):
    """Return the last in-memory fuzz results (for UI polling)."""
    return {"job_id": job_id, "results": LATEST_RESULTS.get(job_id, [])}
