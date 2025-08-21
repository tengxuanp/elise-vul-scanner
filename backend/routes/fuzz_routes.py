# backend/routes/fuzz_routes.py
from __future__ import annotations

import logging
import uuid
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from ..modules.fuzzer_ffuf import run_ffuf
from ..modules.feature_extractor import FeatureExtractor
from ..modules.recommender import Recommender
from ..modules.target_builder import build_fuzz_targets_for_job

from ..db import SessionLocal
from ..models import ScanJob, JobPhase

# --- new imports for baseline/verify/deltas ---
import httpx
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

# -------- storage locations --------
REPO_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = REPO_ROOT / "data" / "results" / "ffuf"
DATA_DIR.mkdir(parents=True, exist_ok=True)

# -------- optional evidence sink --------
try:
    from ..modules.evidence_sink import persist_evidence  # type: ignore
except Exception:
    def persist_evidence(**kwargs):  # type: ignore
        return {"endpoint_id": None, "test_case_id": None, "evidence_id": None}

# -------- optional ML modules (safe fallbacks if missing) --------
# Payload family router
try:
    from ..modules.ml.family_router import choose_family  # type: ignore
except Exception:  # fallback heuristic
    def choose_family(method: str, url: str, param: str, content_type: Optional[str]) -> str:
        p = (param or "").lower()
        u = (url or "").lower()
        if p in {"to", "return_to", "redirect", "url", "next", "callback", "continue"} or "redirect" in u:
            return "redirect"
        if p in {"q", "search", "comment", "message", "content"} and (not content_type or "html" in (content_type or "").lower()):
            return "xss"
        if p in {"id", "uid", "pid", "productid", "order", "page", "sort", "filter"}:
            return "sqli"
        return "sqli"

# Delta scorer
try:
    from ..modules.ml.delta_scorer import DeltaScorer  # type: ignore
    DELTA_SCORER: Optional[DeltaScorer] = DeltaScorer()
    try:
        DELTA_SCORER.load()
    except Exception:
        DELTA_SCORER = None
except Exception:
    DELTA_SCORER = None

router = APIRouter()
fe = FeatureExtractor()

# Cache latest results by job for simple polling
LATEST_RESULTS: Dict[str, List[Dict[str, Any]]] = {}


# -------- helpers --------
def create_payload_file(payload: str, directory: Optional[Path] = None) -> Path:
    directory = directory or (REPO_ROOT / "payloads" / "temp")
    directory.mkdir(parents=True, exist_ok=True)
    p = directory / f"{uuid.uuid4()}.txt"
    p.write_text(payload.strip() + "\n", encoding="utf-8")
    return p

def _fallback_payloads_for_family(family: str) -> List[str]:
    family = (family or "").lower()
    if family == "redirect":
        return [
            "https://example.org/",
            "//evil.tld",
            "https:%2F%2Fattacker.tld",
            "/\\evil.tld",
        ]
    if family == "xss":
        return [
            "\"/><script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
        ]
    # default: SQLi-leaning, boolean-based
    return [
        "' OR 1=1--",
        "' OR 'a'='b'--",
        "\" OR \"a\"=\"a\" --",
    ]

def _guess_label(payload: str) -> str:
    s = payload.lower()
    if any(x in s for x in ("<script", "onerror=", "onload=", "alert(")):
        return "xss"
    if any(x in s for x in ("http://", "https://", "//")):
        return "redirect"
    if any(x in s for x in (" or 1=1", "'--", "\"--")):
        return "sqli"
    return "benign"

def _derive_confidence_fallback(base_conf: float, match_count: int, external_redirect: bool) -> float:
    """
    Legacy fallback if ML delta scorer isn't available.
    """
    if external_redirect:
        return 0.8
    if base_conf and base_conf > 0:
        return float(base_conf)
    return min(1.0, 0.2 + 0.2 * match_count)

def _merge_headers(h1: Optional[Dict[str, str]], h2: Optional[Dict[str, str]]) -> Dict[str, str]:
    """
    Merge headers with h2 overriding h1 on key collisions.
    """
    out: Dict[str, str] = {}
    for src in (h1 or {}), (h2 or {}):
        for k, v in src.items():
            out[k] = v
    return out

def _key(method: str, url: str) -> str:
    return f"{method.upper()} {url}"

# --- request construction for baseline/verify ---
def _url_with_replaced_param(url: str, param: str, value: str) -> str:
    p = urlparse(url)
    q = [(k, v) for (k, v) in parse_qsl(p.query, keep_blank_values=True) if k != param]
    q.append((param, value))
    new_q = urlencode(q, doseq=True)
    return urlunparse((p.scheme, p.netloc, p.path, p.params, new_q, p.fragment))

def _build_request_with_value(t: "FuzzTarget", value: str) -> Tuple[str, str, Dict[str, str], Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """
    Build a single HTTP request identical to the fuzzed one, but with a specific value.
    Returns (method, url, headers, data(form), json(json)).
    """
    method = (t.method or "GET").upper()
    headers = dict((t.meta or {}).get("headers") or {})
    body = (t.meta or {}).get("body")
    body_type = (t.meta or {}).get("body_type")
    if method == "GET":
        url = _url_with_replaced_param(t.url, t.param, value)
        return method, url, headers, None, None
    else:
        if body_type == "json":
            b = dict(body or {})
            if t.param in b:
                b[t.param] = value
            return method, t.url, headers, None, b
        elif body_type == "form":
            b = dict(body or {})
            if t.param in b:
                b[t.param] = value
            else:
                # ensure presence once
                b[t.param] = value
            return method, t.url, headers, b, None
        else:
            # treat as query-only if no declared body_type
            url = _url_with_replaced_param(t.url, t.param, value)
            return method, url, headers, None, None

def _send_once(method: str, url: str, headers: Dict[str, str], data: Optional[Dict[str, Any]] = None, json_: Optional[Dict[str, Any]] = None, follow_redirects: bool = False) -> Dict[str, Any]:
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
    if location.startswith("http://") or location.startswith("https://") or location.startswith("//"):
        try:
            b = urlparse(base_url)
            l = urlparse(location if "://" in location else f"{b.scheme}:{location}")
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


# -------- dependencies --------
def get_recommender(request: Request) -> Optional[Recommender]:
    """Return a ready recommender or None (fallback to static payloads)."""
    obj = getattr(request.app.state, "reco", None)
    if obj is not None:
        return obj

    try:
        r = Recommender()
    except FileNotFoundError:
        return None

    load = getattr(r, "load", None)
    if callable(load):
        try:
            r.load()
        except FileNotFoundError:
            return None

    request.app.state.reco = r
    return r


# -------- models --------
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
    params: Optional[List[str]] = None   # if provided, restrict to these param names
    body_keys: Optional[List[str]] = None  # informational; we match by param

class FuzzByJobPayload(BaseModel):
    selection: Optional[List[EndpointShape]] = None
    top_n: int = 3
    threshold: float = 0.2


# -------- core fuzz routine --------
def _fuzz_targets(
    targets: List[FuzzTarget],
    reco: Optional[Recommender],
    top_n: int = 3,
    threshold: float = 0.2,
) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []

    for t in targets:
        # 0) Pre-calc context
        meta = t.meta or {}
        h_lower = {k.lower(): v for k, v in (meta.get("headers") or {}).items()}
        content_type = h_lower.get("content-type")
        family = choose_family(t.method, t.url, t.param, content_type)

        # 1) Feature extraction (best-effort; do not block fuzzing)
        try:
            base_payload = "' OR 1=1 --"
            feats = fe.extract_features(t.url, t.param, payload=base_payload, method=t.method)
        except Exception:
            logging.exception("feature_extractor failed for %s %s", t.url, t.param)
            feats = None

        # 2) Payload selection (ML or fallback)
        try:
            if reco is not None and feats is not None:
                try:
                    pairs = reco.recommend(feats, top_n=top_n, threshold=threshold, family=family)  # [(payload, prob), ...]
                except TypeError:
                    pairs = reco.recommend(feats, top_n=top_n, threshold=threshold)  # legacy signature
                candidates = [(p, float(conf)) for p, conf in pairs] if pairs else []
                if not candidates:
                    candidates = [(p, 0.0) for p in _fallback_payloads_for_family(family)]
            else:
                candidates = [(p, 0.0) for p in _fallback_payloads_for_family(family)]
        except Exception:
            logging.exception("recommender failed; falling back")
            candidates = [(p, 0.0) for p in _fallback_payloads_for_family(family)]

        # 3) Build request context (headers/body/body_type), with meta taking precedence
        meta_headers: Dict[str, str] = meta.get("headers") or {}
        meta_body = meta.get("body")
        meta_body_type = meta.get("body_type")  # "json" | "form" | None
        eff_headers = _merge_headers(meta_headers, t.headers)

        # 3.5) Baseline using seed value if available
        baseline_meta = None
        try:
            seed_val = (meta.get("seed") or {}).get("value", None)
            if seed_val is not None:
                m, u, h, d, j = _build_request_with_value(t, str(seed_val))
                baseline_meta = _send_once(m, u, _merge_headers(h, eff_headers), d, j, follow_redirects=False)
        except Exception:
            logging.exception("baseline request failed for %s %s", t.url, t.param)

        # 4) Execute ffuf per candidate and verify redirect/deltas
        for payload, base_conf in candidates:
            payload_file = create_payload_file(payload)
            try:
                ffuf_out = run_ffuf(
                    url=t.url,
                    param=t.param,
                    payload_file=str(payload_file),
                    method=t.method,
                    headers=eff_headers or None,
                    body=meta_body,
                    body_type=meta_body_type,
                    output_dir=str(DATA_DIR),
                )

                # One verification request with the payload to inspect headers/status/len
                verify_meta = None
                try:
                    m, u, h, d, j = _build_request_with_value(t, payload)
                    verify_meta = _send_once(m, u, _merge_headers(h, eff_headers), d, j, follow_redirects=False)
                except Exception:
                    logging.exception("verify request failed for %s %s", t.url, t.param)

                external_redirect = bool(verify_meta and _is_external_redirect(t.url, verify_meta.get("location")))
                delta = _delta(baseline_meta, verify_meta)

                # Confidence via ML delta scorer (fallback if missing)
                try:
                    features = {
                        "status_changed": (delta or {}).get("status_changed", 0),
                        "len_ratio": (delta or {}).get("len_ratio", 1.0),
                        "is_5xx": (delta or {}).get("is_5xx", 0),
                        "is_4xx": (delta or {}).get("is_4xx", 0),
                        "external_redirect": 1 if external_redirect else 0,
                    }
                    if DELTA_SCORER is not None:
                        derived_conf = max(float(base_conf or 0.0), float(DELTA_SCORER.score(features)))
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
                    "family": family,
                    "confidence": float(min(1.0, max(0.0, derived_conf))),
                    "output_file": ffuf_out.get("output_file"),
                    "status": "ok",
                    "meta": t.meta,
                    "verify": verify_meta,
                    "baseline": baseline_meta,
                    "delta": delta,
                    "signals": {
                        "external_redirect": external_redirect,
                    },
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

                # Persist evidence if job_id provided
                if t.job_id:
                    try:
                        # Decide param location for bookkeeping
                        param_in_body = isinstance(meta_body, dict) and t.param in meta_body
                        param_locs = (
                            {"body": [t.param]}
                            if (t.method.upper() != "GET" and param_in_body)
                            else {"query": [t.param]}
                        )

                        request_meta = {
                            "method": t.method,
                            "url": t.url,
                            "param": t.param,
                            "payload_path": ffuf_out.get("payload_file") or str(payload_file),
                            "headers": eff_headers,
                            "body_type": meta_body_type,
                        }
                        response_meta = {
                            "elapsed_ms": ffuf_out.get("elapsed_ms"),
                            "output_file": ffuf_out.get("output_file"),
                            "status": ffuf_out.get("status"),
                            "len": ffuf_out.get("response_length"),
                            "verify": verify_meta,
                            "baseline": baseline_meta,
                            "delta": delta,
                        }
                        label = _guess_label(payload)
                        signals = {
                            "ffuf_match_count": len(matches),
                            "ffuf_errors": ffuf_out.get("errors"),
                            "external_redirect": external_redirect,
                        }

                        persist_evidence(
                            job_id=t.job_id,
                            method=t.method,
                            url=t.url,
                            param_locs=param_locs,
                            param=t.param,
                            family=label,
                            payload_id="auto",
                            request_meta=request_meta,
                            response_meta=response_meta,
                            signals=signals,
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


# -------- endpoints --------
@router.post("/fuzz")
def fuzz_many(
    targets: List[FuzzTarget],
    reco: Optional[Recommender] = Depends(get_recommender),
):
    """
    Legacy endpoint: fuzz an explicit list of FuzzTarget items.
    """
    results = _fuzz_targets(targets, reco=reco)
    # best-effort: attach to a synthetic job bucket if all share the same job_id
    job_ids = {t.job_id for t in targets if t.job_id}
    if len(job_ids) == 1:
        LATEST_RESULTS[next(iter(job_ids))] = results
    return {"results": results}


def _filter_targets_by_selection(
    raw_targets: List[Dict[str, Any]],
    selection: Optional[List[EndpointShape]],
) -> List[Dict[str, Any]]:
    if not selection:
        return raw_targets

    # Group raw targets by method+url for quick match
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for t in raw_targets:
        grouped.setdefault(_key(t.get("method", "GET"), t["url"]), []).append(t)

    chosen: List[Dict[str, Any]] = []
    for sel in selection:
        key = _key(sel.method, sel.url)
        candidates = grouped.get(key, [])
        if not candidates:
            continue

        # If params provided, only include those targets whose single 'param' is in list
        if sel.params:
            allowed = set(sel.params)
            chosen.extend([t for t in candidates if t.get("param") in allowed])
        else:
            # No explicit params: include all under this method+url
            chosen.extend(candidates)

    # Dedup by (method,url,param) triple
    seen: set[Tuple[str, str, str]] = set()
    unique: List[Dict[str, Any]] = []
    for t in chosen:
        sig = (t.get("method", "GET").upper(), t["url"], t.get("param", ""))
        if sig in seen:
            continue
        seen.add(sig)
        unique.append(t)
    return unique


@router.post("/fuzz/by_job/{job_id}")
def fuzz_by_job(
    job_id: str,
    payload: Optional[FuzzByJobPayload] = None,
    reco: Optional[Recommender] = Depends(get_recommender),
):
    """
    Fuzz all targets for a job, or only a selected subset if 'selection' is provided.
    Body (optional):
    {
      "selection": [{ "method":"GET","url":"/api/search","params":["q","size"] }, ...],
      "top_n": 3,
      "threshold": 0.2
    }
    """
    raw_targets = build_fuzz_targets_for_job(job_id)
    if payload and payload.selection:
        raw_targets = _filter_targets_by_selection(raw_targets, payload.selection)

    targets = [FuzzTarget(**{**t, "job_id": job_id}) for t in raw_targets]
    results = _fuzz_targets(
        targets,
        reco=reco,
        top_n=(payload.top_n if payload else 3),
        threshold=(payload.threshold if payload else 0.2),
    )

    # cache for polling
    LATEST_RESULTS[job_id] = results

    # auto-advance phase
    with SessionLocal() as db:
        row = db.query(ScanJob).filter_by(job_id=job_id).first()
        if row:
            row.phase = JobPhase.triage
            db.commit()

    return {"job_id": job_id, "count": len(results), "results": results}


@router.get("/fuzz/result/{job_id}")
def get_fuzz_result(job_id: str):
    """
    Best-effort retrieval of the latest fuzz results for a job (in-memory).
    Intended for UI polling; not a persistent store.
    """
    return {"job_id": job_id, "results": LATEST_RESULTS.get(job_id, [])}
