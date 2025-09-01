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
from ..modules.fuzzer_core import run_fuzz  # primary (verification-first)
try:
    # optional, legacy ffuf runner used inside _fuzz_targets_ffuf()
    from ..modules.fuzzer_ffuf import run_ffuf  # type: ignore
except Exception:  # pragma: no cover
    run_ffuf = None  # type: ignore

# ---- builders ----
# New builder that consumes merged endpoints from crawl_result.json
from ..modules.target_builder import build_targets  # type: ignore

# ---- optional ML/feature plumbing (safe fallbacks) ----
try:
    from ..modules.feature_extractor import FeatureExtractor  # type: ignore
except Exception:  # pragma: no cover
    class FeatureExtractor:  # minimal stub
        def extract_features(self, *a, **kw): return {}

# Import the real Recommender - no stub fallback
from ..modules.recommender import Recommender  # type: ignore

def _init_reco() -> Optional[Recommender]:
    """Instantiate and best-effort load recommender."""
    try:
        r = Recommender()
        try:
            if hasattr(r, "load"):
                r.load()  # may no-op
        except Exception:
            logging.exception("Recommender.load() failed; continuing with object anyway")
        return r
    except Exception:
        logging.exception("Failed to initialize Recommender")
        return None

# ---- DB (optional) ----
try:
    from ..db import SessionLocal  # type: ignore
    from ..models import ScanJob, JobPhase  # type: ignore
except Exception:  # pragma: no cover
    SessionLocal, ScanJob, JobPhase = None, None, None

# ---- filesystem layout ----
REPO_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = REPO_ROOT / "data"
JOBS_DIR = DATA_DIR / "jobs"
RESULTS_DIR = DATA_DIR / "results"
FFUF_TMP = DATA_DIR / "results" / "ffuf"
for _p in (JOBS_DIR, RESULTS_DIR, FFUF_TMP):
    _p.mkdir(parents=True, exist_ok=True)

# ---- optional evidence sink ----
try:
    from ..modules.evidence_sink import persist_evidence  # type: ignore
except Exception:  # pragma: no cover
    def persist_evidence(**kwargs):  # type: ignore
        return {"endpoint_id": None, "test_case_id": None, "evidence_id": None}

router = APIRouter()
fe = FeatureExtractor()

# Cache latest results by job for simple polling
LATEST_RESULTS: Dict[str, List[Dict[str, Any]]] = {}

# ML-used paths for clear “origin” labeling
_ML_USED_PATHS = {
    "family_ranker",
    "plugin",
    "generic_pairwise",
    "generic_predict_proba",
    "generic_decision_function",
    "generic_predict",
    "legacy_recommend",  # include legacy recommender path as ML
}


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
    """High-level endpoint selector from the UI (method + exact URL)."""
    method: str
    url: str
    # If provided, restrict to these parameter names across ANY location (query|form|json)
    params: Optional[List[str]] = None


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
    """
    Filter merged endpoints (from crawler) by method+url and optional param list.
    If params are provided, trim param_locs to those names across query|form|json.
    """
    if not selection:
        return endpoints

    # Map "METHOD URL" -> allowed set (None = all params)
    allow: Dict[str, Optional[set]] = {}
    for s in selection:
        key = _key(s.method, s.url)
        allow[key] = set([p for p in (s.params or []) if p]) if s.params else None

    def _names(items):
        out = []
        for it in items or []:
            if isinstance(it, str):
                out.append(it)
            elif isinstance(it, dict) and it.get("name"):
                out.append(it["name"])
        return out

    filtered: List[Dict[str, Any]] = []
    for ep in endpoints:
        key = _key(ep.get("method", "GET"), ep.get("url", ""))
        if key not in allow:
            continue
        allowed = allow[key]
        if allowed is None:
            # Normalize convenience fields even if we accept all params
            ep2 = dict(ep)
            locs = dict(ep2.get("param_locs") or {})
            ep2["param_locs"] = {
                "query": _names(locs.get("query")),
                "form": _names(locs.get("form")),
                "json": _names(locs.get("json")),
            }
            ep2["query_keys"] = ep2["param_locs"]["query"]
            ep2["body_keys"] = ep2["param_locs"]["form"] or ep2["param_locs"]["json"]
            ep2["content_type"] = ep.get("content_type_hint") or ep.get("content_type")
            filtered.append(ep2)
            continue

        # Trim to allowed names
        ep2 = dict(ep)
        locs = dict(ep2.get("param_locs") or {})
        qn = [n for n in _names(locs.get("query")) if n in allowed]
        fn = [n for n in _names(locs.get("form")) if n in allowed]
        jn = [n for n in _names(locs.get("json")) if n in allowed]
        if not (qn or fn or jn):
            continue
        ep2["param_locs"] = {"query": qn, "form": fn, "json": jn}
        # legacy helpers for any old code paths
        ep2["query_keys"] = qn
        ep2["body_keys"] = fn if fn else jn
        ep2["content_type"] = ep.get("content_type_hint") or ep.get("content_type")
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


def _hostname_of(url: Optional[str]) -> Optional[str]:
    if not url:
        return None
    try:
        return urlparse(url).netloc or None
    except Exception:
        return None


def _post_normalize_row_for_ui(one: Dict[str, Any]) -> Dict[str, Any]:
    """
    Make sure the row contains:
      - signals.verify (dup of top-level verify if needed)
      - signals.open_redirect.{open_redirect,location,location_host}
      - origin: 'ml' | 'curated'
      - ranker_meta (and mirror ranker_score top-level for legacy)
      - method upper-cased; family present when we can infer it
    """
    out = dict(one or {})
    signals = dict(out.get("signals") or {})
    # Copy verify up into signals.verify if present elsewhere
    verify = out.get("verify") or signals.get("verify") or (out.get("response_meta") or {}).get("verify")
    if isinstance(verify, dict):
        signals["verify"] = verify

    # Open-redirect consolidation
    loc = None
    if isinstance(verify, dict):
        loc = verify.get("location")
    open_redirect = signals.get("external_redirect") or signals.get("open_redirect", {}).get("open_redirect")
    open_redirect_obj = dict(signals.get("open_redirect") or {})
    if loc is not None:
        open_redirect_obj["location"] = loc
    if "open_redirect" not in open_redirect_obj and isinstance(open_redirect, bool):
        open_redirect_obj["open_redirect"] = open_redirect
    if "location_host" not in open_redirect_obj and loc:
        open_redirect_obj["location_host"] = _hostname_of(loc)
    if open_redirect_obj:
        signals["open_redirect"] = open_redirect_obj

    # Ensure booleans exist (even if falsey) for UI safety
    for k in ("sql_error", "boolean_sqli", "time_sqli", "xss_reflected", "external_redirect"):
        if k not in signals:
            signals[k] = bool(signals.get(k))

    out["signals"] = signals

    # Origin determination (keep if explicitly set; else infer)
    if "origin" not in out:
        origin_existing = (out.get("origin") or (out.get("meta") or {}).get("origin") or "").strip().lower()
        is_ml_flags = any([
            bool(out.get("is_ml")),
            isinstance(out.get("ml"), (dict, bool)) and out.get("ml") not in (False, None),
            isinstance(out.get("ranker_meta"), dict) and (
                "ranker_score" in out["ranker_meta"]
                or "family_probs" in out["ranker_meta"]
                or "model_ids" in out["ranker_meta"]
                or out["ranker_meta"].get("used_path") in _ML_USED_PATHS
            ),
            isinstance(out.get("ml_meta"), dict),
            isinstance(out.get("ranker"), dict),
            isinstance((out.get("payload_id") or ""), str) and out.get("payload_id", "").lower().startswith("ml-"),
            origin_existing == "ml",
        ])
        out["origin"] = "ml" if is_ml_flags else "curated"

    # Ranker meta mirroring (so UI always finds something)
    rm = out.get("ranker_meta") or out.get("ranker") or out.get("ml_meta") or {}
    if not isinstance(rm, dict):
        rm = {}
    if "family_chosen" not in rm and out.get("family"):
        rm["family_chosen"] = out.get("family")
    out["ranker_meta"] = rm
    if "ranker_score" in rm and "ranker_score" not in out:
        try:
            out["ranker_score"] = float(rm["ranker_score"])
        except Exception:
            pass

    # Method normalization
    if out.get("method"):
        out["method"] = str(out["method"]).upper()

    # Family fallback if missing (very light heuristic)
    if not out.get("family"):
        param = (out.get("param") or "").lower()
        url_l = (out.get("url") or "").lower()
        if param in {"to", "return_to", "redirect", "url", "next", "callback", "continue"} or "redirect" in url_l:
            out["family"] = "redirect"
        elif param in {"q", "query", "search", "comment", "message", "content", "text", "title", "name"}:
            out["family"] = "xss"
        else:
            out["family"] = "sqli"

    return out


def _post_normalize_results_for_ui(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [_post_normalize_row_for_ui(r) for r in (rows or [])]


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
    global_headers: Optional[Dict[str, str]] = None,
) -> Tuple[str, str, Dict[str, str], Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    method = (t.method or "GET").upper()
    headers = _merge_headers((t.meta or {}).get("headers") or {}, t.headers)
    headers = _merge_headers(headers, global_headers or {})
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
    if any(x in s for x in (" or 1=1", "'--", "\"--", "union select", "sleep(")): return "sqli"
    return "benign"

# optional ML delta scorer
try:
    from ..modules.ml.delta_scorer import DeltaScorer  # type: ignore
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
    global_headers: Optional[Dict[str, str]] = None,
) -> List[Dict[str, Any]]:
    """Legacy ffuf-based fuzz. Keep for compatibility; prefer core engine."""
    if run_ffuf is None:
        raise HTTPException(400, "ffuf engine not available on this deployment")

    results: List[Dict[str, Any]] = []

    for t in targets:
        # Determine family up-front and use it consistently (ML + fallback)
        content_type = (t.meta or {}).get("headers", {}).get("Content-Type")
        family = _choose_family(t.method, t.url, t.param, content_type)

        # feature extraction (best-effort; does not block)
        try:
            feats = fe.extract_features(t.url, t.param, payload="' OR 1=1 --", method=t.method)
        except Exception:
            logging.exception("feature_extractor failed for %s %s", t.url, t.param)
            feats = None

        # payload selection (ML or fallback) — now using recommend_with_meta
        candidates: List[Tuple[str, float]] = []
        ranker_meta: Dict[str, Any] = {}
        try:
            if reco is not None and feats is not None and hasattr(reco, "recommend_with_meta"):
                pairs, meta = reco.recommend_with_meta(
                    feats=feats,
                    top_n=top_n,
                    threshold=threshold,
                    family=family,   # critical: keep the family consistent
                )
                candidates = [(p, float(conf)) for p, conf in (pairs or [])]
                ranker_meta = dict(meta or {})
        except Exception:
            logging.exception("recommender.recommend_with_meta failed; falling back")
            candidates = []

        used_fallback = False
        if not candidates:
            used_fallback = True
            for p in _fallback_payloads_for_family(family):
                candidates.append((p, 0.0))
            ranker_meta = {}

        # Decide origin up-front based on ranker_meta.used_path
        origin = "ml" if (ranker_meta.get("used_path") in _ML_USED_PATHS) else "curated"

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
                eff_headers = _merge_headers(eff_headers, global_headers or {})

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

                # Construct result with full ranker_meta + truthful origin
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
                    "family": family,
                    # Origin & ranker
                    "origin": origin if not used_fallback else "curated",
                    "ranker_meta": ranker_meta if not used_fallback else {},
                    "ranker_score": float(base_conf or 0.0) if not used_fallback else None,
                    "ml": {"enabled": True, "ranker": ranker_meta} if (origin == "ml" and not used_fallback) else False,
                    # Signals: include external + open_redirect shape + dup verify for UI
                    "signals": {
                        "external_redirect": external_redirect,
                        "verify": verify_meta or {},
                        "open_redirect": {
                            "open_redirect": external_redirect,
                            "location": (verify_meta or {}).get("location"),
                            "location_host": _hostname_of((verify_meta or {}).get("location")),
                        },
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
                    # Payload id for provenance
                    "payload_id": "ml-ffuf" if (origin == "ml" and not used_fallback) else "ffuf",
                }

                results.append(_post_normalize_row_for_ui(one))

                # optional: persist to your evidence sink (unified locations)
                if t.job_id:
                    try:
                        label = _guess_label(payload)
                        body_type = (t.meta or {}).get("body_type")
                        if body_type == "json":
                            locs = {"json": [t.param]}
                        elif body_type == "form":
                            locs = {"form": [t.param]}
                        else:
                            locs = {"query": [t.param]}
                        persist_evidence(
                            job_id=t.job_id,
                            method=t.method,
                            url=t.url,
                            param_locs=locs,
                            param=t.param,
                            family=label,
                            payload_id=("ml-ffuf" if (origin == "ml" and not used_fallback) else "ffuf"),
                            request_meta={"headers": eff_headers},
                            response_meta={"verify": verify_meta, "baseline": baseline_meta, "delta": delta},
                            signals={"external_redirect": external_redirect, "ffuf_match_count": len(matches)},
                            confidence=float(min(1.0, max(0.0, derived_conf))),
                            label=label,
                            ranker_meta=ranker_meta if not used_fallback else {},
                        )
                    except Exception:
                        logging.exception("persist_evidence failed")

            except Exception as e:
                logging.exception("ffuf run failed for %s %s", t.url, t.param)
                results.append(_post_normalize_row_for_ui({
                    "url": t.url,
                    "param": t.param,
                    "method": t.method,
                    "payload": payload,
                    "status": "error",
                    "stage": "ffuf",
                    "error": str(e),
                    "meta": t.meta,
                    "family": family,
                    "origin": "curated",
                }))
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
    # NOTE: builder expects raw token without the "Bearer " prefix
    raw_token = norm.split(" ", 1)[1] if norm else None
    targets_path = build_targets(eps, job_dir, bearer_token=raw_token)  # writes <job_dir>/targets.json
    evidence_path = run_fuzz(job_dir, targets_path, out_dir=job_dir / "results")
    rows = _read_evidence(evidence_path)

    # Best-effort normalization so UI always sees origin/ranker_meta/signals.verify
    normed: List[Dict[str, Any]] = []
    for r in rows:
        # Try to surface 'verify' if present in response_meta or nested signals
        verify = (
            (r.get("signals") or {}).get("verify")
            or (r.get("response_meta") or {}).get("verify")
            or r.get("verify")
        )
        if verify:
            r.setdefault("signals", {}).setdefault("verify", verify)
            r.setdefault("signals", {}).setdefault("open_redirect", {})
            r["signals"]["open_redirect"].setdefault("location", verify.get("location"))
            r["signals"]["open_redirect"].setdefault("location_host", _hostname_of(verify.get("location")))

        # ---- Canonicalize ML/ranker metadata so the UI can detect ML properly ----
        # Gather possible raw containers
        raw_rm: Dict[str, Any] = {}
        for k in ("ranker_meta", "ranker", "ml_meta"):
            if isinstance(r.get(k), dict):
                try:
                    # do not overwrite existing keys already present in raw_rm
                    for kk, vv in r[k].items():
                        raw_rm.setdefault(kk, vv)
                except Exception:
                    pass
        if isinstance(r.get("ml"), dict):
            ml = r["ml"]
            for k in ("ranker_meta", "ranker"):
                if isinstance(ml.get(k), dict):
                    for kk, vv in ml[k].items():
                        raw_rm.setdefault(kk, vv)

        # Collect probabilities (support many key names; prefer ranker_meta first)
        family_probs = None
        for container in (raw_rm, r):
            for alt in ("family_probs", "probs", "family_probabilities", "probabilities", "per_family", "ranker_probs", "ml_probs"):
                val = container.get(alt)
                if isinstance(val, dict) and val:
                    family_probs = dict(val)
                    break
            if family_probs:
                break

        if family_probs:
            # keep only the three we render; renormalize
            picked = {}
            for k, v in family_probs.items():
                try:
                    kl = str(k).lower()
                    if kl in {"sqli", "xss", "redirect"}:
                        picked[kl] = float(v)
                except Exception:
                    continue
            s = sum(picked.values())
            if s > 0:
                family_probs = {k: (v / s) for k, v in picked.items()}
            else:
                family_probs = picked

        # Score
        ranker_score = None
        for alt in ("ranker_score", "score", "rank_score"):
            val = raw_rm.get(alt, r.get(alt))
            if isinstance(val, (int, float)):
                ranker_score = float(val)
                break

        # Chosen family and models
        family_chosen = raw_rm.get("family_chosen") or r.get("family")
        model_ids = raw_rm.get("model_ids") or raw_rm.get("models") or r.get("model_ids") or r.get("models")

        # used_path: preserve existing ML path or stamp standard value if missing
        has_ml_fields = bool(family_probs) or isinstance(ranker_score, (int, float)) or (isinstance(model_ids, (list, tuple)) and len(model_ids) > 0)
        used_path = raw_rm.get("used_path")
        # CRITICAL: Preserve the original used_path from evidence - don't overwrite ML paths!
        if raw_rm.get("used_path") and raw_rm.get("used_path").startswith("ml:"):
            used_path = raw_rm.get("used_path")  # Keep "ml:redirect", "ml:sqli", etc.
        elif has_ml_fields and not used_path:
            used_path = "family_ranker"  # Only use fallback if no ML path exists

        # Persist canonicalized ranker_meta back if anything present
        canonical_rm: Dict[str, Any] = {}
        if family_probs:
            canonical_rm["family_probs"] = family_probs
        if family_chosen:
            canonical_rm["family_chosen"] = family_chosen
        if isinstance(ranker_score, (int, float)):
            canonical_rm["ranker_score"] = float(ranker_score)
        if model_ids:
            canonical_rm["model_ids"] = model_ids
        if used_path:
            canonical_rm["used_path"] = used_path
        if canonical_rm:
            r["ranker_meta"] = canonical_rm
        
        # Preserve the original ranker_used_path from evidence
        if r.get("ranker_used_path"):
            r["ranker_used_path"] = r["ranker_used_path"]

        # If there is an explicit origin/flag, keep it; else infer as ML if we have ML-ish fields
        if "origin" not in r:
            if has_ml_fields or r.get("is_ml") or isinstance(r.get("ml"), (dict, bool)) or (
                isinstance(r.get("payload_id"), str) and r["payload_id"].lower().startswith("ml-")
            ):
                r["origin"] = "ml"

        normed.append(_post_normalize_row_for_ui(r))

    return normed


# =========================
# API endpoints
# =========================
@router.post("/fuzz")
def fuzz_many(
    targets: List[FuzzTarget],
    reco: Optional[Recommender] = Depends(_init_reco),  # explicit load path
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
    reco: Optional[Recommender] = Depends(_init_reco),
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
        # Build legacy per-param targets from captured traffic (query-only fallback for ffuf simplicity)
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
            tmp_targets = [FuzzTarget(**t.dict()) for t in _filter_endpoints_by_selection([t.dict() for t in tmp_targets], payload.selection)]
        results_ffuf = _fuzz_targets_ffuf(
            tmp_targets,
            reco=reco,
            top_n=(payload.top_n if payload else 3),
            threshold=(payload.threshold if payload else 0.2),
            global_headers=global_headers,
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
