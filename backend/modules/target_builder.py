# backend/modules/target_builder.py
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlunparse
from typing import List, Dict, Any, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[2]
JOBS_DIR = REPO_ROOT / "data" / "jobs"

# Noise filters
# IMPORTANT: do NOT include ".json" or ".txt" here; many APIs legitimately end with those.
STATIC_EXT = (
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".map", ".md"
)

# ---- optional ML prioritizer -------------------------------------------------
try:
    # tiny model that scores (method, url, param) -> [0..1]
    from ..modules.ml.param_prioritizer import ParamPrioritizer  # type: ignore
    _PP: Optional[ParamPrioritizer] = ParamPrioritizer()
    try:
        _PP.load()
    except Exception:
        _PP = None
except Exception:
    _PP = None
# -----------------------------------------------------------------------------

def _load_crawl(job_id: str) -> Dict[str, Any]:
    job_dir = JOBS_DIR / job_id
    f = job_dir / "crawl_result.json"
    if not f.exists():
        # fallback to old location for backwards-compat
        legacy = REPO_ROOT / "data" / "crawl_result.json"
        if legacy.exists():
            return json.loads(legacy.read_text(encoding="utf-8"))
        raise FileNotFoundError(f"crawl_result.json not found for job {job_id} at {f}")
    return json.loads(f.read_text(encoding="utf-8"))


def _pick_headers(h: Dict[str, str]) -> Dict[str, str]:
    """
    Keep only safe/useful headers for reproduction.
    - We DO NOT persist raw Cookie from capture (we synthesize from storage_state).
    - We DO keep Authorization (many APIs auth via bearer tokens).
    - We keep CSRF-ish headers if present.
    """
    keep_list = {
        "content-type",
        "accept",
        "referer",
        "user-agent",
        "x-requested-with",
        "authorization",
        "x-csrf-token",
        "x-xsrf-token",
        "x-request-id",
        "origin",
    }
    keep: Dict[str, str] = {}
    for k, v in (h or {}).items():
        if k and k.lower() in keep_list:
            keep[k] = v
    return keep


def _same_origin(url: str, base_host: str) -> bool:
    try:
        return base_host and (urlparse(url).netloc == base_host)
    except Exception:
        return False


def _skip_noise(url: str) -> bool:
    u = (url or "").lower()
    if "/socket.io/" in u:
        return True
    return any(u.endswith(ext) for ext in STATIC_EXT)


def _normalize_url_for_ffuf(url: str) -> str:
    # strip hash routes for ffuf
    return (url or "").split("#", 1)[0]


def _infer_base_host(blob: Dict[str, Any]) -> str:
    # Prefer explicit target saved by crawl route
    target = blob.get("target") or blob.get("target_url") or ""
    host = urlparse(target).netloc
    if host:
        return host
    # Fallback: first URL from captured/endpoints
    for coll in (blob.get("captured_requests") or []), (blob.get("endpoints") or []):
        for item in coll:
            u = item.get("url") or ""
            h = urlparse(u).netloc
            if h:
                return h
    return ""


def _cookie_header_from_storage(state_path: str, base_host: str) -> Dict[str, str]:
    """
    Build a Cookie header from Playwright storage_state.json limited to base_host scope.
    """
    try:
        if not state_path:
            return {}
        st = json.loads(Path(state_path).read_text(encoding="utf-8"))
        cookies = st.get("cookies", [])
        parts = []
        for c in cookies:
            dom = (c.get("domain") or "").lstrip(".")
            name = c.get("name")
            value = c.get("value")
            if not dom or name is None or value is None:
                continue
            # domain match: either cookie domain suffix matches host or vice versa
            if base_host.endswith(dom) or dom.endswith(base_host):
                parts.append(f"{name}={value}")
        return {"Cookie": "; ".join(parts)} if parts else {}
    except Exception:
        return {}


def _extract_seed_from_query(url: str, param: str) -> Optional[str]:
    try:
        qs = parse_qs(urlparse(url).query, keep_blank_values=True)
        vals = qs.get(param)
        if not vals:
            return None
        # keep the last seen value as seed (closer to "current" state)
        return vals[-1]
    except Exception:
        return None


def _extract_seed_from_body(body: Any, param: str) -> Optional[str]:
    try:
        if isinstance(body, dict):
            v = body.get(param)
            if v is None:
                return None
            return str(v)
        return None
    except Exception:
        return None


def _path_only(url: str) -> str:
    try:
        p = urlparse(url)
        return urlunparse((p.scheme, p.netloc, p.path, "", "", ""))
    except Exception:
        return url


def _shape_sig(method: str, url: str, param: str, body_type: Optional[str]) -> Tuple[str, str, str, str]:
    """
    Canonical signature for deduplication:
    (METHOD, scheme://host/path, param, body_type_or_query)
    """
    m = (method or "GET").upper()
    pathish = _path_only(_normalize_url_for_ffuf(url))
    bt = (body_type or "").lower() or "query"
    return (m, pathish, param, bt)


def _count_shapes(captured: List[Dict[str, Any]]) -> Dict[Tuple[str, str, str, str], int]:
    """
    Count how many times we saw each (method,path,param,loc) shape in captured traffic.
    Used to attach 'freq' to targets for prioritization/triage.
    """
    counts: Dict[Tuple[str, str, str, str], int] = {}
    for r in captured:
        url = r.get("url") or ""
        method = (r.get("method") or "GET").upper()
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
            continue
        if method == "GET" or method == "DELETE":
            qs = parse_qs(urlparse(url).query, keep_blank_values=True)
            for param in qs.keys():
                sig = _shape_sig(method if method != "DELETE" else "DELETE", url, param, None)
                counts[sig] = counts.get(sig, 0) + 1
        else:
            body_parsed = r.get("body_parsed")
            body_type = r.get("body_type")
            if isinstance(body_parsed, dict):
                for param in body_parsed.keys():
                    sig = _shape_sig(method, url, param, body_type)
                    counts[sig] = counts.get(sig, 0) + 1
    return counts


def _build_from_capture(
    captured: List[Dict[str, Any]],
    job_id: str,
    session_headers: Dict[str, str],
    counts: Dict[Tuple[str, str, str, str], int],
) -> List[Dict[str, Any]]:
    targets: List[Dict[str, Any]] = []
    seen_shapes: set[Tuple[str, str, str, str]] = set()

    for r in captured:
        url = r.get("url")
        if not url:
            continue
        method = (r.get("method") or "GET").upper()
        headers = {**session_headers, **_pick_headers(r.get("headers") or {})}
        body_type = r.get("body_type")
        body_parsed = r.get("body_parsed")

        if method in {"GET", "DELETE"}:
            qs = parse_qs(urlparse(url).query, keep_blank_values=True)
            for param in sorted(qs.keys()):
                seed_val = _extract_seed_from_query(url, param)
                sig = _shape_sig(method, url, param, None)
                if sig in seen_shapes:
                    continue
                seen_shapes.add(sig)
                targets.append({
                    "url": _normalize_url_for_ffuf(url),
                    "param": param,
                    "method": method,
                    "job_id": job_id,
                    "headers": headers,
                    "meta": {
                        "headers": headers,
                        "body": None,
                        "body_type": None,
                        "seed": {"value": seed_val},
                        "source": "captured",
                        "freq": counts.get(sig, 0),
                    }
                })

        elif method in {"POST", "PUT", "PATCH"}:
            if isinstance(body_parsed, dict):
                for param in sorted(body_parsed.keys()):
                    seed_val = _extract_seed_from_body(body_parsed, param)
                    sig = _shape_sig(method, url, param, body_type)
                    if sig in seen_shapes:
                        continue
                    seen_shapes.add(sig)
                    targets.append({
                        "url": _normalize_url_for_ffuf(url),
                        "param": param,
                        "method": method,
                        "job_id": job_id,
                        "headers": headers,
                        "meta": {
                            "headers": headers,
                            "body": body_parsed,
                            "body_type": body_type,
                            "seed": {"value": seed_val},
                            "source": "captured",
                            "freq": counts.get(sig, 0),
                        }
                    })
    return targets


def _add_priority_scores(targets: List[Dict[str, Any]]) -> None:
    """
    Attach 'priority' to each target using the ML prioritizer if available,
    else fallback to cheap heuristics. Frequency gives a small bump.
    """
    for t in targets:
        m = t.get("method") or "GET"
        u = t.get("url") or ""
        p = t.get("param") or ""
        freq = int(((t.get("meta") or {}).get("freq")) or 0)
        score = 0.0
        if _PP:
            try:
                score = float(_PP.predict_proba(m, u, p))
            except Exception:
                score = 0.0
        else:
            # weak heuristics when model missing
            lp = p.lower()
            lu = u.lower()
            if lp in {"id","uid","pid","productid","user","q","search","query","to","return_to","redirect","url"}:
                score += 0.6
            if any(x in lu for x in ("/login", "/auth", "/admin", "/search", "/redirect", "/report", "/download")):
                score += 0.2
            if (t.get("method") or "").upper() in {"GET", "DELETE"}:
                score += 0.1
        # small frequency bump (cap 0.3)
        score += min(0.3, 0.03 * max(0, freq))
        t["priority"] = float(min(1.0, score))


def build_fuzz_targets_for_job(job_id: str) -> List[Dict[str, Any]]:
    """
    Load data/jobs/<job_id>/crawl_result.json and turn captured requests into FuzzTarget dicts.

    Filters to same-origin and skips noisy endpoints (socket.io, static assets).
    Preference order:
      1) captured_requests (have real headers/body and seed values)
      2) endpoints (forms/links) as a fallback when capture missed them

    Adds a Cookie header synthesized from storage_state.json (if present) to enable authenticated fuzzing.

    Returns a list of dicts with keys:
      - url, param, method, job_id, headers
      - meta: { headers, body, body_type, seed: {value}, source: "captured"|"endpoints_fallback", freq: int }
      - priority: float in [0,1]
    """
    blob = _load_crawl(job_id)
    base_host = _infer_base_host(blob)
    session_headers = _cookie_header_from_storage(blob.get("session_state_path", ""), base_host)

    captured_all = blob.get("captured_requests") or []
    endpoints_all = blob.get("endpoints") or []

    # Filter captured to same-origin, non-static, non-socket.io
    captured = [
        r for r in captured_all
        if _same_origin(r.get("url", ""), base_host) and not _skip_noise(r.get("url", ""))
    ]

    # Count shapes to compute frequency
    counts = _count_shapes(captured)

    targets = _build_from_capture(captured, job_id, session_headers, counts)

    # Fallbacks from "endpoints" (DOM/heuristics) if capture missed them
    seen = {(t["method"], _path_only(t["url"]), t["param"], (t.get("meta") or {}).get("body_type") or "query") for t in targets}
    for ep in endpoints_all:
        url = ep.get("url") or ""
        if not _same_origin(url, base_host) or _skip_noise(url):
            continue
        method = (ep.get("method") or "GET").upper()

        # Prefer explicit param lists if present; else parse what's on the URL for GET.
        explicit_params = ep.get("params") if isinstance(ep.get("params"), list) else None
        explicit_body_keys = ep.get("body_keys") if isinstance(ep.get("body_keys"), list) else None
        body_type_hint = (ep.get("body_type") or "").lower() or None

        if method in {"GET", "DELETE"}:
            keys = explicit_params if explicit_params else list(parse_qs(urlparse(url).query, keep_blank_values=True).keys())
            for param in sorted(keys):
                sig = (method, _path_only(_normalize_url_for_ffuf(url)), param, "query")
                if sig in seen:
                    continue
                headers = session_headers.copy()
                targets.append({
                    "url": _normalize_url_for_ffuf(url),
                    "param": param,
                    "method": method,
                    "job_id": job_id,
                    "headers": headers,
                    "meta": {
                        "headers": headers,
                        "body": None,
                        "body_type": None,
                        "seed": {"value": None},
                        "source": "endpoints_fallback",
                        "freq": 0,
                    }
                })
                seen.add(sig)

        elif method in {"POST", "PUT", "PATCH"}:
            if explicit_body_keys:
                for param in sorted(explicit_body_keys):
                    sig = (method, _path_only(_normalize_url_for_ffuf(url)), param, body_type_hint or "json")
                    if sig in seen:
                        continue
                    headers = session_headers.copy()
                    targets.append({
                        "url": _normalize_url_for_ffuf(url),
                        "param": param,
                        "method": method,
                        "job_id": job_id,
                        "headers": headers,
                        "meta": {
                            "headers": headers,
                            "body": None,                 # unknown; fuzzer will add param=FUZZ
                            "body_type": body_type_hint,  # helps set Content-Type
                            "seed": {"value": None},
                            "source": "endpoints_fallback",
                            "freq": 0,
                        }
                    })
                    seen.add(sig)

    # Score and sort by priority (desc)
    _add_priority_scores(targets)
    targets.sort(key=lambda t: t.get("priority", 0.0), reverse=True)

    return targets
