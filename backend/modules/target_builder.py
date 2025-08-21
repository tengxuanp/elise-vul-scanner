# backend/modules/target_builder.py
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse, parse_qs
from typing import List, Dict, Any

REPO_ROOT = Path(__file__).resolve().parents[2]
JOBS_DIR = REPO_ROOT / "data" / "jobs"

# Noise filters
STATIC_EXT = (
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".map", ".json", ".txt", ".md"
)


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
    """Keep only safe/useful headers. We don't persist cookies/tokens by design."""
    keep = {}
    for k, v in (h or {}).items():
        kl = k.lower()
        if kl in ("content-type", "accept", "referer", "user-agent", "x-requested-with"):
            keep[k] = v
    return keep


def _same_origin(url: str, base_host: str) -> bool:
    try:
        return urlparse(url).netloc == base_host
    except Exception:
        return False


def _skip_noise(url: str) -> bool:
    u = (url or "").lower()
    if "/socket.io/" in u:
        return True
    if u.endswith(STATIC_EXT):
        return True
    return False


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


def _build_from_capture(
    captured: List[Dict[str, Any]],
    job_id: str,
    session_headers: Dict[str, str],
) -> List[Dict[str, Any]]:
    targets: List[Dict[str, Any]] = []
    for r in captured:
        url = r.get("url")
        if not url:
            continue
        method = (r.get("method") or "GET").upper()
        headers = {**session_headers, **_pick_headers(r.get("headers") or {})}
        body_type = r.get("body_type")
        body_parsed = r.get("body_parsed")

        if method == "GET":
            qs = parse_qs(urlparse(url).query)
            for param in sorted(qs.keys()):
                targets.append({
                    "url": _normalize_url_for_ffuf(url),
                    "param": param,
                    "method": "GET",
                    "job_id": job_id,
                    "headers": headers,
                    "meta": {
                        "headers": headers,
                        "body": None,
                        "body_type": None
                    }
                })

        elif method in {"POST", "PUT", "PATCH"}:
            # Only fuzz if we know the body keys
            if isinstance(body_parsed, dict):
                for param in sorted(body_parsed.keys()):
                    targets.append({
                        "url": _normalize_url_for_ffuf(url),
                        "param": param,
                        "method": method,
                        "job_id": job_id,
                        "headers": headers,
                        "meta": {
                            "headers": headers,
                            "body": body_parsed,
                            "body_type": body_type
                        }
                    })
    return targets


def build_fuzz_targets_for_job(job_id: str) -> List[Dict[str, Any]]:
    """
    Load data/jobs/<job_id>/crawl_result.json and turn captured requests into FuzzTarget dicts.
    Filters to same-origin and skips noisy endpoints (socket.io, static assets).
    Preference order:
      1) captured_requests (have real headers/body)
      2) endpoints (forms/links) as a fallback for GET-only pages
    Adds a Cookie header synthesized from storage_state.json (if present) to enable authenticated fuzzing.
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

    targets = _build_from_capture(captured, job_id, session_headers)

    # Fallback: GET endpoints that weren't seen in capture (same-origin + non-noise)
    seen = {(t["method"], t["url"], t["param"]) for t in targets}
    for ep in endpoints_all:
        url = ep.get("url") or ""
        method = (ep.get("method") or "GET").upper()
        if method != "GET":
            continue
        if not _same_origin(url, base_host) or _skip_noise(url):
            continue
        qs_keys = parse_qs(urlparse(url).query).keys()
        for param in sorted(qs_keys):
            key = (method, _normalize_url_for_ffuf(url), param)
            if key in seen:
                continue
            targets.append({
                "url": _normalize_url_for_ffuf(url),
                "param": param,
                "method": "GET",
                "job_id": job_id,
                "headers": session_headers.copy(),
                "meta": {"headers": session_headers.copy(), "body": None, "body_type": None}
            })
            seen.add(key)

    return targets
