# backend/routes/verify_routes.py
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Dict, Any, Optional, Tuple
from urllib.parse import urlencode, urlparse, urlunparse, parse_qsl, parse_qs

import httpx
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Evidence

router = APIRouter()

# --------------------------- helpers -----------------------------------------

def _inject_query(url: str, key: str, val: str) -> str:
    u = urlparse(url)
    q = parse_qsl(u.query, keep_blank_values=True)
    # replace or add
    q = [(k, v) for (k, v) in q if k != key] + [(key, val)]
    return urlunparse((u.scheme, u.netloc, u.path, u.params, urlencode(q), u.fragment))

def _apply_payload_to_request(
    in_loc: str,
    method: str,
    url: str,
    headers: Dict[str, str],
    body: Optional[str],
    param: str,
    payload: str
) -> Tuple[str, Dict[str, str], Optional[bytes]]:
    """
    Build a concrete request (url, headers, body_bytes) with `payload`
    applied at the target param in either query or body (json/form).
    """
    method = (method or "GET").upper()
    headers = dict(headers or {})
    body_bytes: Optional[bytes] = None

    if (in_loc or "").lower() == "query":
        url = _inject_query(url, param, payload)
        if method == "GET":
            return url, headers, None
        # For non-GET with query injection, pass original body through unchanged
        if isinstance(body, str):
            body_bytes = body.encode("utf-8")
        elif isinstance(body, (bytes, bytearray)):
            body_bytes = bytes(body)
        else:
            body_bytes = None
        return url, headers, body_bytes

    # body injection path
    ctype = (headers.get("Content-Type") or headers.get("content-type") or "").split(";")[0].strip().lower()

    if ctype == "application/json":
        try:
            src = {}
            if body:
                src = json.loads(body) if isinstance(body, str) else json.loads(body.decode("utf-8", "ignore"))
            if not isinstance(src, dict):
                src = {}
        except Exception:
            src = {}
        src[param] = payload
        body_bytes = json.dumps(src).encode("utf-8")
        headers["Content-Type"] = "application/json"
        return url, headers, body_bytes

    # default: x-www-form-urlencoded
    try:
        parsed = parse_qs(body or "", keep_blank_values=True) if isinstance(body, str) else {}
    except Exception:
        parsed = {}
    parsed[param] = [payload]
    from urllib.parse import urlencode as _ue
    body_str = _ue([(k, v) for k, vs in parsed.items() for v in (vs if isinstance(vs, list) else [vs])])
    body_bytes = body_str.encode("utf-8")
    headers["Content-Type"] = "application/x-www-form-urlencoded"
    return url, headers, body_bytes

def _origin_host(url: str) -> str:
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return ""

def _read_payload(request_meta: Dict[str, Any], ev: Evidence) -> str:
    """
    Prefer in-memory payload fields. Fall back to payload_path file.
    """
    for key in ("payload",):
        v = request_meta.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    # try Evidence top-level, if your ORM keeps it
    try:
        v = getattr(ev, "payload", None)
        if isinstance(v, str) and v.strip():
            return v.strip()
    except Exception:
        pass
    # last resort: file
    p = request_meta.get("payload_path")
    if not p:
        raise ValueError("missing payload in request_meta (no 'payload' or 'payload_path')")
    return Path(p).read_text(encoding="utf-8").strip()

def _verify_reflection(resp_text: str, payload: str) -> bool:
    return (payload or "") in (resp_text or "")

def _verify_timing(client: httpx.Client, method: str, url: str, param: str, slow_payload: str) -> Dict[str, Any]:
    # baseline
    fast_url = _inject_query(url, param, "baseline")
    t0 = time.perf_counter()
    r0 = client.request(method, fast_url, timeout=10)
    t1 = time.perf_counter()
    # slow
    slow_url = _inject_query(url, param, slow_payload)
    t2 = time.perf_counter()
    r1 = client.request(method, slow_url, timeout=25)
    t3 = time.perf_counter()

    base_ms = int((t1 - t0) * 1000)
    slow_ms = int((t3 - t2) * 1000)
    return {
        "baseline_ms": base_ms,
        "slow_ms": slow_ms,
        "delta_ms": slow_ms - base_ms,
        "baseline_status": r0.status_code,
        "slow_status": r1.status_code,
    }

def _login_success_oracle(resp: httpx.Response) -> Dict[str, Any]:
    ok = False
    reason = []
    token_present = False
    try:
        if "application/json" in (resp.headers.get("content-type","").lower()):
            j = resp.json()
        else:
            j = {}
    except Exception:
        j = {}
    if isinstance(j, dict):
        if "authentication" in j and isinstance(j["authentication"], dict) and "token" in j["authentication"]:
            token_present = True
        elif "token" in j:
            token_present = True
    if token_present:
        ok = True; reason.append("json_token")
    if any(h.lower()=="set-cookie" for h in resp.headers.keys()):
        ok = True; reason.append("set_cookie")
    return {"login_success": ok, "reasons": reason, "token_present": token_present}

def _boolean_pair(payload_true: str) -> Tuple[str, str]:
    """
    Produce a 'true'/'false' boolean-based pair from a truthy payload,
    best-effort. This is heuristic but works well in practice.
    """
    pt = payload_true
    # simple normalizations
    variants = [
        ("'1'='1", "'1'='2"),
        ("\"1\"=\"1\"", "\"1\"=\"2\""),
        ("=1=1", "=1=2"),
    ]
    for a, b in variants:
        if a in pt:
            return pt, pt.replace(a, b, 1)
    # default injection style
    return "' OR '1'='1' -- ", "' OR '1'='2' -- "

# --------------------------- route -------------------------------------------

@router.post("/verify/{evidence_id}")
def verify_evidence(evidence_id: int, db: Session = Depends(get_db)):
    ev: Optional[Evidence] = db.query(Evidence).filter(Evidence.id == evidence_id).first()
    if not ev:
        raise HTTPException(404, "evidence not found")

    req = ev.request_meta or {}
    resp_meta = ev.response_meta or {}
    method = (req.get("method") or "GET").upper()
    url = req.get("url")
    param = req.get("param")
    headers = dict(req.get("headers") or {})
    body = req.get("body")
    if not url or not param:
        raise HTTPException(400, "evidence missing url/param in request_meta")

    # try to learn injection location & ctype
    in_loc = getattr(ev, "in_", None) or getattr(ev, "in", None) or "query"
    ctype = (req.get("headers", {}).get("Content-Type") or req.get("headers", {}).get("content-type") or ev.content_type or "").lower()

    try:
        payload = _read_payload(req, ev)
    except Exception as e:
        raise HTTPException(400, f"cannot read payload: {e}")

    verdict = {"confirmed": False, "reason": "unknown"}
    details: Dict[str, Any] = {}

    label = getattr(ev, "label", None) or (ev.signals or {}).get("label")  # be permissive
    signals = ev.signals or {}

    # Prepare mutated request for verification
    mut_url, mut_headers, mut_body = _apply_payload_to_request(in_loc, method, url, headers, body, param, payload)

    # 1) OPEN REDIRECT VERIFICATION
    # If label hints or signals show redirect, check Location with follow_redirects=False
    origin = _origin_host(url)
    if label == "open_redirect" or (signals.get("open_redirect") or {}).get("open_redirect"):
        with httpx.Client(follow_redirects=False, headers=mut_headers) as client:
            r = client.request(method, mut_url, content=mut_body, timeout=10)
            loc = r.headers.get("location") or r.headers.get("Location")
            host = urlparse(loc).netloc.lower() if loc else ""
            is_redir = r.status_code in (301,302,303,307,308)
            external = bool(host and host != origin)
            verdict["confirmed"] = bool(loc and is_redir and external)
            verdict["reason"] = "external_location_header" if verdict["confirmed"] else "no_external_location"
            details = {
                "status": r.status_code,
                "location": loc,
                "location_host": host,
                "origin_host": origin,
            }

    # 2) LOGIN BYPASS VERIFICATION (JSON/form login)
    elif label in ("login_bypass","sqli_login") or (signals.get("login") or {}).get("login_success"):
        with httpx.Client(follow_redirects=True, headers=mut_headers) as client:
            r = client.request(method, mut_url, content=mut_body, timeout=15)
            login = _login_success_oracle(r)
            verdict["confirmed"] = bool(login["login_success"])
            verdict["reason"] = ",".join(login["reasons"]) if verdict["confirmed"] else "no_login_token_or_cookie"
            details = {"status": r.status_code, **login}

    # 3) XSS VERIFICATION (prefer browser dialog; fallback to reflection)
    elif label == "xss":
        # Try Playwright; if not available, fallback to reflection-only
        try:
            from playwright.sync_api import sync_playwright  # type: ignore
            saw = {"dialog": False}
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                ctx = browser.new_context()
                page = ctx.new_page()
                page.on("dialog", lambda d: (saw.__setitem__("dialog", True), d.dismiss()))
                if method == "GET" and (in_loc or "").lower() == "query":
                    page.goto(mut_url, wait_until="domcontentloaded", timeout=15000)
                else:
                    # Fallback: naive GET verify if we cannot replay POST in-browser here
                    page.goto(mut_url if method == "GET" else url, wait_until="domcontentloaded", timeout=15000)
                # small dwell to let JS execute
                page.wait_for_timeout(800)
                browser.close()
            verdict["confirmed"] = saw["dialog"]
            verdict["reason"] = "dialog_fired" if saw["dialog"] else "no_dialog"
            details = {"dialog": saw["dialog"], "method": method, "in": in_loc}
        except Exception:
            # Fallback: HTTP reflection only
            with httpx.Client(follow_redirects=True, headers=mut_headers) as client:
                r = client.request(method, mut_url, content=mut_body, timeout=10)
                body_txt = r.text or ""
                reflected = _verify_reflection(body_txt, payload)
                verdict["confirmed"] = bool(reflected and r.status_code < 500)
                verdict["reason"] = "payload_reflected" if reflected else "not_reflected"
                details = {"status": r.status_code, "body_len": len(body_txt)}

    # 4) GENERIC SQLi VERIFICATION (boolean pair or timing)
    elif label == "sqli" or (signals.get("sql_error") is True):
        # Try boolean-based confirmation first (works on login/search)
        p_true, p_false = _boolean_pair(payload)
        url_t, headers_t, body_t = _apply_payload_to_request(in_loc, method, url, headers, body, param, p_true)
        url_f, headers_f, body_f = _apply_payload_to_request(in_loc, method, url, headers, body, param, p_false)
        with httpx.Client(follow_redirects=True) as client:
            r_t = client.request(method, url_t, headers=headers_t, content=body_t, timeout=15)
            r_f = client.request(method, url_f, headers=headers_f, content=body_f, timeout=15)
        # Heuristic: 200 vs 401/403 or meaningful len diff
        len_t = len(r_t.text or "")
        len_f = len(r_f.text or "")
        delta_len = abs(len_t - len_f)
        ok_pair = (r_t.status_code != r_f.status_code) or (delta_len >= 200)
        if ok_pair and r_t.status_code < 500:
            verdict["confirmed"] = True
            verdict["reason"] = "boolean_diff"
            details = {
                "true_status": r_t.status_code, "false_status": r_f.status_code,
                "len_true": len_t, "len_false": len_f, "len_delta": delta_len
            }
        else:
            # Fallback timing (only for query params where we can trivial-inject)
            slow_payload = payload if "waitfor delay" in payload.lower() else "';WAITFOR DELAY '0:0:3'--"
            if (in_loc or "").lower() == "query":
                with httpx.Client(follow_redirects=True) as client:
                    stats = _verify_timing(client, method, url, param, slow_payload)
                verdict["confirmed"] = stats["delta_ms"] >= 1500 and stats["slow_status"] < 500
                verdict["reason"] = "timing_delta" if verdict["confirmed"] else "no_timing_signal"
                details = stats
            else:
                verdict["confirmed"] = False
                verdict["reason"] = "no_boolean_or_timing_signal"

    else:
        verdict["reason"] = f"unhandled_label_{label or 'unknown'}"

    # write back into signals and bump confidence on confirm
    signals["verify"] = {"label": label, "verdict": verdict, "details": details}
    ev.signals = signals
    if verdict["confirmed"]:
        # strong confirmations deserve a bigger bump
        bump = 0.95 if label in ("open_redirect","login_bypass","sqli","xss") else 0.8
        ev.confidence = max(ev.confidence or 0.0, bump)
    db.commit()

    return {
        "evidence_id": ev.id,
        "label": label,
        "confidence": ev.confidence,
        "verdict": verdict,
        "details": details,
        "artifact": resp_meta.get("output_file"),
        "request_url": mut_url,
    }
