from dataclasses import dataclass
from typing import Optional, Dict, Any
import httpx, time, os
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode
from .targets import Target

# Configuration
SNIPPET_MAX = int(os.getenv("ELISE_RESP_SNIPPET_MAX", 16384))
HEADER_KEYS = {"server", "x-powered-by", "via", "content-type", "set-cookie", "x-aspnet-version", "x-runtime"}

def _filter_headers(hdrs) -> Dict[str, str]:
    """Filter response headers to only include relevant ones."""
    out = {}
    for k, v in hdrs.items():
        lk = k.lower()
        if lk in HEADER_KEYS:
            if lk == "set-cookie":
                # Store cookie names only
                names = []
                for part in (v if isinstance(v, list) else [v]):
                    # Cookie string like: NAME=VALUE; Path=/; HttpOnly
                    name = part.split(";", 1)[0].split("=", 1)[0].strip()
                    if name: 
                        names.append(name)
                out[lk] = ",".join(sorted(set(names)))
            else:
                out[lk] = str(v)[:512]
    return out

@dataclass
class InjectionResult:
    confirmed: bool
    why: list
    status: int
    response_snippet: str
    response_headers: Dict[str, str]
    response_len: int
    redirect_location: Optional[str]=None
    timing_ms: float=0.0
    # Schema/structure summaries for data-diff (generic, optional)
    is_json: bool = False
    json_top_keys: Optional[str] = None  # comma-joined sample of top-level keys
    json_is_array: bool = False
    html_tag_counts: Optional[Dict[str, int]] = None

def _summarize_response(text: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "is_json": False,
        "json_top_keys": None,
        "json_is_array": False,
        "html_tag_counts": None,
    }
    if not text:
        return out
    # Try JSON first
    try:
        import json
        obj = json.loads(text)
        out["is_json"] = True
        if isinstance(obj, dict):
            keys = list(obj.keys())[:15]
            out["json_top_keys"] = ",".join(sorted(str(k) for k in keys))
        elif isinstance(obj, list):
            out["json_is_array"] = True
            if obj and isinstance(obj[0], dict):
                keys = list(obj[0].keys())[:15]
                out["json_top_keys"] = ",".join(sorted(str(k) for k in keys))
        return out
    except Exception:
        pass
    # Lightweight HTML tag counts
    try:
        import re
        tags = ["a","table","tr","td","th","script","iframe","img","div","span"]
        counts = {}
        low = text.lower()
        for t in tags:
            counts[t] = len(re.findall(r"<\s*"+re.escape(t)+r"\b", low))
        out["html_tag_counts"] = counts
    except Exception:
        pass
    return out

def _should_disable_tls_verify(url: str) -> bool:
    """Decide whether to disable TLS verification for a given URL.

    Rules:
    - If env ELISE_TLS_INSECURE=1 or ELISE_HTTP_VERIFY_TLS in {"0","false"} -> disable
    - If host is localhost/127.0.0.1 and scheme is https -> disable (self-signed typical for labs)
    """
    try:
        if os.getenv("ELISE_TLS_INSECURE", "0") == "1":
            return True
        v = (os.getenv("ELISE_HTTP_VERIFY_TLS") or "").strip().lower()
        if v in {"0", "false", "no"}:
            return True
        p = urlparse(url)
        if (p.scheme or "").lower() == "https" and (p.hostname or "").lower() in {"localhost", "127.0.0.1"}:
            return True
    except Exception:
        pass
    return False


def inject_once(t: Target, family: str, payload: str) -> InjectionResult:
    params, data, json_body = t.build_with_payload(payload)
    headers = t.headers or {}
    # TLS verification policy
    verify_tls = not _should_disable_tls_verify(t.url)
    start = time.time()
    # For query params, override the value directly in the URL to avoid duplicate keys
    url = t.url
    if t.param_in == "query" and t.param:
        try:
            parts = list(urlparse(url))
            q = parse_qs(parts[4], keep_blank_values=True)
            q[t.param] = [payload]
            parts[4] = urlencode(q, doseq=True)
            url = urlunparse(parts)
            # Clear params to avoid adding duplicates
            params = {}
        except Exception:
            pass

    r = httpx.request(
        t.method.upper(),
        url,
        params=params,
        data=data,
        json=json_body,
        headers=headers,
        follow_redirects=False,
        timeout=10.0,
        verify=verify_tls,
    )
    dt = (time.time()-start)*1000
    text = r.text or ""
    why = []
    confirmed = False
    if family=="xss":
        if payload in text: confirmed=True; why.append("reflection")
    elif family=="sqli":
        low = text.lower()
        # Error-based confirmation only (generic)
        if any(tok in low for tok in ("sql syntax","sqlite error","warning: mysql","psql:","sql error","unrecognized token","syntax error","database error")):
            confirmed=True; why.append("sql_error")
    elif family=="redirect":
        loc = r.headers.get("location","")
        if 300<=r.status_code<400 and loc.startswith(("http://","https://")): confirmed=True; why.append("open_redirect")
    
    # Enhanced evidence collection
    response_len = len(text)
    response_snippet = text[:SNIPPET_MAX]
    response_headers = _filter_headers(r.headers)
    # Schema/structure summary
    summary = _summarize_response(text)
    
    return InjectionResult(
        confirmed=confirmed, 
        why=why, 
        status=r.status_code, 
        response_snippet=response_snippet,
        response_headers=response_headers,
        response_len=response_len,
        redirect_location=r.headers.get("location"), 
        timing_ms=dt,
        is_json=bool(summary.get("is_json")),
        json_top_keys=summary.get("json_top_keys"),
        json_is_array=bool(summary.get("json_is_array")),
        html_tag_counts=summary.get("html_tag_counts"),
    )
