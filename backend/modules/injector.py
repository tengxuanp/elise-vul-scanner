from dataclasses import dataclass
from typing import Optional, Dict
import httpx, time, os
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

def inject_once(t: Target, family: str, payload: str) -> InjectionResult:
    params, data, json_body = t.build_with_payload(payload)
    headers = t.headers or {}
    start = time.time()
    r = httpx.request(t.method.upper(), t.url, params=params, data=data, json=json_body, headers=headers, follow_redirects=False, timeout=10.0)
    dt = (time.time()-start)*1000
    text = r.text or ""
    why = []
    confirmed = False
    if family=="xss":
        if payload in text: confirmed=True; why.append("reflection")
    elif family=="sqli":
        low = text.lower()
        if any(tok in low for tok in ("sql syntax","sqlite error","warning: mysql","psql:")): confirmed=True; why.append("sql_error")
    elif family=="redirect":
        loc = r.headers.get("location","")
        if 300<=r.status_code<400 and loc.startswith(("http://","https://")): confirmed=True; why.append("open_redirect")
    
    # Enhanced evidence collection
    response_len = len(text)
    response_snippet = text[:SNIPPET_MAX]
    response_headers = _filter_headers(r.headers)
    
    return InjectionResult(
        confirmed=confirmed, 
        why=why, 
        status=r.status_code, 
        response_snippet=response_snippet,
        response_headers=response_headers,
        response_len=response_len,
        redirect_location=r.headers.get("location"), 
        timing_ms=dt
    )