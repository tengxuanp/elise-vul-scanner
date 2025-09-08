from dataclasses import dataclass
from typing import Optional
import httpx, time
from .targets import Target

@dataclass
class InjectionResult:
    confirmed: bool
    why: list
    status: int
    response_snippet: str
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
    snippet = text[:2048]
    return InjectionResult(confirmed, why, r.status_code, snippet, r.headers.get("location"), dt)