import httpx
import os
from urllib.parse import urlparse
from dataclasses import dataclass
from typing import Optional

@dataclass
class RedirectProbe:
    influence: bool = False
    location: Optional[str] = None
    # Param information for UI display
    param_in: str = ""
    param: str = ""
    skipped: bool = False

def run_redirect_probe(url, method, param_in, param, headers=None, plan=None):
    # Defensive check: skip if redirect probes are disabled
    if plan and "redirect" in plan.probes_disabled:
        probe = RedirectProbe()
        probe.skipped = True
        return probe
    
    params={}; data=None; js=None
    external = "https://example.com/"
    if param_in=="query": params={param: external}
    elif param_in=="form": data={param: external}
    elif param_in=="json": js={param: external}
    def _tls_insecure(u: str) -> bool:
        try:
            if os.getenv("ELISE_TLS_INSECURE", "0") == "1":
                return True
            v = (os.getenv("ELISE_HTTP_VERIFY_TLS") or "").strip().lower()
            if v in {"0", "false", "no"}:
                return True
            p = urlparse(u)
            if (p.scheme or "").lower() == "https" and (p.hostname or "").lower() in {"localhost", "127.0.0.1"}:
                return True
        except Exception:
            pass
        return False

    r = httpx.request(
        method,
        url,
        params=params,
        data=data,
        json=js,
        headers=headers,
        timeout=8.0,
        follow_redirects=False,
        verify=not _tls_insecure(url),
    )
    loc = r.headers.get("location")
    if (300 <= r.status_code < 400) and loc and loc.startswith(("http://","https://")):
        return RedirectProbe(True, loc, param_in="header", param="location")
    return RedirectProbe()
