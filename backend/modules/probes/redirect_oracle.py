import httpx
from dataclasses import dataclass

@dataclass
class RedirectProbe:
    influence: bool = False
    location: str | None = None

def run_redirect_probe(url, method, param_in, param, headers=None):
    params={}; data=None; js=None
    external = "https://example.com/"
    if param_in=="query": params={param: external}
    elif param_in=="form": data={param: external}
    elif param_in=="json": js={param: external}
    r = httpx.request(method, url, params=params, data=data, json=js, headers=headers, timeout=8.0, follow_redirects=False)
    loc = r.headers.get("location")
    if (300 <= r.status_code < 400) and loc and loc.startswith(("http://","https://")):
        return RedirectProbe(True, loc)
    return RedirectProbe()