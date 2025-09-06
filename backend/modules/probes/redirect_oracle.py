import httpx, time, uuid
from typing import Optional, Tuple
from urllib.parse import urlencode, urlparse, parse_qsl, urlunparse

TIMEOUT = 6.0

def _inject(url: str, param: str, value: str) -> str:
    u = urlparse(url)
    q = dict(parse_qsl(u.query, keep_blank_values=True))
    q[param] = value
    new_q = urlencode(list(q.items()))
    return urlunparse((u.scheme, u.netloc, u.path, u.params, new_q, u.fragment))

def proves_open_redirect(url: str, method: str, param: str) -> Tuple[bool, int, Optional[str]]:
    token = str(uuid.uuid4())
    # Use an obviously foreign absolute URL carrying a unique token
    evil = f"https://elise.invalid/{token}"
    u = _inject(url, param, evil)
    with httpx.Client(follow_redirects=False, timeout=TIMEOUT) as c:
        r = c.request(method, u)
    loc = r.headers.get("location")
    status = r.status_code
    if status in range(300, 400) and loc and token in loc:
        return True, status, loc
    return False, status, loc
