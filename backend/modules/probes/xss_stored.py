import httpx, time, uuid, re
from typing import Optional, Tuple

TIMEOUT = 6.0

def prove_stored_xss(create_url: str, list_url: str, field: str = "note") -> Tuple[bool, str]:
    token = f"__ELISE_STORED__{uuid.uuid4().hex}"
    with httpx.Client(follow_redirects=True, timeout=TIMEOUT) as c:
        # Hop 1: submit benign HTML with canary
        c.post(create_url, data={field: token})
        # Hop 2: read listing
        r = c.get(list_url)
        body = r.text or ""
        hit = token in body
        return hit, token
