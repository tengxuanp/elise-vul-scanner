import httpx, time, re, html
from typing import Literal, Optional
from urllib.parse import urlencode, urlparse, parse_qsl, urlunparse

XSSContext = Literal["none", "html", "attr", "js_string"]
CANARY_KEY = "__ELISE__"
TIMEOUT = 6.0

ATTR_PAT = re.compile(rb'''[a-zA-Z-]+\s*=\s*("|')(?P<val>[^"']*__ELISE__[^"']*)\1''')
SCRIPT_BLOCK_PAT = re.compile(rb"<script\b[^>]*>(?P<body>.*?)</script>", re.I | re.S)

def _inject_query(url: str, param: str, value: str) -> str:
    u = urlparse(url)
    q = dict(parse_qsl(u.query, keep_blank_values=True))
    q[param] = value
    new_q = urlencode(list(q.items()))
    return urlunparse((u.scheme, u.netloc, u.path, u.params, new_q, u.fragment))

def classify_reflection(url: str, method: str, in_: str, param: str, session: Optional[httpx.Client] = None) -> XSSContext:
    value = f"{CANARY_KEY}{int(time.time()*1000)}"
    client = session or httpx.Client(follow_redirects=True, timeout=TIMEOUT)
    try:
        if in_ == "query":
            u = _inject_query(url, param, value)
            r = client.request(method, u)
        elif in_ == "form":
            r = client.request(method, url, data={param: value}, headers={"Content-Type": "application/x-www-form-urlencoded"})
        elif in_ == "json":
            r = client.request(method, url, json={param: value})
        else:
            return "none"
        body = r.content or b""
        if CANARY_KEY.encode() not in body:
            return "none"
        # JS-string context
        for m in SCRIPT_BLOCK_PAT.finditer(body):
            if CANARY_KEY.encode() in m.group("body"):
                # crude but safe: surrounding quotes near the canary
                if b'"' + CANARY_KEY.encode() in m.group("body") or b"'" + CANARY_KEY.encode() in m.group("body"):
                    return "js_string"
                return "js_string"  # conservative toward JS when inside script
        # Attribute context
        if ATTR_PAT.search(body):
            return "attr"
        # HTML text context otherwise
        return "html"
    finally:
        if session is None:
            client.close()
