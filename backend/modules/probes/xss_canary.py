import httpx
from dataclasses import dataclass

CANARY = "EliseXSSCanary123"

@dataclass
class XssProbe:
    context: str = "none"  # none|html|attr|js_string
    reflected: bool = False

def run_xss_probe(url: str, method: str, param_in: str, param: str, headers=None):
    params = {}; data=None; js=None
    if param_in=="query": params={param: CANARY}
    elif param_in=="form": data={param: CANARY}
    elif param_in=="json": js={param: CANARY}
    r = httpx.request(method, url, params=params, data=data, json=js, headers=headers, timeout=8.0, follow_redirects=True)
    text = r.text or ""
    ctx = "none"
    if CANARY in text:
        # poor-man context: detect quotes or tags around reflection
        i = text.find(CANARY)
        window = text[max(0,i-16):i+len(CANARY)+16]
        if "<" in window and ">" in window: ctx="html"
        elif '"' in window or "'" in window: ctx="attr"
        elif "</script>" in text[: max(0,i+64)]: ctx="js_string"
        return XssProbe(ctx, True)
    return XssProbe()