import httpx, time
from dataclasses import dataclass

ERR_TOKENS = ("sql syntax", "sqlite error", "warning: mysql", "psql:", "unterminated", "odbc")

@dataclass
class SqliProbe:
    error_based: bool = False
    time_based: bool = False
    boolean_delta: float = 0.0

def run_sqli_probe(url, method, param_in, param, headers=None) -> SqliProbe:
    probe = SqliProbe()
    def send(val):
        params={}; data=None; js=None
        if param_in=="query": params={param: val}
        elif param_in=="form": data={param: val}
        elif param_in=="json": js={param: val}
        return httpx.request(method, url, params=params, data=data, json=js, headers=headers, timeout=8.0)
    # error-based
    r = send("'")
    low = (r.text or "").lower()
    if any(tok in low for tok in ERR_TOKENS): probe.error_based=True
    # boolean quick check
    a = send("1")
    b = send("1 AND 1=2")
    if a.status_code == b.status_code:
        lena, lenb = len(a.text or ""), len(b.text or "")
        if lena: probe.boolean_delta = max(0.0, min(1.0, abs(lena - lenb) / lena))
    # crude time-based
    t0=time.time(); send("1 OR SLEEP(2)"); dt = time.time()-t0
    if dt > 1.9: probe.time_based=True
    return probe