import httpx, time, re
from dataclasses import dataclass
from typing import Optional, Literal
from urllib.parse import urlencode, urlparse, parse_qsl, urlunparse

TIMEOUT = 6.0

DB_ERROR_PATTERNS = [
    (re.compile(rb"you have an error in your sql syntax|mysql_fetch|mysqli|near syntax", re.I), "mysql"),
    (re.compile(rb"unclosed quotation mark after the character string|sql server", re.I), "mssql"),
    (re.compile(rb"org\.postgresql|pg_query|syntax error at or near", re.I), "postgres"),
    (re.compile(rb"sqlite(error|3)|unrecognized token", re.I), "sqlite"),
    (re.compile(rb"ORA-\d{5}", re.I), "oracle"),
]

@dataclass
class SQLiTriage:
    error_based: bool
    error_db: Optional[str]
    boolean_delta: float  # relative body-size delta (0..1)
    time_based: bool
    time_delta_ms: float

def _inject_query(url: str, param: str, value: str) -> str:
    u = urlparse(url)
    q = dict(parse_qsl(u.query, keep_blank_values=True))
    q[param] = value
    new_q = urlencode(list(q.items()))
    return urlunparse((u.scheme, u.netloc, u.path, u.params, new_q, u.fragment))

def _do(client: httpx.Client, method: str, url: str, in_: str, param: str, value: str):
    if in_ == "query":
        u = _inject_query(url, param, value)
        return client.request(method, u)
    elif in_ == "form":
        return client.request(method, url, data={param: value}, headers={"Content-Type": "application/x-www-form-urlencoded"})
    elif in_ == "json":
        return client.request(method, url, json={param: value})
    else:
        return client.request(method, url)

def triage(url: str, method: str, in_: str, param: str) -> SQLiTriage:
    with httpx.Client(follow_redirects=True, timeout=TIMEOUT) as c:
        # Baseline
        r0 = _do(c, method, url, in_, param, "1")
        base_len = len(r0.content or b"")
        # Error-based
        r_err = _do(c, method, url, in_, param, "1'")  # cheap break
        body = r_err.content or b""
        error_based = False
        db = None
        for pat, vendor in DB_ERROR_PATTERNS:
            if pat.search(body):
                error_based = True
                db = vendor
                break
        # Boolean-based
        r_true = _do(c, method, url, in_, param, "1 AND 1=1")
        r_false = _do(c, method, url, in_, param, "1 AND 1=2")
        len_t = len(r_true.content or b"")
        len_f = len(r_false.content or b"")
        delta = 0.0
        if max(len_t, len_f, base_len) > 0:
            delta = abs(len_t - len_f) / max(len_t, len_f, base_len)
        # Time-based (single quick check)
        t0 = time.time()
        _ = _do(c, method, url, in_, param, "1")
        tN = time.time()
        base_ms = (tN - t0) * 1000.0
        t1 = time.time()
        _ = _do(c, method, url, in_, param, "1 AND SLEEP(2)")
        t2 = time.time()
        dt_ms = (t2 - t1) * 1000.0
        time_based = dt_ms - base_ms > 1500.0  # ~>1.5s slower
        return SQLiTriage(error_based, db, delta, time_based, max(0.0, dt_ms - base_ms))
