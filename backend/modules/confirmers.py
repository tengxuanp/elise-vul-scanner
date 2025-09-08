"""
Family-specific vulnerability confirmation oracles.
Determines which vulnerability family was actually triggered based on response signals.
"""

from __future__ import annotations
import os

# thresholds (env overrides)
TAU_SQLI = float(os.getenv("ELISE_TAU_SQLI", "0.50"))


def confirm_xss(signals: dict) -> tuple[bool, str | None]:
    """
    True when reflection is in a script-executable context.
    signals.xss_context ∈ {html, js, attr, js_string, html_body, url, css}
    """
    ctx = (signals or {}).get("xss_context")
    ok = ctx in {"html", "js", "attr", "js_string", "html_body", "url", "css"}
    return ok, ("xss_reflection" if ok else None)


def confirm_sqli(signals: dict) -> tuple[bool, str | None]:
    """
    True when DB error fingerprint OR timing oracle crosses threshold.
    Prefers error-based; falls back to boolean/timing delta.
    """
    s = signals or {}
    if s.get("sqli_error_based"):
        return True, "sqli_error"
    delta = s.get("sql_boolean_delta")
    if isinstance(delta, (int, float)) and delta >= TAU_SQLI:
        return True, "sqli_timing"
    return False, None


def confirm_redirect(signals: dict) -> tuple[bool, str | None]:
    """
    True when attacker-controlled host observed in Location or equivalent influence.
    """
    ok = (signals or {}).get("redirect_influence") is True
    return ok, ("redirect_location" if ok else None)


def oracle_from_signals(signals: dict) -> tuple[str | None, str | None]:
    """
    Returns (family, reason_code) in deterministic priority:
    SQLi > Redirect > XSS. This avoids mislabeling when multiple hints appear.
    """
    ok, rc = confirm_sqli(signals)
    if ok: 
        return "sqli", rc
    ok, rc = confirm_redirect(signals)
    if ok: 
        return "redirect", rc
    ok, rc = confirm_xss(signals)
    if ok: 
        return "xss", rc
    return None, None
