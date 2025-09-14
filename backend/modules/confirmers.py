"""
Family-specific vulnerability confirmation oracles.
Determines which vulnerability family was actually triggered based on response signals.
"""

from __future__ import annotations
import os
from typing import Optional

# thresholds (env overrides)
TAU_SQLI = float(os.getenv("ELISE_TAU_SQLI", "0.15"))


def confirm_xss(signals: dict) -> tuple[bool, Optional[str]]:
    """
    True when reflection is in a script-executable context.
    signals.xss_context ∈ {html, js, attr, js_string, html_body, url, css}
    """
    ctx = (signals or {}).get("xss_context")
    ok = ctx in {"html", "js", "attr", "js_string", "html_body", "url", "css"}
    return ok, ("xss_reflection" if ok else None)


def confirm_sqli(signals: dict) -> tuple[bool, Optional[str]]:
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


def confirm_redirect(signals: dict) -> tuple[bool, Optional[str]]:
    """
    True when attacker-controlled host observed in Location or equivalent influence.
    """
    ok = (signals or {}).get("redirect_influence") is True
    return ok, ("redirect_location" if ok else None)


def oracle_from_signals(signals: dict) -> tuple[Optional[str], Optional[str]]:
    """
    Returns (family, reason_code) with improved logic to avoid mislabeling.
    Instead of rigid priority, use signal strength to determine the most likely family.
    """
    print(f"ORACLE_DEBUG signals={signals}")
    
    # Check all families
    sqli_ok, sqli_rc = confirm_sqli(signals)
    redirect_ok, redirect_rc = confirm_redirect(signals)
    xss_ok, xss_rc = confirm_xss(signals)
    
    print(f"ORACLE_DEBUG sqli_ok={sqli_ok} redirect_ok={redirect_ok} xss_ok={xss_ok}")
    
    # If only one family is confirmed, return it
    confirmed_families = []
    if sqli_ok:
        confirmed_families.append(("sqli", sqli_rc))
    if redirect_ok:
        confirmed_families.append(("redirect", redirect_rc))
    if xss_ok:
        confirmed_families.append(("xss", xss_rc))
    
    if len(confirmed_families) == 1:
        return confirmed_families[0]
    elif len(confirmed_families) == 0:
        return None, None
    
    # Multiple families confirmed - use signal strength to decide
    # For now, prefer XSS over SQLi when both are present (common case for XSS in HTML contexts)
    # This fixes the bug where XSS targets were being misclassified as SQLi
    if xss_ok and sqli_ok:
        # Check if SQLi has strong error-based signals
        if signals.get("sqli_error_based"):
            return "sqli", sqli_rc  # Strong SQLi signal
        else:
            return "xss", xss_rc    # Prefer XSS for weak SQLi signals
    
    # Original priority for other cases: SQLi > Redirect > XSS
    if sqli_ok:
        return "sqli", sqli_rc
    if redirect_ok:
        return "redirect", redirect_rc
    if xss_ok:
        return "xss", xss_rc
    
    return None, None
