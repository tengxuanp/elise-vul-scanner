from __future__ import annotations

"""
DOM-based XSS probe using Playwright.
Generic, JS-aware probe that injects a canary payload into a page URL and
observes execution via dialog hooks and window overrides.
"""

from dataclasses import dataclass
from typing import Optional, List, Dict
import os
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError

CANARY = "EliseDomXSS123"


@dataclass
class DomXssResult:
    executed: bool = False
    dialogs: int = 0
    messages: List[str] = None
    url_used: str = ""
    payload_used: str = ""


def _set_query(url: str, param: str, value: str) -> str:
    """Set or replace a query parameter in a standard URL (no fragment)."""
    parts = list(urlparse(url))
    qs = parse_qs(parts[4], keep_blank_values=True)
    qs[param] = [value]
    parts[4] = urlencode(qs, doseq=True)
    return urlunparse(parts)


def _set_hash_query(url: str, param: str, value: str) -> str:
    """Set or replace a query parameter inside a hash fragment (e.g., /#/route?q=)."""
    parts = list(urlparse(url))
    frag = parts[5] or ""
    # Split fragment into path + ?query
    if "?" in frag:
        fpath, fqs = frag.split("?", 1)
    else:
        fpath, fqs = frag, ""
    fdict = parse_qs(fqs, keep_blank_values=True)
    fdict[param] = [value]
    new_fqs = urlencode(fdict, doseq=True)
    parts[5] = fpath + ("?" + new_fqs if new_fqs else "")
    return urlunparse(parts)


def _inject_param_into_url_for_dom(base_url: str, param: str, value: str) -> str:
    if "#" in base_url:
        return _set_hash_query(base_url, param, value)
    return _set_query(base_url, param, value)


def run_xss_probe_dom(
    base_url: str,
    param_in: str,
    param: str,
    spa_view_url: Optional[str] = None,
    timeout_ms: int = 6000,
) -> DomXssResult:
    """
    Perform a DOM XSS probe by loading a page in a headless browser with an
    injected canary payload and observing execution.

    Returns DomXssResult with execution indicators.
    """
    if not param or param_in not in {"query", "form", "json"}:
        return DomXssResult(executed=False, dialogs=0, messages=[], url_used="", payload_used="")

    # Choose the page URL: prefer SPA view when provided
    page_url = spa_view_url or base_url

    # Minimal, generic canary payloads for DOM contexts
    payloads = [
        f"javascript:alert('{CANARY}')",
        f"\"'><svg onload=alert('{CANARY}')>",
        f"\"'><img src=x onerror=alert('{CANARY}')>",
        f"<iframe src=javascript:alert('{CANARY}')>",
    ]

    # Only query injection is supported for DOM probe (form/json require app-specific flows)
    if param_in != "query":
        return DomXssResult(executed=False, dialogs=0, messages=[], url_used=page_url, payload_used="")

    enable = os.getenv("ELISE_ENABLE_DOM_XSS", "1") == "1"
    if not enable:
        return DomXssResult(executed=False, dialogs=0, messages=[], url_used=page_url, payload_used="")

    # Browser session
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(ignore_https_errors=True)
        # Install dialog/message hooks early
        context.add_init_script(
            """
            window.__eliseCanaryMsgs = [];
            const _a = window.alert; const _c = window.confirm; const _p = window.prompt;
            window.alert = (m)=>{ try { window.__eliseCanaryMsgs.push(String(m)); } catch(e){} return undefined; };
            window.confirm = (m)=>{ try { window.__eliseCanaryMsgs.push(String(m)); } catch(e){} return false; };
            window.prompt = (m)=>{ try { window.__eliseCanaryMsgs.push(String(m)); } catch(e){} return null; };
            """
        )

        page = context.new_page()
        dialog_msgs: List[str] = []
        page.on("dialog", lambda d: (dialog_msgs.append(d.message), d.dismiss()))

        executed = False
        used_url = page_url
        used_payload = ""

        for pl in payloads:
            test_url = _inject_param_into_url_for_dom(page_url, param, pl)
            try:
                page.goto(test_url, wait_until="domcontentloaded", timeout=timeout_ms)
            except PlaywrightTimeoutError:
                # try to proceed anyway
                pass
            # Best-effort settle
            try:
                page.wait_for_load_state("networkidle", timeout=1200)
            except PlaywrightTimeoutError:
                pass
            # Try generic SPA interactions to reveal search fields and submit
            try:
                # Open search UI if hidden behind a toggle/icon
                toggle = page.query_selector('button[aria-label*="search" i], button[aria-label*="open" i], [role=button] mat-icon[svgicon="search"]')
                if toggle and toggle.is_visible():
                    toggle.click()
                    page.wait_for_timeout(150)
            except Exception:
                pass
            try:
                # Fill typical search inputs and submit
                search = page.query_selector('input[aria-label="Search"], input[placeholder*="search" i], input[name="q"], input#searchQuery')
                if search and search.is_visible():
                    search.click()
                    search.fill(pl)
                    page.keyboard.press('Enter')
                    try:
                        page.wait_for_load_state('networkidle', timeout=1200)
                    except PlaywrightTimeoutError:
                        pass
                    page.wait_for_timeout(150)
            except Exception:
                pass
            # Collect messages
            try:
                msgs = page.evaluate("window.__eliseCanaryMsgs || []") or []
            except Exception:
                msgs = []

            all_msgs = dialog_msgs + list(msgs)
            if any(CANARY in str(m) for m in all_msgs):
                executed = True
                used_url = test_url
                used_payload = pl
                break

        browser.close()

        return DomXssResult(
            executed=executed,
            dialogs=len(dialog_msgs),
            messages=list(set(dialog_msgs)),
            url_used=used_url,
            payload_used=used_payload,
        )
