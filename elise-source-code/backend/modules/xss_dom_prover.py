# backend/modules/xss_dom_prover.py
from __future__ import annotations

import hashlib
import json
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError


# =============================== helpers =====================================

def _sha1(s: str) -> str:
    return hashlib.sha1((s or "").encode("utf-8", "ignore")).hexdigest()


def _ensure_base(html: str, base_url: Optional[str]) -> str:
    """
    Insert <base href="..."> so relative URLs resolve correctly when we use set_content().
    If document already has a <base>, we do not add another. Minimal meddling to avoid side effects.
    """
    if not html:
        html = ""
    if not base_url:
        return html

    # Already has a base tag?
    if re.search(r"<\s*base\b", html, flags=re.I):
        return html

    has_html = re.search(r"<\s*html\b", html, flags=re.I)
    has_head = re.search(r"<\s*head\b", html, flags=re.I)

    base_tag = f'<base href="{base_url}">'
    if has_head:
        # inject right after <head ...>
        return re.sub(r"(<\s*head\b[^>]*>)", r"\1" + base_tag, html, count=1, flags=re.I)
    elif has_html:
        # add a <head> with base before first <body> or at start of <html>
        if re.search(r"<\s*body\b", html, flags=re.I):
            return re.sub(r"(<\s*html\b[^>]*>)", r"\1<head>" + base_tag + r"</head>", html, count=1, flags=re.I)
        else:
            return re.sub(r"(<\s*html\b[^>]*>)", r"\1<head>" + base_tag + r"</head>", html, count=1, flags=re.I)
    else:
        # bare fragment → wrap minimally
        return f"<!doctype html><html><head>{base_tag}</head><body>{html}</body></html>"


def _now_ms() -> int:
    return int(time.time() * 1000)


# =============================== core ========================================

INIT_HOOK = r"""
(() => {
  // A tiny instrumentation layer that shouts to the console with a stable prefix.
  // We intentionally keep this small, deterministic, and without external deps.
  const PREFIX = "XSS_PROOF|";
  function say(type, payload) {
    try {
      const msg = PREFIX + type + "|" + JSON.stringify(payload ?? {});
      // Using console.info so we don't interfere with app's console.error handlers
      console.info(msg);
    } catch (e) {
      try { console.info(PREFIX + type + "|{}"); } catch(_) {}
    }
  }

  // Dialogs
  const _alert = window.alert;
  const _confirm = window.confirm;
  const _prompt = window.prompt;
  window.alert = (msg) => { say("alert", { message: String(msg) }); /* do NOT call _alert to avoid blocking */ };
  window.confirm = (msg) => { say("confirm", { message: String(msg) }); return false; };
  window.prompt = (msg, defVal) => { say("prompt", { message: String(msg), default: String(defVal ?? "") }); return null; };

  // Dangerous evaluators
  const _eval = window.eval;
  window.eval = (code) => { try { say("eval", { code: String(code) }); } catch(_) {} return _eval(code); };

  const _Function = window.Function;
  window.Function = function(...args) { try { say("Function", { args }); } catch(_) {} return new _Function(...args); };

  const _setTimeout = window.setTimeout;
  window.setTimeout = function(handler, timeout, ...rest) {
    if (typeof handler === "string") { try { say("setTimeout#string", { code: handler, timeout }); } catch(_) {} }
    return _setTimeout(handler, timeout, ...rest);
  };
  const _setInterval = window.setInterval;
  window.setInterval = function(handler, timeout, ...rest) {
    if (typeof handler === "string") { try { say("setInterval#string", { code: handler, timeout }); } catch(_) {} }
    return _setInterval(handler, timeout, ...rest);
  };

  // document.write / writeln
  const _docWrite = document.write.bind(document);
  const _docWriteln = document.writeln.bind(document);
  document.write = function(...args) { try { say("document.write", { args }); } catch(_) {} return _docWrite(...args); };
  document.writeln = function(...args) { try { say("document.writeln", { args }); } catch(_) {} return _docWriteln(...args); };

  // javascript: URLs (href) are largely caught by navigation; we also detect inline-event attributes.
  // We'll rely on the runner to dispatch common events to elements with on* handlers.

  // Signal we are ready.
  say("init", { when: Date.now() });
})();
"""


def _collect_on_attr_names(js: str) -> List[str]:
    # Heuristic to extract event names like 'click' from 'onclick', 'onload', etc.
    # Caller already provides attribute names; this remains here for possible reuse.
    out = []
    for token in re.findall(r"\bon([a-z0-9_]+)\b", js or "", flags=re.I):
        out.append(token.lower())
    return out


def _simulate_common_events_script() -> str:
    """
    JS snippet: find elements with inline on* handlers and dispatch the corresponding events.
    Also dispatch a few generic events widely (click, mouseover, focus).
    """
    return r"""
(() => {
  const PREFIX = "XSS_PROOF|";
  const say = (type, payload) => {
    try { console.info(PREFIX + type + "|" + JSON.stringify(payload ?? {})); } catch(_) {}
  };

  const dispatch = (el, type) => {
    try {
      const ev = new Event(type, { bubbles: true, cancelable: true });
      el.dispatchEvent(ev);
      say("dispatched", { type, tag: el.tagName, id: el.id || null, class: el.className || null });
    } catch (e) {
      say("dispatch_error", { type, error: String(e) });
    }
  };

  // 1) Inline handlers: onclick, onmouseover, onerror, onload, onfocus, etc.
  const walker = document.createTreeWalker(document, NodeFilter.SHOW_ELEMENT);
  const candidates = [];
  while (walker.nextNode()) {
    const el = walker.currentNode;
    const attrs = el.attributes ? Array.from(el.attributes) : [];
    const onAttrs = attrs.filter(a => /^on[a-z]/i.test(a.name));
    if (onAttrs.length) {
      const events = onAttrs.map(a => a.name.toLowerCase().replace(/^on/, ""));
      candidates.push({ el, events });
    }
  }
  for (const {el, events} of candidates) {
    for (const t of events) dispatch(el, t);
  }

  // 2) Generic nudges on broad selectors
  const generic = Array.from(document.querySelectorAll("a, button, input, textarea, img, [role=button], [onclick], [onmouseover]"));
  for (const el of generic) {
    ["click", "mouseover", "focus"].forEach(t => dispatch(el, t));
  }

  // 3) Try error for images without actual network I/O manipulation (won't always work if already loaded).
  for (const img of Array.from(document.images || [])) {
    try { img.dispatchEvent(new Event("error", { bubbles: true })); } catch(_) {}
  }

  say("simulate_done", { when: Date.now() });
})();
    """.strip()


def _parse_proof_console(text: str) -> Optional[Tuple[str, Dict[str, Any]]]:
    """
    Extract (type, payload) from console lines emitted by INIT_HOOK or simulator.
    """
    if not text or not text.startswith("XSS_PROOF|"):
        return None
    try:
        _, rest = text.split("XSS_PROOF|", 1)
        type_, payload = rest.split("|", 1)
        data = json.loads(payload) if payload else {}
        if not isinstance(data, dict):
            data = {"payload": data}
        return type_, data
    except Exception:
        return None


# =============================== public API ==================================

def prove_dom_xss_from_html(
    html: str,
    *,
    base_url: Optional[str] = None,
    run_ms: int = 2500,
    simulate_events: bool = True,
    job_dir: Optional[str] = None,
    screenshot: bool = True,
    viewport: Tuple[int, int] = (1200, 800),
) -> Dict[str, Any]:
    """
    Load the provided HTML into a headless browser, instrument dangerous sinks,
    optionally dispatch common events, and report whether code executed.

    Returns:
      {
        "executed": bool,
        "signals": {... per-sink counts ...},
        "console_tokens": [...],
        "dialogs": [...],
        "errors": [...],
        "screenshot_path": str|None,
        "html_sha1": str,
        "started_at": ms,
        "ended_at": ms,
      }
    """
    started = _now_ms()
    html_sha = _sha1(html or "")
    console_tokens: List[Dict[str, Any]] = []
    dialogs: List[Dict[str, Any]] = []
    errors: List[str] = []

    # Aggregate counters for sinks
    counters = {
        "alert": 0,
        "confirm": 0,
        "prompt": 0,
        "eval": 0,
        "Function": 0,
        "setTimeout#string": 0,
        "setInterval#string": 0,
        "document.write": 0,
        "document.writeln": 0,
        "javascript_href": 0,   # may be surfaced via our dispatcher & console tokens
        "inline_handler_fired": 0,  # inferred from 'dispatched' tokens
    }

    html_to_load = _ensure_base(html or "", base_url)

    screenshot_path = None
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=["--disable-web-security"])
        context = browser.new_context(viewport={"width": viewport[0], "height": viewport[1]})
        page = context.new_page()

        # Hook dialogs (backup channel; our init script also reports them)
        def on_dialog(dlg):
            try:
                dialogs.append({"type": dlg.type, "message": dlg.message})
                dlg.dismiss()
            except Exception:
                pass

        page.on("dialog", on_dialog)

        # Collect our instrumented console tokens
        def on_console(msg):
            try:
                t = msg.text
            except Exception:
                return
            parsed = _parse_proof_console(t)
            if not parsed:
                return
            typ, payload = parsed
            console_tokens.append({"type": typ, "payload": payload})

            # Bump counters for selected types
            if typ in counters:
                counters[typ] += 1
            if typ == "dispatched":
                counters["inline_handler_fired"] += 1

        page.on("console", on_console)

        # Initialize hooks *before* any page content loads
        page.add_init_script(INIT_HOOK)

        try:
            # Use set_content to avoid navigating the network unless HTML pulls it in.
            page.set_content(html_to_load, wait_until="load", timeout=20000)
        except PlaywrightTimeoutError:
            errors.append("set_content_timeout")
        except Exception as e:
            errors.append(f"set_content_error:{e!r}")

        # Try to stimulate common inline handlers if requested
        if simulate_events:
            try:
                page.evaluate(_simulate_common_events_script())
            except PlaywrightTimeoutError:
                errors.append("simulate_timeout")
            except Exception as e:
                errors.append(f"simulate_error:{e!r}")

        # Let the page run for a short while to allow async handlers to fire
        try:
            page.wait_for_timeout(max(0, int(run_ms)))
        except Exception:
            pass

        # Evidence snapshot
        if screenshot and job_dir:
            try:
                Path(job_dir).mkdir(parents=True, exist_ok=True)
                sp = Path(job_dir) / f"xss_proof_{int(time.time())}.png"
                page.screenshot(path=str(sp), full_page=True)
                screenshot_path = str(sp)
            except Exception as e:
                errors.append(f"screenshot_error:{e!r}")

        try:
            context.close()
        except Exception:
            pass
        try:
            browser.close()
        except Exception:
            pass

    # Decide execution: any strong signal is enough
    executed = any([
        counters["alert"] > 0,
        counters["confirm"] > 0,
        counters["prompt"] > 0,
        counters["eval"] > 0,
        counters["Function"] > 0,
        counters["setTimeout#string"] > 0,
        counters["setInterval#string"] > 0,
        counters["document.write"] > 0 or counters["document.writeln"] > 0,
        counters["inline_handler_fired"] > 0,  # this implies inline JS ran when dispatched
        len(dialogs) > 0,
    ])

    ended = _now_ms()
    return {
        "executed": bool(executed),
        "signals": counters,
        "console_tokens": console_tokens,
        "dialogs": dialogs,
        "errors": errors,
        "screenshot_path": screenshot_path,
        "html_sha1": html_sha,
        "started_at": started,
        "ended_at": ended,
        "duration_ms": ended - started,
    }


def prove_dom_xss_from_url(
    url: str,
    *,
    run_ms: int = 2500,
    simulate_events: bool = True,
    job_dir: Optional[str] = None,
    screenshot: bool = True,
    viewport: Tuple[int, int] = (1200, 800),
    extra_headers: Optional[Dict[str, str]] = None,
    storage_state_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Navigate directly to a URL and observe whether DOM sinks are triggered.
    Useful for stored/DOM XSS that manifests on a routed page.

    Note: For reflected XSS where you already have the HTML body, prefer prove_dom_xss_from_html
    so you can add a <base> and avoid network noise. This method is great for
    authenticated or stateful views (set 'storage_state_path' for cookies/JWT).
    """
    started = _now_ms()
    console_tokens: List[Dict[str, Any]] = []
    dialogs: List[Dict[str, Any]] = []
    errors: List[str] = []
    counters = {
        "alert": 0, "confirm": 0, "prompt": 0,
        "eval": 0, "Function": 0,
        "setTimeout#string": 0, "setInterval#string": 0,
        "document.write": 0, "document.writeln": 0,
        "javascript_href": 0,
        "inline_handler_fired": 0,
    }
    screenshot_path = None

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=["--disable-web-security"])
        ctx_kwargs: Dict[str, Any] = {"viewport": {"width": viewport[0], "height": viewport[1]}}
        if storage_state_path:
            ctx_kwargs["storage_state"] = storage_state_path
        context = p.chromium.launch(headless=True).new_context(**ctx_kwargs)  # separate context from browser above for clarity
        page = context.new_page()

        if extra_headers:
            try:
                context.set_extra_http_headers(extra_headers)
            except Exception:
                pass

        def on_dialog(dlg):
            try:
                dialogs.append({"type": dlg.type, "message": dlg.message})
                dlg.dismiss()
            except Exception:
                pass

        page.on("dialog", on_dialog)

        def on_console(msg):
            try:
                t = msg.text
            except Exception:
                return
            parsed = _parse_proof_console(t)
            if not parsed:
                return
            typ, payload = parsed
            console_tokens.append({"type": typ, "payload": payload})
            if typ in counters:
                counters[typ] += 1
            if typ == "dispatched":
                counters["inline_handler_fired"] += 1

        page.on("console", on_console)
        page.add_init_script(INIT_HOOK)

        try:
            page.goto(url, wait_until="load", timeout=20000)
        except PlaywrightTimeoutError:
            errors.append("goto_timeout")
        except Exception as e:
            errors.append(f"goto_error:{e!r}")

        if simulate_events:
            try:
                page.evaluate(_simulate_common_events_script())
            except Exception as e:
                errors.append(f"simulate_error:{e!r}")

        try:
            page.wait_for_timeout(max(0, int(run_ms)))
        except Exception:
            pass

        if screenshot and job_dir:
            try:
                Path(job_dir).mkdir(parents=True, exist_ok=True)
                sp = Path(job_dir) / f"xss_proof_url_{int(time.time())}.png"
                page.screenshot(path=str(sp), full_page=True)
                screenshot_path = str(sp)
            except Exception as e:
                errors.append(f"screenshot_error:{e!r}")

        try:
            context.close()
        except Exception:
            pass
        try:
            browser.close()
        except Exception:
            pass

    executed = any([
        counters["alert"] > 0,
        counters["confirm"] > 0,
        counters["prompt"] > 0,
        counters["eval"] > 0,
        counters["Function"] > 0,
        counters["setTimeout#string"] > 0,
        counters["setInterval#string"] > 0,
        counters["document.write"] > 0 or counters["document.writeln"] > 0,
        counters["inline_handler_fired"] > 0,
        len(dialogs) > 0,
    ])
    ended = _now_ms()

    return {
        "executed": bool(executed),
        "signals": counters,
        "console_tokens": console_tokens,
        "dialogs": dialogs,
        "errors": errors,
        "screenshot_path": screenshot_path,
        "url": url,
        "started_at": started,
        "ended_at": ended,
        "duration_ms": ended - started,
    }
