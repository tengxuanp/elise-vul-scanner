# backend/modules/playwright_crawler.py
from __future__ import annotations

from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional

import json
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
from urllib.parse import urljoin, urlparse, parse_qs

STATIC_EXTENSIONS = (
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".ico", ".woff", ".woff2", ".ttf", ".map", ".json", ".txt"
)

SENSITIVE_HEADERS = {"authorization", "cookie", "x-api-key", "x-auth-token", "set-cookie"}


def is_static_resource(url: str) -> bool:
    return url.lower().endswith(STATIC_EXTENSIONS)


def scrub_headers(h: Dict[str, str]) -> Dict[str, str]:
    out = {}
    for k, v in (h or {}).items():
        out[k] = "***redacted***" if k.lower() in SENSITIVE_HEADERS else v
    return out


def parse_body(headers: Dict[str, str], post_data: Optional[str]) -> Dict[str, Any]:
    """
    Returns: {"type": "json"|"form"|"other"|None, "parsed": dict|None, "raw": str|None}
    """
    ct = ""
    for k, v in (headers or {}).items():
        if k.lower() == "content-type":
            ct = (v or "").lower()
            break

    if not post_data:
        return {"type": None, "parsed": None, "raw": None}

    if "application/json" in ct:
        try:
            return {"type": "json", "parsed": json.loads(post_data), "raw": post_data}
        except Exception:
            return {"type": "json", "parsed": None, "raw": post_data}

    if "application/x-www-form-urlencoded" in ct or "form" in ct:
        try:
            # parse_qs returns {k: [v,...]}
            parsed = {k: (v[0] if isinstance(v, list) and v else v) for k, v in parse_qs(post_data).items()}
        except Exception:
            parsed = None
        return {"type": "form", "parsed": parsed, "raw": post_data}

    return {"type": "other", "parsed": None, "raw": post_data}


def crawl_site(
    target_url: str,
    max_depth: int = 2,
    auth: Optional[Dict[str, str]] = None,
    job_dir: Optional[str] = None,
):
    """
    Returns:
      - raw_endpoints: [{"url", "method", "params": [...], "is_login": bool, "csrf_params": [...]}]
      - captured_requests: [{"method","url","headers","post_data","body_type","body_parsed","query_params":[...]}]
    """
    visited: set[Tuple[str, Tuple[str, ...]]] = set()
    raw_endpoints: List[Dict[str, Any]] = []
    captured_requests: List[Dict[str, Any]] = []

    def normalize_url(url: str) -> Tuple[str, Tuple[str, ...]]:
        parsed = urlparse(url)
        params = sorted(parse_qs(parsed.query).keys())
        return parsed.path, tuple(params)

    def dedupe_endpoints(endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen = set()
        unique = []
        for ep in endpoints:
            if not ep.get("url"):
                continue
            parsed = urlparse(ep["url"])
            key = (
                ep.get("method", "GET").upper(),
                parsed.path,
                tuple(sorted(ep.get("params") or [])),
                bool(ep.get("is_login")),
            )
            if key not in seen:
                seen.add(key)
                unique.append(ep)
        return unique

    def dedupe_requests(reqs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Deduplicate by method + path + query param keys + body shape (type+keys).
        We intentionally ignore header values to avoid exploding the key space.
        """
        seen = set()
        unique = []
        for r in reqs:
            url = r.get("url", "")
            parsed = urlparse(url)
            q_keys = tuple(sorted((r.get("query_params") or [])))
            body_type = r.get("body_type")
            body_keys: Tuple[str, ...] = ()
            if isinstance(r.get("body_parsed"), dict):
                body_keys = tuple(sorted(r["body_parsed"].keys()))
            key = (r.get("method", "GET").upper(), parsed.path, q_keys, body_type, body_keys)
            if key not in seen:
                seen.add(key)
                unique.append(r)
        return unique

    def crawl(url: str, depth: int, context):
        if depth > max_depth or normalize_url(url) in visited:
            return
        visited.add(normalize_url(url))
        page = context.new_page()

        def capture_request(request):
            try:
                if is_static_resource(request.url):
                    return
                req_headers = dict(request.headers)
                post_data = request.post_data
                body_info = parse_body(req_headers, post_data)
                q_params = sorted(parse_qs(urlparse(request.url).query).keys())

                captured_requests.append({
                    "method": request.method,
                    "url": request.url,
                    "headers": scrub_headers(req_headers),  # safe to persist
                    "post_data": body_info["raw"],
                    "body_type": body_info["type"],         # "json" | "form" | "other" | None
                    "body_parsed": body_info["parsed"],     # dict for json/form; else None
                    "query_params": q_params,
                })
            except Exception as e:
                print(f"[WARN] capture_request error for {request.url}: {e}")

        page.on("request", capture_request)

        try:
            page.goto(url, timeout=15000, wait_until="networkidle")
            html = page.content()
            soup = BeautifulSoup(html, "html.parser")

            # === Capture form endpoints (potential POSTs) ===
            for form in soup.find_all("form"):
                action = form.get("action") or url
                method = (form.get("method") or "GET").upper()
                full_action_url = urljoin(url, action)
                if is_static_resource(full_action_url):
                    continue

                inputs = form.find_all("input")
                form_params = [i.get("name") for i in inputs if i.get("name")]

                # Heuristics: login form detection
                login_keywords = {"user", "username", "email", "pass", "password", "login"}
                is_login = False
                for inp in inputs:
                    name = (inp.get("name") or "").lower()
                    itype = (inp.get("type") or "").lower()
                    if itype == "password" or any(k in name for k in login_keywords):
                        is_login = True
                        break

                # Heuristics: CSRF tokens (hidden inputs)
                csrf_params = []
                for inp in inputs:
                    name = (inp.get("name") or "").lower()
                    itype = (inp.get("type") or "").lower()
                    if itype == "hidden" and any(k in name for k in ("csrf", "token", "authenticity", "_csrf", "__requestverificationtoken")):
                        csrf_params.append(inp.get("name"))

                raw_endpoints.append({
                    "url": full_action_url,
                    "method": method,
                    "params": [p for p in form_params if p],  # keep all param names
                    "is_login": is_login,
                    "csrf_params": csrf_params
                })

            # === Capture <a href> navigations & recurse ===
            for link in soup.find_all("a", href=True):
                href = link["href"]
                full_url = urljoin(url, href)

                if is_static_resource(full_url):
                    continue

                # SPA hash routes like http://host/#/login
                if href.startswith("#/") or full_url.split("#", 1)[-1].startswith("/"):
                    try:
                        page.goto(full_url, timeout=15000, wait_until="networkidle")
                        sub_html = page.content()
                        sub_soup = BeautifulSoup(sub_html, "html.parser")
                        inputs = sub_soup.find_all("input")
                        param_names = [inp.get("name") for inp in inputs if inp.get("name")]

                        raw_endpoints.append({
                            "url": full_url,
                            "method": "GET",
                            "params": [p for p in param_names if p],
                            "is_login": False,
                            "csrf_params": []
                        })
                    except Exception as e:
                        print(f"[WARN] Could not load client-side route {full_url}: {e}")

                # Same-origin links; enqueue crawl and register endpoint
                elif urlparse(full_url).netloc == urlparse(target_url).netloc:
                    get_params = list(parse_qs(urlparse(full_url).query).keys())
                    raw_endpoints.append({
                        "url": full_url,
                        "method": "GET",
                        "params": get_params or [],
                        "is_login": False,
                        "csrf_params": []
                    })
                    crawl(full_url, depth + 1, context)

        except PlaywrightTimeoutError:
            print(f"[TIMEOUT] {url}")
        except Exception as e:
            print(f"[ERROR] Failed to crawl {url}: {e}")
        finally:
            try:
                page.close()
            except Exception:
                pass

    # --- Playwright bootstrap (with optional auth) ---
    headful = bool(auth and auth.get("mode") == "manual")
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=not headful)
        context = browser.new_context()

        # Optional auth bootstrap
        if auth and auth.get("mode", "none") != "none":
            mode = auth.get("mode")
            try:
                if mode == "cookie" and auth.get("cookie"):
                    u = urlparse(target_url)
                    pairs = []
                    for kv in (auth["cookie"] or "").split(";"):
                        kv = kv.strip()
                        if "=" in kv:
                            name, val = kv.split("=", 1)
                            pairs.append({"name": name, "value": val, "domain": u.hostname, "path": "/"})
                    if pairs:
                        context.add_cookies(pairs)

                elif mode == "bearer" and auth.get("bearer_token"):
                    context.set_extra_http_headers({"Authorization": f"Bearer {auth['bearer_token']}"})

                elif mode in ("form", "manual"):
                    lp = context.new_page()
                    try:
                        lp.goto(auth.get("login_url") or f"{target_url}/#/login", timeout=15000, wait_until="domcontentloaded")
                        if mode == "form":
                            # Best-effort selectors; user can override via crawl request
                            lp.fill(auth.get("username_selector", "input[type=email], #email, input[name=email]"), auth.get("username", ""))
                            lp.fill(auth.get("password_selector", "input[type=password], #password, input[name=password]"), auth.get("password", ""))
                            lp.click(auth.get("submit_selector", "button[type=submit], button#loginButton"))
                        # manual: user interacts in headful window (if available); fall back to wait
                        wait_ms = int(auth.get("wait_after_ms", 1500))
                        lp.wait_for_timeout(wait_ms)
                    finally:
                        try:
                            lp.close()
                        except Exception:
                            pass
            except Exception as e:
                print(f"[WARN] Auth bootstrap failed: {e}")

        try:
            crawl(target_url, 0, context)
        finally:
            # Persist storage state for this job (optional, used by target builder)
            try:
                if job_dir:
                    state_path = Path(job_dir) / "storage_state.json"
                    state_path.parent.mkdir(parents=True, exist_ok=True)
                    context.storage_state(path=str(state_path))
            except Exception:
                pass
            try:
                browser.close()
            except Exception:
                pass

    return (
        dedupe_endpoints(raw_endpoints),
        dedupe_requests(captured_requests)
    )
