# backend/modules/playwright_crawler.py
from __future__ import annotations

from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional, Set

import json
import re
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
from urllib.parse import urljoin, urlparse, parse_qs

# === Heuristics / constants ===
# IMPORTANT: do NOT block ".json" or ".txt" — many APIs legitimately end with those.
STATIC_EXTENSIONS = (
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".ico", ".woff", ".woff2", ".ttf", ".map"
)
SENSITIVE_HEADERS = {"authorization", "cookie", "x-api-key", "x-auth-token", "set-cookie"}
LOGIN_KEYWORDS = {"user", "username", "email", "pass", "password", "login"}
CSRF_KEYS = ("csrf", "token", "authenticity", "_csrf", "__requestverificationtoken")
HASH_ROUTE_RE = re.compile(r".*#/\S*")


def is_static_resource(url: str) -> bool:
    try:
        path = urlparse(url).path.lower()
        return any(path.endswith(ext) for ext in STATIC_EXTENSIONS)
    except Exception:
        return False


def same_origin(a: str, b: str) -> bool:
    try:
        ua, ub = urlparse(a), urlparse(b)
        return (ua.scheme, ua.hostname, ua.port or default_port(ua.scheme)) == (
            ub.scheme, ub.hostname, ub.port or default_port(ub.scheme)
        )
    except Exception:
        return False


def default_port(scheme: Optional[str]) -> int:
    return 443 if (scheme or "").lower() == "https" else 80


def scrub_headers(h: Dict[str, str]) -> Dict[str, str]:
    out = {}
    for k, v in (h or {}).items():
        out[k] = "***redacted***" if k.lower() in SENSITIVE_HEADERS else v
    return out


def parse_query(url: str) -> List[str]:
    try:
        return sorted(parse_qs(urlparse(url).query).keys())
    except Exception:
        return []


def parse_body(headers: Dict[str, str], post_data: Optional[str]) -> Dict[str, Any]:
    """
    Returns: {"type": "json"|"form"|"other"|None, "parsed": dict|None, "raw": str|None, "keys":[...]}
    """
    ct = ""
    for k, v in (headers or {}).items():
        if k.lower() == "content-type":
            ct = (v or "").lower()
            break

    if not post_data:
        return {"type": None, "parsed": None, "raw": None, "keys": []}

    if "application/json" in ct:
        try:
            parsed = json.loads(post_data)
            keys = sorted(parsed.keys()) if isinstance(parsed, dict) else []
            return {"type": "json", "parsed": parsed if isinstance(parsed, dict) else None, "raw": post_data, "keys": keys}
        except Exception:
            return {"type": "json", "parsed": None, "raw": post_data, "keys": []}

    if "application/x-www-form-urlencoded" in ct or "form" in ct:
        try:
            # parse_qs returns {k: [v,...]}
            parsed_qs = parse_qs(post_data)
            parsed = {k: (v[0] if isinstance(v, list) and v else v) for k, v in parsed_qs.items()}
            return {"type": "form", "parsed": parsed, "raw": post_data, "keys": sorted(parsed.keys())}
        except Exception:
            return {"type": "form", "parsed": None, "raw": post_data, "keys": []}

    return {"type": "other", "parsed": None, "raw": post_data, "keys": []}


def endpoint_shape(method: str, url: str, query_keys: List[str], body_keys: List[str]) -> Tuple[str, str, Tuple[str, ...], Tuple[str, ...]]:
    p = urlparse(url).path
    return (method.upper(), p, tuple(sorted(query_keys)), tuple(sorted(body_keys)))


def build_param_locs(query_keys: List[str], body_keys: List[str]) -> Dict[str, List[str]]:
    return {"query": sorted(query_keys or []), "body": sorted(body_keys or []), "header": [], "cookie": []}


def form_is_login(inputs: List[Any]) -> bool:
    for inp in inputs:
        name = (inp.get("name") or "").lower()
        itype = (inp.get("type") or "").lower()
        if itype == "password" or any(k in name for k in LOGIN_KEYWORDS):
            return True
    return False


def form_csrf_params(inputs: List[Any]) -> List[str]:
    out = []
    for inp in inputs:
        name = (inp.get("name") or "").lower()
        itype = (inp.get("type") or "").lower()
        if itype == "hidden" and any(k in name for k in CSRF_KEYS):
            real = inp.get("name")
            if real:
                out.append(real)
    return out


def crawl_site(
    target_url: str,
    max_depth: int = 2,
    auth: Optional[Dict[str, str]] = None,
    job_dir: Optional[str] = None,
    max_pages: int = 200,
):
    """
    Crawl a target and return:
      - endpoints: merged, deduplicated canonical endpoints with method, param_locs, etc.
      - captured_requests: deduped network requests with redacted headers and parsed bodies

    endpoints item shape:
      {
        "url": str,                       # absolute
        "method": "GET"|"POST"|...,
        "path": str,                      # URL path
        "query_keys": [...],              # canonical (sorted)
        "body_keys": [...],               # canonical (sorted)
        "param_locs": {"query":[...], "body":[...], "header":[], "cookie":[]},
        "content_type": "application/json"|"application/x-www-form-urlencoded"|None,
        "is_login": bool,
        "csrf_params": [...],
        "source": "form"|"network"|"merged",
        "form_template": [{"name":..., "example":""}, ...],   # if known
        "body_template": {k: example_value, ...}               # if known (json/form)
      }
    captured_requests item shape:
      {
        "method","url","headers","post_data","body_type","body_parsed","query_params"
      }
    """
    # === State ===
    visited: Set[Tuple[str, Tuple[str, ...]]] = set()
    page_budget = [0]  # mutable counter
    raw_form_endpoints: List[Dict[str, Any]] = []
    captured_requests: List[Dict[str, Any]] = []

    def normalize_url(url: str) -> Tuple[str, Tuple[str, ...]]:
        parsed = urlparse(url)
        params = sorted(parse_qs(parsed.query).keys())
        return parsed.path, tuple(params)

    def dedupe_requests(reqs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Deduplicate by method + path + query param keys + body shape (type+keys).
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

    def endpoints_from_requests(reqs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        out = []
        for r in reqs:
            url = r.get("url") or ""
            # NOISE CUT: same-origin and no socket.io
            if not same_origin(url, target_url):
                continue
            if "/socket.io/" in urlparse(url).path:
                continue

            method = (r.get("method") or "GET").upper()
            q_keys = r.get("query_params") or []
            b_type = r.get("body_type")
            parsed_body = r.get("body_parsed") if isinstance(r.get("body_parsed"), dict) else None
            body_keys = sorted((parsed_body or {}).keys()) if parsed_body else []

            content_type = None
            if b_type == "json":
                content_type = "application/json"
            elif b_type == "form":
                content_type = "application/x-www-form-urlencoded"

            ep = {
                "url": url,
                "method": method,
                "path": urlparse(url).path,
                "query_keys": sorted(q_keys),
                "body_keys": body_keys,
                "param_locs": build_param_locs(q_keys, body_keys),
                "content_type": content_type,
                "is_login": False,
                "csrf_params": [],
                "source": "network",
                "form_template": [{"name": k, "example": ""} for k in (parsed_body or {}).keys()] if b_type == "form" else [],
                "body_template": parsed_body if b_type == "json" else {},
            }
            out.append(ep)
        return out

    def endpoints_from_forms(forms: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        out = []
        for f in forms:
            url = f["url"]
            # NOISE CUT: same-origin and no socket.io
            if not same_origin(url, target_url):
                continue
            if "/socket.io/" in urlparse(url).path:
                continue

            method = f["method"]
            body_keys = sorted(f.get("params") or [])
            # Guess content type: respect enctype if present, else default to form-urlencoded for POST
            content_type = f.get("enctype") or ("application/x-www-form-urlencoded" if method == "POST" else None)
            ep = {
                "url": url,
                "method": method,
                "path": urlparse(url).path,
                "query_keys": [],  # form-derived endpoints don't imply query keys
                "body_keys": body_keys if method != "GET" else [],  # don't invent GET body keys
                "param_locs": build_param_locs([], body_keys if method != "GET" else []),
                "content_type": content_type,
                "is_login": bool(f.get("is_login", False)),
                "csrf_params": f.get("csrf_params") or [],
                "source": "form",
                "form_template": [{"name": k, "example": ""} for k in body_keys] if method != "GET" else [],
                "body_template": {},
            }
            out.append(ep)
        return out

    def merge_endpoints(form_eps: List[Dict[str, Any]], req_eps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Merge on canonical shape; prefer network-derived info for content_type/body_template.
        If both exist, mark source as 'merged' and carry union of csrf/is_login flags.
        """
        index: Dict[Tuple[str, str, Tuple[str, ...], Tuple[str, ...]], Dict[str, Any]] = {}

        def upsert(ep: Dict[str, Any]):
            key = endpoint_shape(ep["method"], ep["url"], ep["query_keys"], ep["body_keys"])
            if key not in index:
                index[key] = ep.copy()
                return
            cur = index[key]
            # Merge flags and templates
            cur["is_login"] = cur.get("is_login", False) or ep.get("is_login", False)
            cur["csrf_params"] = sorted(set((cur.get("csrf_params") or []) + (ep.get("csrf_params") or [])))
            # Prefer richer content_type/template from network
            if cur.get("source") == "form" and ep.get("source") == "network":
                cur["content_type"] = ep.get("content_type")
                cur["body_template"] = ep.get("body_template") or {}
                cur["form_template"] = ep.get("form_template") or cur.get("form_template") or []
                cur["source"] = "merged"
            elif cur.get("source") == "network" and ep.get("source") == "form":
                # keep network content_type, but add csrf/is_login hints
                cur["source"] = "merged"
            index[key] = cur

        for e in form_eps:
            upsert(e)
        for e in req_eps:
            upsert(e)

        # Ensure param_locs consistent with final keys
        final = []
        for ep in index.values():
            ep["param_locs"] = build_param_locs(ep.get("query_keys") or [], ep.get("body_keys") or [])
            final.append(ep)
        # Stable sort: network/merged first, then form-only
        final.sort(key=lambda x: (0 if x["source"] != "form" else 1, x["method"], x["path"]))
        return final

    def capture_request(request):
        try:
            url = request.url
            # NOISE CUT: static, cross-origin, socket.io
            if is_static_resource(url):
                return
            if not same_origin(url, target_url):
                return
            if "/socket.io/" in urlparse(url).path:
                return

            req_headers = dict(request.headers)
            post_data = request.post_data
            body_info = parse_body(req_headers, post_data)
            q_params = parse_query(url)

            captured_requests.append({
                "method": request.method,
                "url": url,
                "headers": scrub_headers(req_headers),  # safe to persist
                "post_data": body_info["raw"],
                "body_type": body_info["type"],         # "json" | "form" | "other" | None
                "body_parsed": body_info["parsed"],     # dict for json/form; else None
                "query_params": q_params,
            })
        except Exception as e:
            print(f"[WARN] capture_request error for {getattr(request, 'url', 'unknown')}: {e}")

    def capture_forms_on_page(html: str, base_url: str):
        soup = BeautifulSoup(html, "html.parser")
        for form in soup.find_all("form"):
            action = (form.get("action") or "").strip() or base_url
            method = (form.get("method") or "GET").upper()
            full_action_url = urljoin(base_url, action)

            # NOISE CUT: static, cross-origin, socket.io
            if is_static_resource(full_action_url):
                continue
            if not same_origin(full_action_url, target_url):
                continue
            if "/socket.io/" in urlparse(full_action_url).path:
                continue

            inputs = list(form.find_all(["input", "textarea", "select"]))
            form_params = [i.get("name") for i in inputs if i.get("name")]
            enctype = (form.get("enctype") or "").lower() or None

            raw_form_endpoints.append({
                "url": full_action_url,
                "method": method,
                "params": [p for p in form_params if p],
                "is_login": form_is_login(inputs),
                "csrf_params": form_csrf_params(inputs),
                "enctype": enctype
            })

    def crawl(url: str, depth: int, context):
        if depth > max_depth:
            return
        norm = normalize_url(url)
        if norm in visited:
            return
        if page_budget[0] >= max_pages:
            return

        visited.add(norm)
        page_budget[0] += 1
        page = context.new_page()
        page.on("request", capture_request)

        try:
            # First load
            page.goto(url, timeout=20000, wait_until="networkidle")
            # Wake the page a bit to trigger lazy XHRs
            try:
                page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                page.wait_for_timeout(250)
            except Exception:
                pass

            html = page.content()
            capture_forms_on_page(html, url)

            soup = BeautifulSoup(html, "html.parser")
            # Handle SPA hash routes: navigate and re-capture forms
            for a in soup.find_all("a", href=True):
                href = a["href"].strip()
                if href.startswith("javascript:"):
                    continue
                full_url = urljoin(url, href)

                # NOISE CUT
                if is_static_resource(full_url):
                    continue

                # Hash-based SPA route (e.g., http://host/#/login)
                if HASH_ROUTE_RE.match(full_url) and same_origin(full_url, target_url):
                    try:
                        page.goto(full_url, timeout=15000, wait_until="networkidle")
                        # small wake after route change
                        try:
                            page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                            page.wait_for_timeout(200)
                        except Exception:
                            pass
                        sub_html = page.content()
                        capture_forms_on_page(sub_html, full_url)
                    except Exception as e:
                        print(f"[WARN] SPA route load failed {full_url}: {e}")

                # Same-origin regular links: record GET endpoint & recurse
                if same_origin(full_url, target_url):
                    # skip socket.io links entirely
                    if "/socket.io/" in urlparse(full_url).path:
                        continue
                    # Record GET endpoint truthfully (query keys only)
                    raw_form_endpoints.append({
                        "url": full_url,
                        "method": "GET",
                        "params": [],  # do not invent body params for GET
                        "is_login": False,
                        "csrf_params": [],
                        "enctype": None
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
                        lp.goto(auth.get("login_url") or target_url, timeout=20000, wait_until="domcontentloaded")
                        if mode == "form":
                            # Best-effort selectors; user can override via crawl request
                            if auth.get("username_selector"):
                                lp.fill(auth["username_selector"], auth.get("username", ""))
                            else:
                                # fallback multi-selector attempt
                                for sel in ["input[type=email]", "#email", "input[name=email]", "input[name=username]"]:
                                    try:
                                        lp.fill(sel, auth.get("username", ""))
                                        break
                                    except Exception:
                                        pass
                            if auth.get("password_selector"):
                                lp.fill(auth["password_selector"], auth.get("password", ""))
                            else:
                                for sel in ["input[type=password]", "#password", "input[name=password]"]:
                                    try:
                                        lp.fill(sel, auth.get("password", ""))
                                        break
                                    except Exception:
                                        pass
                            if auth.get("submit_selector"):
                                lp.click(auth["submit_selector"])
                            else:
                                for sel in ["button[type=submit]", "button#loginButton", "button[name=login]"]:
                                    try:
                                        lp.click(sel)
                                        break
                                    except Exception:
                                        pass
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
            # Persist storage state for this job (optional, used by replay/fuzzer)
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

    # === Build final outputs ===
    deduped_reqs = dedupe_requests(captured_requests)
    eps_from_network = endpoints_from_requests(deduped_reqs)
    eps_from_forms = endpoints_from_forms(raw_form_endpoints)
    merged = merge_endpoints(eps_from_forms, eps_from_network)

    return merged, deduped_reqs
