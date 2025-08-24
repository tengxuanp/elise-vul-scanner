# backend/modules/playwright_crawler.py
from __future__ import annotations

from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional, Set

import json
import re
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
from urllib.parse import urljoin, urlparse, urlunparse, parse_qs

from ..schemas import (
    EndpointOut, ParamLocs, Param, AuthConfig, HTTPMethod
)

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


# ------------------------------- helpers ------------------------------------

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
        out[k] = "***redacted***" if str(k).lower() in SENSITIVE_HEADERS else v
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
        if str(k).lower() == "content-type":
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
            parsed_qs = parse_qs(post_data)  # {k: [v,...]}
            parsed = {k: (v[0] if isinstance(v, list) and v else v) for k, v in parsed_qs.items()}
            return {"type": "form", "parsed": parsed, "raw": post_data, "keys": sorted(parsed.keys())}
        except Exception:
            return {"type": "form", "parsed": None, "raw": post_data, "keys": []}

    return {"type": "other", "parsed": None, "raw": post_data, "keys": []}


def strip_fragment(u: str) -> str:
    """Remove any #fragment from URL."""
    try:
        parts = list(urlparse(u))
        parts[5] = ""  # fragment
        return urlunparse(parts)
    except Exception:
        return u


def endpoint_shape_key(
    method: str,
    path: str,
    q_names: List[str],
    f_names: List[str],
    j_names: List[str],
) -> Tuple[str, str, Tuple[str, ...], Tuple[str, ...], Tuple[str, ...]]:
    return (
        method.upper(),
        path or "/",
        tuple(sorted(q_names or [])),
        tuple(sorted(f_names or [])),
        tuple(sorted(j_names or []))
    )


def make_paramlocs(
    q_names: List[str],
    f_names: List[str],
    j_names: List[str]
) -> ParamLocs:
    return ParamLocs(
        query=[Param(name=n) for n in sorted(q_names or [])],
        form=[Param(name=n) for n in sorted(f_names or [])],
        json=[Param(name=n) for n in sorted(j_names or [])],
    )


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


# ------------------------------- main crawl ---------------------------------

def crawl_site(
    target_url: str,
    max_depth: int = 2,
    auth: Optional[Dict[str, Any]] = None,
    job_dir: Optional[str] = None,
    max_pages: int = 200,
) -> Tuple[List[EndpointOut], List[Dict[str, Any]]]:
    """
    Crawl a target and return:
      - endpoints: merged, deduplicated canonical EndpointOut objects
      - captured_requests: deduped network requests with redacted headers and parsed bodies

    captured_requests item shape:
      {
        "method","url","headers","post_data","body_type","body_parsed","query_params"
      }

    NOTES:
    - Same-origin only.
    - SPA hash routes are navigated to mine forms, but endpoints are emitted with fragments stripped.
    - No socket.io endpoints; no static assets.
    """
    # === State ===
    visited: Set[Tuple[str, Tuple[str, ...]]] = set()
    page_budget = [0]  # mutable counter
    raw_form_endpoints: List[Dict[str, Any]] = []
    captured_requests: List[Dict[str, Any]] = []

    def normalize_for_visit(url: str) -> Tuple[str, Tuple[str, ...]]:
        """Normalize a page URL for visited-set: path + query key tuple (fragment stripped)."""
        u = strip_fragment(url)
        parsed = urlparse(u)
        params = sorted(parse_qs(parsed.query).keys())
        return parsed.path or "/", tuple(params)

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
            key = (str(r.get("method", "GET")).upper(), parsed.path, q_keys, body_type, body_keys)
            if key not in seen:
                seen.add(key)
                unique.append(r)
        return unique

    def endpoints_from_requests(reqs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for r in reqs:
            url = strip_fragment(r.get("url") or "")
            if not url:
                continue
            # NOISE CUT: same-origin and no socket.io
            if not same_origin(url, target_url):
                continue
            if "/socket.io/" in urlparse(url).path:
                continue

            method = str(r.get("method") or "GET").upper()
            q_names = list(r.get("query_params") or [])
            b_type = r.get("body_type")
            parsed_body = r.get("body_parsed") if isinstance(r.get("body_parsed"), dict) else None

            f_names: List[str] = []
            j_names: List[str] = []
            content_type_hint: Optional[str] = None

            if b_type == "json":
                j_names = sorted((parsed_body or {}).keys())
                content_type_hint = "application/json"
            elif b_type == "form":
                f_names = sorted((parsed_body or {}).keys())
                content_type_hint = "application/x-www-form-urlencoded"

            out.append({
                "url": url,
                "method": method,
                "path": urlparse(url).path or "/",
                "q_names": sorted(q_names),
                "f_names": f_names,
                "j_names": j_names,
                "content_type_hint": content_type_hint,
                "source": "network",
                "headers": {},  # baseline headers unknown/irrelevant at discovery
            })
        return out

    def endpoints_from_forms(forms: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for f in forms:
            url = strip_fragment(f["url"])
            if not same_origin(url, target_url):
                continue
            if "/socket.io/" in urlparse(url).path:
                continue

            method = str(f["method"]).upper()
            params = sorted(f.get("params") or [])
            enctype = (f.get("enctype") or "").lower() or None

            # Map to unified locations:
            if method == "GET":
                q_names = params
                f_names: List[str] = []
            else:
                q_names = []
                f_names = params  # default to form for non-GET

            j_names: List[str] = []
            if enctype and "json" in enctype:
                # rare, but respect explicit json form enctype
                j_names, f_names = f_names, []

            out.append({
                "url": url,
                "method": method,
                "path": urlparse(url).path or "/",
                "q_names": sorted(q_names),
                "f_names": sorted(f_names),
                "j_names": sorted(j_names),
                "content_type_hint": ("application/json" if j_names else ("application/x-www-form-urlencoded" if f_names else None)),
                "source": "form",
                "headers": {},
            })
        return out

    def merge_endpoints(form_eps: List[Dict[str, Any]], req_eps: List[Dict[str, Any]]) -> List[EndpointOut]:
        """
        Merge on canonical shape (METHOD|PATH|Q|F|J).
        If duplicates exist from both form and network with same param names, keep one and
        prefer non-None content_type_hint (network usually better).
        """
        index: Dict[Tuple[str, str, Tuple[str, ...], Tuple[str, ...], Tuple[str, ...]], Dict[str, Any]] = {}

        def upsert(ep: Dict[str, Any]):
            key = endpoint_shape_key(ep["method"], ep["path"], ep["q_names"], ep["f_names"], ep["j_names"])
            if key not in index:
                index[key] = ep.copy()
                return
            cur = index[key]
            # Prefer richer content_type_hint if current is None
            if not cur.get("content_type_hint") and ep.get("content_type_hint"):
                cur["content_type_hint"] = ep.get("content_type_hint")
            index[key] = cur

        for e in form_eps:
            upsert(e)
        for e in req_eps:
            upsert(e)

        # Materialize EndpointOut
        final_eps: List[EndpointOut] = []
        for ep in index.values():
            param_locs = make_paramlocs(ep["q_names"], ep["f_names"], ep["j_names"])
            final_eps.append(
                EndpointOut(
                    method=HTTPMethod(ep["method"]),
                    url=ep["url"],
                    headers=ep.get("headers") or {},
                    param_locs=param_locs,
                    content_type_hint=ep.get("content_type_hint")
                )
            )
        # Stable sort by method then path
        final_eps.sort(key=lambda x: (x.method.value, x.path))
        return final_eps

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
                "url": strip_fragment(url),
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
                "is_login": form_is_login(inputs),        # currently unused; reserved
                "csrf_params": form_csrf_params(inputs),  # currently unused; reserved
                "enctype": enctype
            })

    def crawl(url: str, depth: int, context):
        if depth > max_depth:
            return
        norm = normalize_for_visit(url)
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
                    if "/socket.io/" in urlparse(full_url).path:
                        continue
                    # Record GET "discoveries" (query keys only; do not invent body params)
                    raw_form_endpoints.append({
                        "url": strip_fragment(full_url),
                        "method": "GET",
                        "params": [],
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
    headful = bool(auth and str(auth.get("mode", "none")).lower() == "manual")
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=not headful)
        context = browser.new_context()

        # Optional auth bootstrap
        if auth and str(auth.get("mode", "none")).lower() != "none":
            mode = str(auth.get("mode")).lower()
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
                                try:
                                    lp.click(auth["submit_selector"])
                                except Exception:
                                    pass
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
