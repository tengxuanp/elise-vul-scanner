# backend/modules/playwright_crawler.py
from __future__ import annotations

from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional, Set

import json
import os
import re
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
from urllib.parse import urljoin, urlparse, urlunparse, parse_qs

from backend.schemas import (
    EndpointOut, ParamLocs, Param, AuthConfig, HTTPMethod
)

# === Heuristics / constants ===
# Static asset extensions to ignore
STATIC_EXTENSIONS = (
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".ico", ".woff", ".woff2", ".ttf", ".map"
)



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


# NEW: treat http↔https upgrades and www. host normalization as same-site
# This helps avoid "0 endpoints" when targets redirect to https or www.

def _canon_host(h: Optional[str]) -> str:
    s = (h or "").strip().lower()
    if s.startswith("www."):
        s = s[4:]
    return s


def same_site(a: str, b: str) -> bool:
    try:
        ua, ub = urlparse(a), urlparse(b)
        ha, hb = _canon_host(ua.hostname), _canon_host(ub.hostname)
        if not ha or not hb or ha != hb:
            return False
        pa = ua.port or default_port(ua.scheme)
        pb = ub.port or default_port(ub.scheme)
        # Allow http(80) ↔ https(443) upgrades, but otherwise require same port
        if pa == pb:
            return True
        if {pa, pb} <= {80, 443}:
            return True
        return False
    except Exception:
        return False


def default_port(scheme: Optional[str]) -> int:
    return 443 if (scheme or "").lower() == "https" else 80




def parse_query(url: str) -> List[str]:
    try:
        # keep_blank_values=True ensures keys like ?q= are preserved
        return sorted(parse_qs(urlparse(url).query, keep_blank_values=True).keys())
    except Exception:
        return []


def _looks_like_json_string(s: Optional[str]) -> bool:
    if not s:
        return False
    ss = s.strip()
    return (ss.startswith("{") and ss.endswith("}")) or (ss.startswith("[") and ss.endswith("]"))


def _json_types(obj: Any) -> Optional[Dict[str, str]]:
    """Return a shallow {key: type_name} map for dict-like JSON bodies."""
    if not isinstance(obj, dict):
        return None
    out: Dict[str, str] = {}
    for k, v in obj.items():
        tn = type(v).__name__
        out[str(k)] = tn
    return out or None


def parse_body(headers: Dict[str, str], post_data: Optional[str]) -> Dict[str, Any]:
    """
    Returns: {"type": "json"|"form"|"multipart"|"other"|None, "parsed": dict|None, "raw": str|None, "keys":[...], "graphql": dict|None, "json_types": dict|None}
    - Tries hard to infer JSON even if content-type is missing/misleading.
    - Multipart: best-effort extraction of field names (no file content preserved).
    """
    ct = ""
    for k, v in (headers or {}).items():
        if str(k).lower() == "content-type":
            ct = (v or "").lower()
            break

    if not post_data:
        return {"type": None, "parsed": None, "raw": None, "keys": [], "graphql": None, "json_types": None}

    # JSON
    if "application/json" in ct or _looks_like_json_string(post_data):
        parsed, keys, gql = None, [], None
        try:
            parsed = json.loads(post_data)
            if isinstance(parsed, dict):
                keys = sorted(parsed.keys())
                # GraphQL hint
                if "query" in parsed:
                    gql = {
                        "has_graphql": True,
                        "operationName": parsed.get("operationName"),
                        "variables_keys": sorted((parsed.get("variables") or {}).keys()) if isinstance(parsed.get("variables"), dict) else [],
                    }
        except Exception:
            parsed = None
        return {
            "type": "json",
            "parsed": parsed if isinstance(parsed, dict) else None,
            "raw": post_data,
            "keys": keys,
            "graphql": gql,
            "json_types": _json_types(parsed) if isinstance(parsed, dict) else None
        }

    # Form-urlencoded
    if "application/x-www-form-urlencoded" in ct or "form" in ct:
        try:
            parsed_qs = parse_qs(post_data, keep_blank_values=True)  # {k: [v,...]}
            parsed = {k: (v[0] if isinstance(v, list) and v else v) for k, v in parsed_qs.items()}
            return {
                "type": "form",
                "parsed": parsed,
                "raw": post_data,
                "keys": sorted(parsed.keys()),
                "graphql": None,
                "json_types": None
            }
        except Exception:
            return {"type": "form", "parsed": None, "raw": post_data, "keys": [], "graphql": None, "json_types": None}

    # Multipart (best-effort names)
    if "multipart/form-data" in ct:
        # Pull out name="field" occurrences; do not keep contents
        names = sorted(set(re.findall(r'name="([^"]+)"', post_data)))
        parsed = {n: "<multipart>" for n in names}
        return {
            "type": "multipart",
            "parsed": parsed if parsed else None,
            "raw": "<multipart redacted>",
            "keys": names,
            "graphql": None,
            "json_types": None
        }

    # Fallback
    return {"type": "other", "parsed": None, "raw": post_data, "keys": [], "graphql": None, "json_types": None}


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




def extract_params_from_url(url: str) -> List[str]:
    """Extract parameter names from query string."""
    try:
        # Preserve blank values so ?q= yields ['q']
        return sorted(parse_qs(urlparse(url).query, keep_blank_values=True).keys())
    except Exception:
        return []


def extract_params_from_form_data(post_data: str, content_type: str) -> List[str]:
    """Extract parameter names from form data."""
    try:
        if "application/x-www-form-urlencoded" in content_type:
            return sorted(parse_qs(post_data, keep_blank_values=True).keys())
        elif "application/json" in content_type:
            data = json.loads(post_data)
            if isinstance(data, dict):
                return sorted(data.keys())
    except Exception:
        pass
    return []


def get_content_type_from_headers(headers: Dict[str, str]) -> str:
    """Extract content-type from response headers."""
    for key, value in headers.items():
        if key.lower() == "content-type":
            return value.split(";")[0].strip()
    return "text/html"


# ------------------------------- main crawl ---------------------------------

def crawl_site(
    target_url: str,
    max_depth: int = 2,
    max_endpoints: int = 30,
    submit_get_forms: bool = True,
    submit_post_forms: bool = True,
    seeds: Optional[List[str]] = None,
    auth: Optional[Dict[str, Any]] = None,
    click_buttons: bool = True,
    max_seconds: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Strict, interaction-based crawler that:
    1. Visits pages with BFS up to depth N
    2. Collects same-origin links (up to 30 per page)
    3. Submits GET/POST forms with real values
    4. Captures XHR/Fetch requests
    5. Extracts parameters from query/form/json
    6. Deduplicates by (method, pathname, sorted param names)
    
    Returns: {
        "endpoints": [{"url", "method", "params", "param_locs", "content_type"}],
        "meta": {"pagesVisited", "xhrCount", "emitted"}
    }
    """
    assert isinstance(max_depth, int) and max_depth >= 0, "max_depth must be a non-negative int"
    
    import time
    print(f"[CRAWL] start={target_url} max_depth={max_depth}")
    # Initialize state
    visited_urls: Set[str] = set()
    url_queue: List[Tuple[str, int]] = []  # (url, current_depth)
    captured_requests: List[Dict[str, Any]] = []
    endpoints: List[Dict[str, Any]] = []
    pages_visited = 0
    xhr_count = 0
    emitted = 0
    visited_routes: Set[str] = set()
    started_at = time.time()

    # Initialize queue with target_url and seeds
    url_queue.append((target_url, 0))
    # Auto-seed common SPA routes for Juice Shop-like hash routers if no seeds provided
    if not seeds and ("/#/" in target_url or urlparse(target_url).fragment.startswith("/")):
        base = strip_fragment(target_url).rstrip('/')
        seeds = [
            f"{base}/#/",
            f"{base}/#/login",
            f"{base}/#/search",
            f"{base}/#/contact",
            f"{base}/#/about",
            f"{base}/#/basket",
        ]
    if seeds:
        for seed in seeds:
            if seed and same_site(seed, target_url):
                url_queue.append((seed, 0))
    
    # Extract parameters from initial target_url and add to captured_requests
    # This ensures that parameters from the initial URL are not missed
    if target_url and same_site(target_url, target_url):
        initial_params = extract_params_from_url(target_url)
        print(f"[CRAWL_DEBUG] Initial URL: {target_url}")
        print(f"[CRAWL_DEBUG] Initial params: {initial_params}")
        if initial_params:
            # Create a mock request for the initial URL
            parsed_url = urlparse(target_url)
            captured_requests.append({
                "url": target_url,
                "method": "GET",
                "req_headers": {},
                "post_data": None,
                "resource_type": "document",
                "content_type": "text/html",
                "source": "initial",
                "status": 200,  # Assume success for initial URL
            })
            print(f"[CRAWL_DEBUG] Added initial request to captured_requests")
    
    # Remove duplicates from queue
    seen_in_queue = set()
    unique_queue = []
    for url, entry_depth in url_queue:
        if url not in seen_in_queue:
            seen_in_queue.add(url)
            unique_queue.append((url, entry_depth))
    url_queue = unique_queue

    def process_request(request_info):
        url = request_info.get("url","")
        method = (request_info.get("method") or "GET").upper()
        if is_static_resource(url) or not same_site(url, target_url):
            return None

        q_names  = extract_params_from_url(url)
        bodyinfo = parse_body(request_info.get("req_headers") or {}, request_info.get("post_data"))
        f_names  = bodyinfo["keys"] if bodyinfo["type"] in ("form","multipart") else []
        j_names  = bodyinfo["keys"] if bodyinfo["type"] == "json" else []
        
        # Compute path for UI
        parsed = urlparse(url)
        path = parsed.path or "/"

        return {
            "url": url,
            "path": path,
            "method": method,
            "params": sorted(set(q_names + f_names + j_names)),
            "param_locs": { "query": q_names, "form": f_names, "json": j_names },
            "status": request_info.get("status"),
            "source": request_info.get("source") or "other",
            "content_type": request_info.get("content_type") or "text/html",
            "seen": 1,
            # Include SPA context for UI/debugging
            "spa_view": request_info.get("view_fragment"),
            "spa_view_url": request_info.get("view_url"),
        }

    def _src_rank(s):
        s = (s or "").lower()
        return 3 if s == "xhr" else 2 if s == "fetch" else 1 if s == "nav" else 0

    def aggregate_endpoints(items):
        """Aggregate duplicate endpoints and sum seen counts."""
        buckets = {}
        for ep in items:
            parsed = urlparse(ep["url"])
            key = (ep["method"], parsed.path or "/", tuple(ep["param_locs"]["query"]),
                   tuple(ep["param_locs"]["form"]), tuple(ep["param_locs"]["json"]))
            if key not in buckets:
                buckets[key] = ep.copy()
            else:
                dst = buckets[key]
                dst["seen"] = int(dst.get("seen",0)) + int(ep.get("seen",0) or 1)
                if ep.get("status"):       dst["status"] = ep["status"]
                if ep.get("content_type"): dst["content_type"] = ep["content_type"]
                if ep.get("source") and _src_rank(ep.get("source")) > _src_rank(dst.get("source")):
                    dst["source"] = ep["source"]
        return list(buckets.values())









    def visit_page(url, context, click_buttons=True):
        page = context.new_page()
        new_urls = []
        try:
            page.on("request", capture_request)
            page.on("response", capture_response)

            try:
                page.goto(url, wait_until="domcontentloaded", timeout=15000)
            except PlaywrightTimeoutError:
                pass
            try:
                page.wait_for_load_state("networkidle", timeout=2000)
            except PlaywrightTimeoutError:
                pass
            nonlocal pages_visited
            pages_visited += 1
            
            # Strengthen input stimulation (immediately after goto)
            inputs = page.query_selector_all('input[type="text"], input[type="search"], input[name="q"], #q, [placeholder*="search" i]')
            for inp in inputs[:5]:
                try:
                    inp.click()
                    inp.fill("test")
                    page.keyboard.press("Enter")
                    inp.dispatch_event("input")
                    inp.dispatch_event("change")
                    page.wait_for_timeout(700)  # debounce window so fetch fires
                except Exception:
                    pass
            
            # Click likely buttons that trigger XHR/fetch (limited, safe)
            if click_buttons:
                buttons = page.query_selector_all('button, input[type="button"], a[role="button"]')
                clicked = 0
                for b in buttons:
                    if clicked >= 6:
                        break
                    try:
                        txt = (b.inner_text() or "").strip().lower()
                        typ = (b.get_attribute("type") or "").lower()
                        # Enhanced pattern matching for XHR-triggering buttons
                        if ((typ == "submit" or typ == "button") or 
                            any(word in txt for word in ["search", "submit", "go", "send", "transfer", "login", "json", "api", "ajax"])):
                            if b.is_visible():
                                b.click()
                                clicked += 1
                                page.wait_for_timeout(250)
                    except Exception:
                        pass
            
            # Collect same-origin links (up to 60 per page, prefer hash/router links first)
            links = page.evaluate("""
                () => {
                    const links = [];
                    const anchors = Array.from(document.querySelectorAll('a[href]'));
                    // prioritize hash-based router links first
                    const sorted = anchors.sort((a,b) => {
                        const ah = (a.getAttribute('href')||'').startsWith('#/');
                        const bh = (b.getAttribute('href')||'').startsWith('#/');
                        return (bh?1:0) - (ah?1:0);
                    });
                    for (let i = 0; i < Math.min(sorted.length, 60); i++) {
                        const href = sorted[i].getAttribute('href');
                        if (href && !href.startsWith('javascript:') && !href.startsWith('mailto:')) {
                            try {
                                const url = new URL(href, window.location.href);
                                links.push(url.href);
                            } catch (e) {
                                // Skip invalid URLs
                            }
                        }
                    }
                    // Also collect Angular routerLink targets if present
                    const routerEls = Array.from(document.querySelectorAll('[routerLink]'));
                    for (let i = 0; i < Math.min(routerEls.length, 40); i++) {
                        const rl = routerEls[i].getAttribute('routerLink');
                        if (!rl) continue;
                        try {
                            const href = rl.startsWith('/') ? `#${rl}` : `#/${rl}`;
                            const url = new URL(href, window.location.href);
                            links.push(url.href);
                        } catch (e) {}
                    }
                    return links;
                }
            """)

            # Detect SPA hash-router presence (Python: use 'in' not JS 'includes')
            is_hash_spa = any((('/#/' in l) or ('#/' in l)) for l in (links or []))

            # Filter to same-site URLs; for SPAs we will prefer in-page navigation and NOT enqueue
            for link in links:
                if same_site(link, target_url) and link not in visited_urls and not is_static_resource(link):
                    if not is_hash_spa:
                        new_urls.append(link)

            # Handle forms
            forms = page.query_selector_all('form')
            for form in forms:
                try:
                    # Get form method and action
                    method = (form.get_attribute('method') or 'GET').upper()
                    action = form.get_attribute('action') or url
                    action_url = urljoin(url, action)
                    
                    # Only process same-site forms
                    if not same_site(action_url, target_url):
                        continue
                    
                    # Submit form if enabled
                    if (method == 'GET' and submit_get_forms) or (method == 'POST' and submit_post_forms):
                        # Fill form fields with type-aware actions
                        inputs = form.query_selector_all('input, select, textarea')
                        
                        for input_elem in inputs:
                            name = input_elem.get_attribute('name')
                            if not name:
                                continue
                            
                            tag = (input_elem.evaluate("e => e.tagName") or "").lower()
                            itype = (input_elem.get_attribute('type') or 'text').lower()
                            
                            try:
                                if tag == "select":
                                    options = input_elem.query_selector_all("option")
                                    if options:
                                        val = options[0].get_attribute("value") or options[0].inner_text() or "1"
                                        input_elem.select_option(val)
                                elif itype in ["checkbox", "radio"]:
                                    input_elem.check()
                                else:
                                    page.fill(f'[name="{name}"]', "test" if itype not in ["email", "number", "range"] else ("alice@example.com" if itype == "email" else "1"))
                            except Exception:
                                pass

                        # Submit form reliably
                        try:
                            submit_btn = form.query_selector('button[type="submit"], input[type="submit"]')
                            if submit_btn:
                                submit_btn.click()
                            else:
                                form.evaluate('f => f.submit()')
                            
                            # Wait both for navigation and network quiet
                            try:
                                page.wait_for_load_state("domcontentloaded", timeout=5000)
                                page.wait_for_load_state("networkidle", timeout=5000)
                            except PlaywrightTimeoutError:
                                pass
                        except Exception as e:
                            print(f"[WARN] Form submission failed: {e}")
                            
                except Exception as e:
                    print(f"[WARN] Form processing failed: {e}")
            
            # small idle to let XHRs flush
            page.wait_for_timeout(300)

            # If SPA (hash router), proactively click a few router links to trigger XHRs without full reloads
            try:
                if True:  # unconditional; inner check limits to SPA only
                    hash_links = page.query_selector_all('a[href^="#/"], a[href*="/#/"], [routerLink]')
                    clicked = 0
                    for a in hash_links:
                        if clicked >= 10:
                            break
                        try:
                            # Click and wait a short settle time (networkidle may not fire for SPAs)
                            href = a.get_attribute('href') or a.get_attribute('routerLink') or ''
                            if not href:
                                continue
                            before = page.url
                            a.click()
                            page.wait_for_timeout(300)
                            after = page.url
                            if after not in visited_routes:
                                visited_routes.add(after)
                                # Discover new links on this routed view
                                more_links = page.evaluate("""
                                    () => Array.from(document.querySelectorAll('a[href]')).slice(0, 40).map(a=>{
                                        try { return new URL(a.getAttribute('href'), window.location.href).href } catch(e){ return null }
                                    }).filter(Boolean)
                                """)
                                for ml in more_links:
                                    if same_site(ml, target_url) and not is_static_resource(ml):
                                        if not (('#/' in ml) or ('/#/' in ml)):
                                            # Only enqueue non-hash links to avoid redundant full reloads
                                            if ml not in visited_urls and ml not in new_urls:
                                                new_urls.append(ml)
                            clicked += 1
                        except Exception:
                            pass
            except Exception:
                pass

            # Explicit search stimulation for common SPA search inputs (ensures ?q= captured)
            try:
                # Reveal the search bar if it is hidden behind an icon/button
                toggle = page.query_selector('button[aria-label*="search" i], button[aria-label*="Search" i], button[aria-label*="open" i], button mat-icon[svgicon="search"]')
                if toggle and toggle.is_visible():
                    try:
                        toggle.click()
                        page.wait_for_timeout(120)
                    except Exception:
                        pass
                search = page.query_selector('input[aria-label="Search"], input[placeholder*="search" i], input[name="q"], input#searchQuery')
                if search and search.is_visible():
                    try:
                        search.click()
                        search.fill('test')
                        page.keyboard.press('Enter')
                    except Exception:
                        pass
                    try:
                        page.wait_for_load_state('domcontentloaded', timeout=1500)
                    except PlaywrightTimeoutError:
                        pass
                    page.wait_for_timeout(200)
            except Exception:
                pass
        except Exception as e:
            print(f"[ERROR] Failed to visit {url}: {e}")
        finally:
            page.close()

        return new_urls

    # Main crawl loop with BFS
    def _do_form_login(context, auth: Dict[str, Any]):
        page = context.new_page()
        try:
            try:
                page.goto(str(auth["login_url"]), wait_until="domcontentloaded", timeout=15000)
            except PlaywrightTimeoutError:
                pass
            try:
                page.wait_for_load_state("networkidle", timeout=2000)
            except PlaywrightTimeoutError:
                pass
            page.fill(f'[name="{auth["username_field"]}"]', auth["username"])
            page.fill(f'[name="{auth["password_field"]}"]', auth["password"])
            if auth.get("submit_selector"):
                page.click(auth["submit_selector"])
            else:
                # try typical submit controls
                btn = page.query_selector('button[type="submit"], input[type="submit"]') or page.query_selector("button, [role=button]")
                if btn: btn.click()
                else: page.keyboard.press("Enter")
            try:
                page.wait_for_load_state("networkidle", timeout=2000)
            except PlaywrightTimeoutError:
                pass
        finally:
            page.close()

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(ignore_https_errors=True)

        # Route handler: block heavy assets and long-lived sockets to speed up crawling
        def _route_handler(route):
            try:
                req = route.request
                rtype = (req.resource_type or '').lower()
                url = req.url
                # Block non-essential resource types
                if rtype in ('image','media','font'):
                    return route.abort()
                # Block long-lived sockets/event streams which delay networkidle
                if 'socket.io' in url or rtype in ('websocket','eventsource'):
                    return route.abort()
                # Block third-party origins altogether
                if not same_site(url, target_url):
                    return route.abort()
            except Exception:
                pass
            return route.continue_()

        try:
            context.route('**/*', _route_handler)
        except Exception:
            # Best-effort; continue if routing not available
            pass
        
        # Perform authentication if provided
        if auth:
            _do_form_login(context, auth)
        
        # Set up request/response capture
        def capture_request(request):
            try:
                url = request.url
                if is_static_resource(url) or not same_site(url, target_url):
                    return
                
                # Debug logging
                if os.getenv("CRAWL_DEBUG") == "1":
                    print("[REQ]", request.method, getattr(request,"resource_type",None), request.url, request.post_data[:120] if request.post_data else "")
                
                # Classify source based on resource type
                rt = (getattr(request, "resource_type", "") or "").lower()
                src = "xhr" if rt in ("xhr","fetch") else ("nav" if rt == "document" else (rt or "other"))
                
                # Try to capture current SPA route (hash) from the frame URL
                view_url = None
                view_fragment = None
                try:
                    frame = getattr(request, 'frame', None)
                    if frame is not None:
                        view_url = getattr(frame, 'url', None)
                        if view_url:
                            from urllib.parse import urlparse
                            frag = urlparse(view_url).fragment or ''
                            if frag:
                                if not frag.startswith('#'):
                                    frag = '#' + frag
                                view_fragment = frag
                except Exception:
                    view_url = None
                    view_fragment = None
                
                captured_requests.append({
                    "url": url,
                    "method": request.method.upper(),
                    "req_headers": request.headers,
                    "post_data": request.post_data,       # raw string
                    "resource_type": getattr(request, "resource_type", None),
                    "content_type": None,                 # will be filled by response
                    "source": src,
                    "status": None,                       # will be filled by response
                    "view_url": view_url,
                    "view_fragment": view_fragment,
                })
            except Exception as e:
                print(f"[WARN] Request capture failed: {e}")
        
        def capture_response(response):
            try:
                url = response.url
                if is_static_resource(url) or not same_site(url, target_url):
                    return
                ct = get_content_type_from_headers(response.headers)
                # match by url+method to avoid wrong pairing
                m = response.request.method.upper()
                for req in reversed(captured_requests):
                    if req["url"] == url and req["method"] == m and req["content_type"] is None:
                        req["content_type"] = ct
                        req["status"] = response.status
                        break
            except Exception as e:
                print(f"[WARN] Response capture failed: {e}")
        
        # Set up event listeners (belt-and-suspenders)
        context.on("request", capture_request)
        context.on("response", capture_response)
        
        # Process URL queue with BFS
        while url_queue:
            current_url, current_depth = url_queue.pop(0)
            
            if current_url in visited_urls or current_depth > max_depth:
                continue
            
            visited_urls.add(current_url)
            
            print(f"[CRAWL] visiting depth={current_depth} url={current_url}")
            
            # Visit page and get new URLs
            new_urls = visit_page(current_url, context, click_buttons)

            # Add new URLs to queue
            for new_url in new_urls:
                if new_url not in visited_urls and current_depth < max_depth:
                    print(f"[CRAWL] enqueue depth={current_depth+1} url={new_url}")
                    url_queue.append((new_url, current_depth + 1))

            # Early stop if enough endpoints captured
            try:
                agg = aggregate_endpoints([process_request(r) for r in captured_requests if process_request(r)])
                if len(agg) >= max_endpoints:
                    print(f"[CRAWL] Reached max_endpoints={max_endpoints}, stopping BFS.")
                    break
            except Exception:
                pass

            # Time budget check
            if max_seconds is not None and (time.time() - started_at) > max_seconds:
                print(f"[CRAWL] Time budget exceeded ({max_seconds}s). Stopping crawl.")
                break
        
        browser.close()
    
    # Process captured requests into endpoints
    for request_info in captured_requests:
        print(f"[CRAWL_DEBUG] Processing request: {request_info}")
        endpoint = process_request(request_info)
        print(f"[CRAWL_DEBUG] Processed endpoint: {endpoint}")
        if endpoint:
            endpoints.append(endpoint)
    
    # Aggregate duplicate endpoints
    endpoints = aggregate_endpoints(endpoints)
    
    # Sort results for UI readability
    endpoints = sorted(endpoints, key=lambda e: (e["path"], e["method"], -len(e["params"])))
    
    # Count correctly
    xhr_count = sum(1 for r in captured_requests if same_site(r["url"], target_url) and not is_static_resource(r["url"]))
    
    return {
        "endpoints": endpoints,
        "meta": {
            "engine": "playwright-strict",
            "pagesVisited": pages_visited,
            "xhrCount": xhr_count,
            "emitted": len(endpoints),
            "uniquePaths": len({e["path"] for e in endpoints}),
            "withParams": sum(1 for e in endpoints if e["params"])
        }
    }
