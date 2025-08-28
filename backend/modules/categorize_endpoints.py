# backend/modules/categorize_endpoints.py
from __future__ import annotations

import json
import re
from typing import List, Dict, Any, Tuple, Optional, Iterable
from pathlib import Path
from urllib.parse import urlparse, parse_qs

# ---- optional family router (non-fatal if missing) --------------------------
try:
    from .family_router import choose_family  # noqa
    _HAS_FAMILY_ROUTER = True
except Exception:
    _HAS_FAMILY_ROUTER = False
    def choose_family(_: Dict[str, Any]) -> Dict[str, Any]:  # type: ignore[override]
        return {"family": "base", "confidence": 0.0, "reason": "router_unavailable", "rules_matched": [], "scores": {}}

# ---- helpers ---------------------------------------------------------------

# Do NOT include ".json" or ".txt" here; many legit APIs use those.
STATIC_EXTENSIONS = (
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".map", ".md"
)

REDIRECT_PARAM_NAMES = {"to", "url", "next", "dest", "redirect", "redirect_uri", "return", "continue", "callback", "return_to"}
UPLOAD_PARAM_HINTS = {"file", "files", "upload", "image", "avatar", "photo", "filename", "attachment"}
GRAPHQL_PATH_HINTS = {"/graphql"}
GRAPHQL_BODY_KEYS = {"query", "operationName", "variables"}

# broader than before: include sort/order/dir and pagination ids seen in the wild
SQLI_HINTS = {
    "q", "query", "search", "term", "filter", "id", "ids", "item", "product", "user", "uid",
    "order", "orderby", "sort", "dir", "page", "page_id", "cat", "category_id"
}
XSS_HINTS = {
    "comment", "message", "content", "text", "name", "title", "feedback", "body", "desc", "description",
    "bio", "notes", "subject"
}

GQL_QUERY_RE = re.compile(r"\b(query|mutation|subscription)\b", re.I)


def is_static_asset(url: str) -> bool:
    try:
        return urlparse(url).path.lower().endswith(STATIC_EXTENSIONS)
    except Exception:
        return False


def _safe_list(val: Any) -> List[Any]:
    return list(val) if isinstance(val, (list, tuple)) else []


def _as_plain(x: Any) -> Any:
    """
    Coerce Pydantic models (v1/v2) or other objects to plain dicts where possible.
    Leave dicts and primitives unchanged.
    """
    if isinstance(x, dict):
        return x
    # pydantic v2
    md = getattr(x, "model_dump", None)
    if callable(md):
        try:
            return md()
        except Exception:
            pass
    # pydantic v1
    d = getattr(x, "dict", None)
    if callable(d):
        try:
            return d()
        except Exception:
            pass
    return x


def _get(obj: Any, key: str, default: Any = None) -> Any:
    """
    Safe getter for dicts, Pydantic models, or plain objects.
    """
    if isinstance(obj, dict):
        return obj.get(key, default)
    # pydantic v2 BaseModel supports attribute access
    if hasattr(obj, key):
        try:
            val = getattr(obj, key)
            return val if val is not None else default
        except Exception:
            return default
    # last-ditch: try item access
    try:
        return obj[key]  # type: ignore[index]
    except Exception:
        return default


def _names_from_param_items(items: Iterable[Any]) -> List[str]:
    """
    Accepts a list of strings OR a list of dicts like {"name": "..."} (Pydantic export).
    Returns normalized, unique names.
    """
    out: List[str] = []
    seen = set()
    for it in _safe_list(items):
        if isinstance(it, str):
            name = it.strip()
        elif isinstance(it, dict):
            name = str(it.get("name", "")).strip()
        else:
            # Unknown object; best-effort getattr
            name = str(getattr(it, "name", "")).strip()
        if name and name not in seen:
            seen.add(name)
            out.append(name)
    return out


# ------------------------ param extraction (unified) ------------------------

def extract_query_param_keys(ep: Any) -> List[str]:
    """
    Preference order:
      1) 'param_locs'.query (EndpointOut)
      2) canonical 'query_keys' (legacy merged endpoints)
      3) 'query_params' (captured request records)
      4) parse URL query
    """
    pl = _get(ep, "param_locs", None)
    if isinstance(pl, dict) and isinstance(pl.get("query"), list):
        return sorted(set(_names_from_param_items(pl["query"])))
    qk = _get(ep, "query_keys")
    if isinstance(qk, list):
        return sorted(set(_safe_list(qk)))
    qp = _get(ep, "query_params")
    if isinstance(qp, list):
        return sorted(set(_safe_list(qp)))
    url = _get(ep, "url", "") or ""
    try:
        return sorted(set(parse_qs(urlparse(url).query).keys()))
    except Exception:
        return []


def extract_form_param_keys(ep: Any) -> List[str]:
    """
    Preference order:
      1) 'param_locs'.form (EndpointOut)
      2) 'body_keys' (legacy)
      3) parsed dict keys from 'body_parsed'
      4) best-effort parse of 'post_data' (x-www-form-urlencoded)
    """
    pl = _get(ep, "param_locs", None)
    if isinstance(pl, dict) and isinstance(pl.get("form"), list):
        return sorted(set(_names_from_param_items(pl["form"])))
    bk = _get(ep, "body_keys")
    if isinstance(bk, list):  # legacy form-urlencoded
        return sorted(set(_safe_list(bk)))
    bp = _get(ep, "body_parsed")
    if isinstance(bp, dict):
        # Only treat as "form" here if content type suggests non-JSON (handled below by detect_content_type)
        return sorted(set(bp.keys()))
    pd = _get(ep, "post_data")
    if isinstance(pd, str) and pd:
        try:
            return sorted(set(parse_qs(pd).keys()))
        except Exception:
            return []
    return []


def extract_json_param_keys(ep: Any) -> List[str]:
    """
    Preference order:
      1) 'param_locs'.json (EndpointOut)
      2) if 'body_parsed' is dict and content-type indicates json, use keys
    """
    pl = _get(ep, "param_locs", None)
    if isinstance(pl, dict) and isinstance(pl.get("json"), list):
        return sorted(set(_names_from_param_items(pl.get("json", []))))
    ct = detect_content_type(ep)
    bp = _get(ep, "body_parsed")
    if ct and "json" in ct and isinstance(bp, dict):
        return sorted(set(bp.keys()))
    return []


# ------------------------ content type & signature --------------------------

def detect_content_type(ep: Any) -> Optional[str]:
    """
    Normalize to one of: 'application/json', 'application/x-www-form-urlencoded',
                         'multipart/form-data', or None/other.
    Preference:
      - EndpointOut 'content_type_hint'
      - 'content_type' (legacy)
      - map from 'body_type' (json|form) (captured requests)
      - infer from 'enctype' (forms)
    """
    ct = (_get(ep, "content_type_hint") or _get(ep, "content_type") or "").lower().strip() or None
    if ct:
        if "json" in ct:
            return "application/json"
        if "x-www-form-urlencoded" in ct or "form-urlencoded" in ct or ct == "application/x-www-form-urlencoded":
            return "application/x-www-form-urlencoded"
        if "multipart/form-data" in ct or "multipart" in ct:
            return "multipart/form-data"
        return ct

    bt = (_get(ep, "body_type") or "").lower().strip()
    if bt == "json":
        return "application/json"
    if bt == "form":
        return "application/x-www-form-urlencoded"

    enctype = (_get(ep, "enctype") or "").lower().strip()
    if enctype:
        if "json" in enctype:
            return "application/json"
        if "multipart" in enctype:
            return "multipart/form-data"
        if "form" in enctype or "x-www-form-urlencoded" in enctype:
            return "application/x-www-form-urlencoded"

    return None


def normalize_signature(ep: Any) -> Tuple[str, str, Tuple[str, ...], str | None, Tuple[str, ...], Tuple[str, ...]]:
    """
    Dedupe signature:
      (METHOD, PATH, sorted(query_param_keys), content_type, sorted(form_keys), sorted(json_keys))
    """
    url = _get(ep, "url", "") or ""
    method = str((_get(ep, "method") or "GET")).upper()
    parsed = urlparse(url)
    q_keys = tuple(extract_query_param_keys(ep))
    f_keys = tuple(extract_form_param_keys(ep))
    j_keys = tuple(extract_json_param_keys(ep))
    content_type = detect_content_type(ep)
    return (method, parsed.path or "/", q_keys, content_type, f_keys, j_keys)


def smart_param_sources(ep: Any) -> Dict[str, List[str]]:
    """
    Return a clean split of params by source. Prefer canonical ParamLocs if present.
    """
    pl = _get(ep, "param_locs", None)
    if isinstance(pl, dict):
        return {
            "query": sorted(set(_names_from_param_items(pl.get("query", [])))),
            "form":  sorted(set(_names_from_param_items(pl.get("form", [])))),
            "json":  sorted(set(_names_from_param_items(pl.get("json", [])))),
        }
    # legacy / captured-request fallback
    return {
        "query": extract_query_param_keys(ep),
        "form":  extract_form_param_keys(ep),
        "json":  extract_json_param_keys(ep),
    }


def looks_like_graphql(ep: Any, path: str, json_keys: List[str], body_parsed: Dict[str, Any] | None) -> bool:
    if any(path.endswith(p) for p in GRAPHQL_PATH_HINTS):
        return True
    if set(json_keys) & GRAPHQL_BODY_KEYS:
        q = ""
        try:
            q = (body_parsed or {}).get("query", "")
        except Exception:
            q = ""
        if isinstance(q, str) and GQL_QUERY_RE.search(q):
            return True
    return False


def is_upload_endpoint(content_type: Optional[str], form_keys: List[str]) -> bool:
    if content_type and "multipart/form-data" in content_type:
        return True
    return any(k.lower() in UPLOAD_PARAM_HINTS for k in form_keys)


# ---- family recommendation --------------------------------------------------

def _recommend_param_families(ep: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    For each parameter source (query/form/json), call family_router.choose_family
    to propose a payload family with reason & confidence.
    """
    if not _HAS_FAMILY_ROUTER:
        return []

    recs: List[Dict[str, Any]] = []
    url: str = (_get(ep, "url", "") or "")
    method: str = str((_get(ep, "method") or "GET")).upper()
    ct = detect_content_type(ep)
    sources = smart_param_sources(ep)

    for loc in ("query", "form", "json"):
        for name in sources.get(loc, []):
            info = choose_family({
                "url": url,
                "method": method,
                "in": loc,
                "target_param": name,
                "content_type": ct,
                "control_value": "FUZZ",
            })
            recs.append({
                "param": name,
                "in": loc,
                "family": info.get("family", "base"),
                "confidence": info.get("confidence", 0.0),
                "reason": info.get("reason", ""),
            })
    # sort by confidence desc, then location priority (query>form>json)
    loc_order = {"query": 0, "form": 1, "json": 2}
    recs.sort(key=lambda r: (-(r.get("confidence") or 0.0), loc_order.get(r.get("in", ""), 9), r.get("param", "")))
    return recs


# ---- categorization --------------------------------------------------------

def categorize_endpoint(endpoint: Any) -> Dict[str, Any]:
    ep = _as_plain(endpoint)
    url: str = (_get(ep, "url", "") or "")
    method: str = str((_get(ep, "method") or "GET")).upper()
    path: str = urlparse(url).path or "/"
    is_login: bool = bool(_get(ep, "is_login", False))
    csrf_params: List[str] = [p for p in (_get(ep, "csrf_params", []) or []) if p]

    # param sources (prefer canonical)
    param_sources = smart_param_sources(ep)
    params_all = sorted(set(param_sources["query"]) | set(param_sources["form"]) | set(param_sources["json"]))

    content_type = detect_content_type(ep)
    body_parsed = _get(ep, "body_parsed") if isinstance(_get(ep, "body_parsed"), dict) else None
    form_keys = param_sources["form"]
    json_keys = param_sources["json"]

    categories: List[str] = []
    vuln_candidates: List[str] = []

    # Static assets
    if is_static_asset(url):
        categories.append("Static_Asset")

    # Basic method/param/content-type shape
    if method == "GET":
        categories.append("GET_with_params" if param_sources["query"] else "GET_no_params")
    elif method == "POST":
        if is_upload_endpoint(content_type, form_keys):
            categories.append("POST_Multipart_Upload")
        elif content_type == "application/json":
            categories.append("POST_JSON_with_params" if json_keys else "POST_JSON_no_params")
        elif content_type == "application/x-www-form-urlencoded" or content_type is None:
            categories.append("POST_FORM_with_params" if form_keys else "POST_no_params")
        else:
            categories.append("POST_other")
    else:
        categories.append(f"{method}_other")

    # GraphQL
    if looks_like_graphql(ep, path, json_keys, body_parsed):
        categories.append("GraphQL")

    # Heuristics: likely vulns based on param names and path
    lower_params = [p.lower() for p in params_all]

    # SQLi candidates: search/identifier/sort-like params
    if any(p in SQLI_HINTS for p in lower_params):
        vuln_candidates.append("SQLi")

    # XSS: user-controlled text fields
    if any(p in XSS_HINTS for p in lower_params):
        vuln_candidates.append("XSS")
        if method == "POST" and any(p in {"comment", "message", "content"} for p in lower_params):
            vuln_candidates.append("Stored_XSS")

    # Open Redirect
    if any(p in REDIRECT_PARAM_NAMES for p in lower_params) or "redirect" in url.lower():
        categories.append("Open_Redirect")
        vuln_candidates.append("Redirect")

    # IDOR: numeric id segments in path (simple heuristic)
    if re.search(r"/\d{3,}(/|$)", url):
        categories.append("IDOR_candidate")
        vuln_candidates.append("IDOR")

    # Token/CSRF handling
    if csrf_params or any("token" in p or "csrf" in p for p in lower_params):
        categories.append("Token_Sensitive")
        vuln_candidates.append("CSRF")

    # Login/auth
    if is_login or re.search(r"/(login|signin|auth)(/|$)", url.lower()):
        categories.append("Auth_Login")

    # Uploads → potential file handling vulns
    if is_upload_endpoint(content_type, form_keys):
        vuln_candidates.append("File_Upload")

    # Fallback categories
    if not params_all and "Static_Asset" not in categories:
        categories.append("Static_or_Display_Only")
    if not categories:
        categories.append("Uncategorized")

    # dedupe candidates
    vuln_candidates = sorted(set(vuln_candidates))
    categories = sorted(set(categories))

    # backward-compatible param_locs for downstream that still expects dict of lists
    param_locs_out = {
        "query": param_sources["query"],
        "form":  param_sources["form"],
        "json":  param_sources["json"],
    }

    # optional per-param family recommendations
    param_recommendations = _recommend_param_families(ep)

    return {
        "url": url,
        "path": path,
        "method": method,
        "params": params_all,
        "param_sources": param_locs_out,        # unified
        "param_locs": param_locs_out,          # alias for older code that reads 'param_locs'
        "content_type": content_type,
        "categories": categories,
        "vuln_type_candidates": vuln_candidates,
        "tested": False,
        "is_login": is_login,
        "csrf_params": csrf_params,
        "param_recommendations": param_recommendations,  # NEW (safe to ignore downstream)
    }


# ---- main processing -------------------------------------------------------

def process_crawl_results(input_path: Path, output_dir: Path, target_url: str):
    """
    Reads crawl_result.json:
      - new shape: {"endpoints": [...], "captured_requests": [...]}
      - legacy shape: flat list of endpoints/requests

    Keeps distinct endpoint *variants* by:
      (method, path, sorted(query_keys), content_type, sorted(form_keys), sorted(json_keys)),
    categorizes them, and writes grouped output per host.
    """
    if not input_path.exists():
        raise FileNotFoundError(f"❌ Input file not found: {input_path}")

    with input_path.open("r", encoding="utf-8") as infile:
        data = json.load(infile)

    # normalize raw list
    if isinstance(data, list):
        raw_items = data
    elif isinstance(data, dict):
        # Prefer canonical merged endpoints; still include requests for any shapes missed
        raw_items = _safe_list(data.get("endpoints")) + _safe_list(data.get("captured_requests"))
    else:
        raise ValueError("❌ Invalid crawl_result.json format")

    # dedupe by rich signature
    seen = set()
    deduped: List[Any] = []
    for ep in raw_items:
        if not ep:
            continue
        url = _get(ep, "url", "")
        if not url:
            continue
        sig = normalize_signature(ep)
        if sig in seen:
            continue
        seen.add(sig)
        deduped.append(ep)

    # group buckets
    grouped: Dict[str, List[Dict[str, Any]]] = {
        "SQLi_Candidates": [],
        "XSS_Candidates": [],
        "Redirects": [],
        "IDOR_Candidates": [],
        "Token_Endpoints": [],
        "Auth_Login": [],
        "Uploads": [],
        "GraphQL": [],
        "Static": [],
        "Static_Asset": [],
        "Uncategorized": []
    }

    categorized: List[Dict[str, Any]] = []
    for ep in deduped:
        result = categorize_endpoint(ep)
        categorized.append(result)

        if "SQLi" in result["vuln_type_candidates"]:
            grouped["SQLi_Candidates"].append(result)
        if "XSS" in result["vuln_type_candidates"] or "Stored_XSS" in result["vuln_type_candidates"]:
            grouped["XSS_Candidates"].append(result)
        if "Redirect" in result["vuln_type_candidates"]:
            grouped["Redirects"].append(result)
        if "IDOR" in result["vuln_type_candidates"]:
            grouped["IDOR_Candidates"].append(result)
        if "CSRF" in result["vuln_type_candidates"]:
            grouped["Token_Endpoints"].append(result)
        if "Auth_Login" in result["categories"]:
            grouped["Auth_Login"].append(result)
        if "POST_Multipart_Upload" in result["categories"]:
            grouped["Uploads"].append(result)
        if "GraphQL" in result["categories"]:
            grouped["GraphQL"].append(result)
        if "Static_or_Display_Only" in result["categories"]:
            grouped["Static"].append(result)
        if "Static_Asset" in result["categories"]:
            grouped["Static_Asset"].append(result)
        if "Uncategorized" in result["categories"]:
            grouped["Uncategorized"].append(result)

    # summarize counts
    summary_counts = {k: len(v) for k, v in grouped.items()}
    total = len(categorized)

    host = urlparse(target_url).netloc.replace(":", "_") or "output"
    output_file = output_dir / host / "categorized_endpoints.json"
    output_file.parent.mkdir(parents=True, exist_ok=True)

    output_payload = {
        "target": target_url,
        "total": total,
        "family_router_available": _HAS_FAMILY_ROUTER,
        "summary_counts": summary_counts,
        "groups": grouped
    }

    with output_file.open("w", encoding="utf-8") as outfile:
        json.dump(output_payload, outfile, indent=2)

    print(f"✅ Grouped & categorized {total} distinct endpoint variants → {output_file}")
