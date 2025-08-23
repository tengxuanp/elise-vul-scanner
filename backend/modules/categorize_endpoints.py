# backend/modules/categorize_endpoints.py
from __future__ import annotations

import json
import re
from typing import List, Dict, Any, Tuple
from pathlib import Path
from urllib.parse import urlparse, parse_qs

# ---- helpers ---------------------------------------------------------------

STATIC_EXTENSIONS = (
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".map", ".json", ".txt", ".md"
)

REDIRECT_PARAM_NAMES = {"to", "url", "next", "dest", "redirect", "redirect_uri", "return", "continue"}
UPLOAD_PARAM_HINTS = {"file", "files", "upload", "image", "avatar", "photo", "filename"}
GRAPHQL_PATH_HINTS = {"/graphql"}
GRAPHQL_BODY_KEYS = {"query", "operationName", "variables"}

SQLI_HINTS = {"q", "query", "search", "id", "ids", "item", "product", "user", "uid", "order", "orderby", "sort"}
XSS_HINTS = {"comment", "message", "content", "text", "name", "title", "feedback", "body", "desc", "description"}

GQL_QUERY_RE = re.compile(r"\b(query|mutation|subscription)\b", re.I)

def is_static_asset(url: str) -> bool:
    try:
        return urlparse(url).path.lower().endswith(STATIC_EXTENSIONS)
    except Exception:
        return False

def _safe_list(val) -> List[str]:
    return list(val) if isinstance(val, (list, tuple)) else []

def extract_query_param_keys(ep: Dict[str, Any]) -> List[str]:
    """
    Preference order:
      1) canonical 'query_keys' (from merged endpoints)
      2) 'query_params' (from captured requests)
      3) parse URL query
    """
    if isinstance(ep.get("query_keys"), list):
        return sorted(set(_safe_list(ep.get("query_keys"))))
    if isinstance(ep.get("query_params"), list):
        return sorted(set(_safe_list(ep.get("query_params"))))
    url = ep.get("url", "")
    try:
        return sorted(set(parse_qs(urlparse(url).query).keys()))
    except Exception:
        return []

def extract_body_param_keys(ep: Dict[str, Any]) -> List[str]:
    """
    Preference order:
      1) canonical 'body_keys'
      2) 'param_locs'.body
      3) parsed dict keys from 'body_parsed'
      4) best-effort parse of 'post_data' (x-www-form-urlencoded)
    """
    if isinstance(ep.get("body_keys"), list):
        return sorted(set(_safe_list(ep.get("body_keys"))))
    if isinstance(ep.get("param_locs"), dict) and isinstance(ep["param_locs"].get("body"), list):
        return sorted(set(_safe_list(ep["param_locs"]["body"])))
    bp = ep.get("body_parsed")
    if isinstance(bp, dict):
        return sorted(set(bp.keys()))
    pd = ep.get("post_data")
    if isinstance(pd, str) and pd:
        try:
            return sorted(set(parse_qs(pd).keys()))
        except Exception:
            return []
    return []

def detect_content_type(ep: Dict[str, Any]) -> str | None:
    """
    Normalize to one of: 'application/json', 'application/x-www-form-urlencoded',
                         'multipart/form-data', None/other
    Preference:
      - 'content_type' (from merged endpoints)
      - map from 'body_type' (json|form)
      - infer from 'enctype'
    """
    ct = (ep.get("content_type") or "").lower().strip() or None
    if ct:
        if "json" in ct:
            return "application/json"
        if "x-www-form-urlencoded" in ct or "form-urlencoded" in ct:
            return "application/x-www-form-urlencoded"
        if "multipart/form-data" in ct or "multipart" in ct:
            return "multipart/form-data"
        return ct

    bt = (ep.get("body_type") or "").lower().strip()
    if bt == "json":
        return "application/json"
    if bt == "form":
        return "application/x-www-form-urlencoded"

    enctype = (ep.get("enctype") or "").lower().strip()
    if enctype:
        if "json" in enctype:
            return "application/json"
        if "multipart" in enctype:
            return "multipart/form-data"
        if "form" in enctype or "x-www-form-urlencoded" in enctype:
            return "application/x-www-form-urlencoded"

    return None

def normalize_signature(ep: Dict[str, Any]) -> Tuple[str, str, Tuple[str, ...], str | None, Tuple[str, ...]]:
    """
    Dedupe signature:
      (METHOD, PATH, sorted(query_param_keys), content_type, sorted(body_param_keys))
    """
    url = ep.get("url", "")
    method = (ep.get("method") or "GET").upper()
    parsed = urlparse(url)
    q_keys = tuple(extract_query_param_keys(ep))
    b_keys = tuple(extract_body_param_keys(ep))
    content_type = detect_content_type(ep)
    return (method, parsed.path, q_keys, content_type, b_keys)

def smart_param_sources(ep: Dict[str, Any]) -> Dict[str, List[str]]:
    """
    Return a clean split of params by source. Prefer canonical param_locs if present.
    """
    if isinstance(ep.get("param_locs"), dict):
        locs = ep["param_locs"]
        return {
            "query": sorted(set(_safe_list(locs.get("query")))),
            "body": sorted(set(_safe_list(locs.get("body")))),
        }
    return {
        "query": extract_query_param_keys(ep),
        "body": extract_body_param_keys(ep)
    }

def looks_like_graphql(ep: Dict[str, Any], path: str, body_keys: List[str], body_parsed: Dict[str, Any] | None) -> bool:
    if any(path.endswith(p) for p in GRAPHQL_PATH_HINTS):
        return True
    if set(body_keys) & GRAPHQL_BODY_KEYS:
        q = ""
        try:
            q = (body_parsed or {}).get("query", "")
        except Exception:
            q = ""
        if isinstance(q, str) and GQL_QUERY_RE.search(q):
            return True
    return False

def is_upload_endpoint(content_type: str | None, body_keys: List[str]) -> bool:
    if content_type and "multipart/form-data" in content_type:
        return True
    return any(k.lower() in UPLOAD_PARAM_HINTS for k in body_keys)

# ---- categorization --------------------------------------------------------

def categorize_endpoint(endpoint: Dict[str, Any]) -> Dict[str, Any]:
    url: str = endpoint.get("url", "")
    method: str = (endpoint.get("method") or "GET").upper()
    path: str = urlparse(url).path
    is_login: bool = bool(endpoint.get("is_login", False))
    csrf_params: List[str] = [p for p in (endpoint.get("csrf_params") or []) if p]

    # param sources (prefer canonical)
    param_sources = smart_param_sources(endpoint)
    params_all = sorted(set(param_sources["query"]) | set(param_sources["body"]))

    content_type = detect_content_type(endpoint)
    body_parsed = endpoint.get("body_parsed") if isinstance(endpoint.get("body_parsed"), dict) else None
    body_keys = param_sources["body"]

    categories: List[str] = []
    vuln_candidates: List[str] = []

    # Static assets
    if is_static_asset(url):
        categories.append("Static_Asset")

    # Basic method/param/content-type shape
    if method == "GET":
        categories.append("GET_with_params" if params_all else "GET_no_params")
    elif method == "POST":
        if is_upload_endpoint(content_type, body_keys):
            categories.append("POST_Multipart_Upload")
        elif content_type == "application/json":
            categories.append("POST_JSON_with_params" if body_keys else "POST_JSON_no_params")
        elif content_type == "application/x-www-form-urlencoded" or content_type is None:
            categories.append("POST_FORM_with_params" if body_keys else "POST_no_params")
        else:
            categories.append("POST_other")

    # GraphQL
    if looks_like_graphql(endpoint, path, body_keys, body_parsed):
        categories.append("GraphQL")
        # GraphQL is less SQLi-prone at SQL layer but still can have injections in resolvers—don’t pre-judge.

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
    if is_upload_endpoint(content_type, body_keys):
        vuln_candidates.append("File_Upload")

    # Fallback categories
    if not params_all and "Static_Asset" not in categories:
        categories.append("Static_or_Display_Only")
    if not categories:
        categories.append("Uncategorized")

    # dedupe candidates
    vuln_candidates = sorted(set(vuln_candidates))
    categories = sorted(set(categories))

    return {
        "url": url,
        "path": path,
        "method": method,
        "params": params_all,
        "param_sources": param_sources,        # {"query": [...], "body": [...]}
        "param_locs": endpoint.get("param_locs") if isinstance(endpoint.get("param_locs"), dict) else param_sources,
        "content_type": content_type,
        "categories": categories,
        "vuln_type_candidates": vuln_candidates,
        "tested": False,
        "is_login": is_login,
        "csrf_params": csrf_params
    }

# ---- main processing -------------------------------------------------------

def process_crawl_results(input_path: Path, output_dir: Path, target_url: str):
    """
    Reads crawl_result.json:
      - new shape: {"endpoints": [...], "captured_requests": [...]}
      - legacy shape: flat list of endpoints/requests
    Keeps distinct endpoint *variants* by (method, path, query_keys, content_type, body_keys),
    categorizes them, and writes grouped output per host.
    """
    if not input_path.exists():
        raise FileNotFoundError(f"❌ Input file not found: {input_path}")

    with input_path.open("r", encoding="utf-8") as infile:
        data = json.load(infile)

    # normalize the raw list
    if isinstance(data, list):
        raw_items = data
    elif isinstance(data, dict):
        # Prefer canonical merged endpoints; still include requests for any shapes missed
        raw_items = _safe_list(data.get("endpoints")) + _safe_list(data.get("captured_requests"))
    else:
        raise ValueError("❌ Invalid crawl_result.json format")

    # dedupe by rich signature
    seen = set()
    deduped: List[Dict[str, Any]] = []
    for ep in raw_items:
        if not ep or not ep.get("url"):
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
        "summary_counts": summary_counts,
        "groups": grouped
    }

    with output_file.open("w", encoding="utf-8") as outfile:
        json.dump(output_payload, outfile, indent=2)

    print(f"✅ Grouped & categorized {total} distinct endpoint variants → {output_file}")
