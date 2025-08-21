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

def is_static_asset(url: str) -> bool:
    return url.lower().endswith(STATIC_EXTENSIONS)

def extract_query_param_keys(url: str) -> List[str]:
    parsed = urlparse(url)
    return list(parse_qs(parsed.query).keys())

def extract_body_param_keys(endpoint: Dict[str, Any]) -> List[str]:
    """
    Prefer crawler-parsed body keys (body_parsed), otherwise attempt to parse post_data (form).
    """
    keys: List[str] = []
    body_parsed = endpoint.get("body_parsed")
    if isinstance(body_parsed, dict):
        keys = list(body_parsed.keys())
    else:
        post_data = endpoint.get("post_data")
        if isinstance(post_data, str) and post_data:
            try:
                # best-effort for x-www-form-urlencoded
                keys = list(parse_qs(post_data).keys())
            except Exception:
                keys = []
    return keys

def normalize_signature(ep: Dict[str, Any]) -> Tuple[str, str, Tuple[str, ...], str, Tuple[str, ...]]:
    """
    Dedupe signature:
      (METHOD, PATH, sorted(query_param_keys), body_type, sorted(body_param_keys))
    """
    url = ep.get("url", "")
    method = (ep.get("method") or "GET").upper()
    parsed = urlparse(url)
    q_keys = tuple(sorted(set(extract_query_param_keys(url) + (ep.get("params") or []))))
    body_type = (ep.get("body_type") or "").lower()
    b_keys = tuple(sorted(set(extract_body_param_keys(ep))))
    return (method, parsed.path, q_keys, body_type, b_keys)

def smart_params_union(ep: Dict[str, Any]) -> Dict[str, List[str]]:
    """
    Return a clean split of params by source.
    """
    params_query = set(extract_query_param_keys(ep.get("url", "")))
    # legacy 'params' field (from forms) is often "all inputs"; keep them but do not overwrite
    legacy = ep.get("params") or []
    params_query.update([p for p in legacy if p and p not in params_query])

    params_body = set(extract_body_param_keys(ep))
    return {
        "query": sorted(params_query),
        "body": sorted(params_body)
    }

# ---- categorization --------------------------------------------------------

def categorize_endpoint(endpoint: Dict[str, Any]) -> Dict[str, Any]:
    url: str = endpoint.get("url", "")
    method: str = (endpoint.get("method") or "GET").upper()
    is_login: bool = bool(endpoint.get("is_login", False))
    csrf_params: List[str] = [p for p in (endpoint.get("csrf_params") or []) if p]

    # param sources
    param_sources = smart_params_union(endpoint)
    params_all = sorted(set(param_sources["query"]) | set(param_sources["body"]))

    categories: List[str] = []
    vuln_candidates: List[str] = []

    # Static assets
    if is_static_asset(url):
        categories.append("Static_Asset")

    # Basic method/param shape
    if method == "GET":
        if params_all:
            categories.append("GET_with_params")
        else:
            categories.append("GET_no_params")
    elif method == "POST":
        body_type = (endpoint.get("body_type") or "").lower()
        if param_sources["body"]:
            if body_type == "json":
                categories.append("POST_JSON_with_params")
            elif body_type == "form" or body_type == "":
                categories.append("POST_FORM_with_params")
            else:
                categories.append("POST_other_with_params")
        else:
            categories.append("POST_no_params")

    # Heuristics: likely vulns based on param names and path
    lower_params = [p.lower() for p in params_all]

    # SQLi candidates: search-like or identifier params, works for both GET/POST
    if any(p in {"q", "query", "search", "id", "ids", "item", "product", "user", "uid"} for p in lower_params):
        vuln_candidates.append("SQLi")

    # XSS: user-controlled text fields
    if any(p in {"comment", "message", "content", "text", "name", "title", "feedback"} for p in lower_params):
        vuln_candidates.append("XSS")

    # Stored XSS more likely on POST text fields
    if method == "POST" and any(p in {"comment", "message", "content"} for p in lower_params):
        vuln_candidates.append("Stored_XSS")

    # Open Redirect
    if any(p in REDIRECT_PARAM_NAMES for p in lower_params) or "redirect" in url.lower():
        categories.append("Open_Redirect")
        vuln_candidates.append("Redirect")

    # IDOR: numeric id segments in path
    if re.search(r"/\d{3,}(/|$)", url):
        categories.append("IDOR_candidate")
        vuln_candidates.append("IDOR")

    # Token/CSRF handling
    if csrf_params or any("token" in p or "csrf" in p for p in lower_params):
        categories.append("Token_Sensitive")
        vuln_candidates.append("CSRF")

    # Login/auth
    if is_login or re.search(r"/login|/signin|/auth", url.lower()):
        categories.append("Auth_Login")

    # Fallback categories
    if not params_all and "Static_Asset" not in categories:
        categories.append("Static_or_Display_Only")
    if not categories:
        categories.append("Uncategorized")

    # dedupe candidates
    vuln_candidates = sorted(set(vuln_candidates))

    return {
        "url": url,
        "method": method,
        "params": params_all,
        "param_sources": param_sources,        # {"query": [...], "body": [...]}
        "body_type": (endpoint.get("body_type") or None),
        "categories": categories,
        "vuln_type_candidates": vuln_candidates,
        "tested": False,
        "is_login": is_login,
        "csrf_params": csrf_params
    }

# ---- main processing -------------------------------------------------------

def process_crawl_results(input_path: Path, output_dir: Path, target_url: str):
    """
    Reads crawl_result.json (either {"endpoints": [...], "captured_requests": [...]} or a flat list),
    keeps distinct endpoint *variants* (by method + path + param keys + body_type),
    categorizes them, and writes grouped output per host.
    """
    if not input_path.exists():
        raise FileNotFoundError(f"❌ Input file not found: {input_path}")

    with input_path.open("r", encoding="utf-8") as infile:
        data = json.load(infile)

    # normalize the raw list
    if isinstance(data, list):
        raw_endpoints = data
    elif isinstance(data, dict):
        # keep forms and captured XHR/fetch; both may contain body info
        raw_endpoints = (data.get("endpoints") or []) + (data.get("captured_requests") or [])
    else:
        raise ValueError("❌ Invalid crawl_result.json format")

    # dedupe by rich signature
    seen = set()
    deduped: List[Dict[str, Any]] = []
    for ep in raw_endpoints:
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
