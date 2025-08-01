import json
import re
from typing import List, Dict, Any
from pathlib import Path
from urllib.parse import urlparse, parse_qs

def extract_params_from_url(url: str) -> List[str]:
    parsed = urlparse(url)
    return list(parse_qs(parsed.query).keys())

def categorize_endpoint(endpoint: Dict[str, Any]) -> Dict[str, Any]:
    url = endpoint.get("url", "")
    method = endpoint.get("method", "GET").upper()
    raw_params = endpoint.get("params", [])
    headers = endpoint.get("headers", {})
    post_data = endpoint.get("post_data", "")

    parsed_params = set(raw_params)
    parsed_params.update(extract_params_from_url(url))

    if post_data and isinstance(post_data, str):
        try:
            post_fields = parse_qs(post_data)
            parsed_params.update(post_fields.keys())
        except:
            pass

    params = sorted(parsed_params)
    categories = []
    vuln_candidates = []

    static_extensions = (
        ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
        ".woff", ".woff2", ".ttf", ".map", ".json", ".txt", ".md"
    )
    if url.lower().endswith(static_extensions):
        categories.append("Static_Asset")

    if method == "GET" and params:
        categories.append("GET_with_params")
        if any(p.lower() in {"q", "search", "id", "query"} for p in params):
            vuln_candidates += ["SQLi", "XSS"]

    elif method == "POST" and params:
        categories.append("POST_with_params")
        if any(p.lower() in {"comment", "message", "email", "name"} for p in params):
            vuln_candidates.append("Stored_XSS")
        if any("query" in p.lower() for p in params):
            vuln_candidates.append("SQLi")

    if "redirect" in url.lower() and any(p.lower() in {"to", "url", "next", "dest", "redirect_uri"} for p in params):
        categories.append("Open_Redirect")
        vuln_candidates.append("Redirect")

    if re.search(r"/\d{3,}", url):
        categories.append("IDOR_candidate")
        vuln_candidates.append("IDOR")

    if any("token" in p.lower() for p in params):
        categories.append("Token_Sensitive")
        vuln_candidates.append("CSRF")

    if not params:
        categories.append("Static_or_Display_Only")

    if not categories:
        categories.append("Uncategorized")

    return {
        "url": url,
        "method": method,
        "params": params,
        "categories": categories,
        "vuln_type_candidates": sorted(set(vuln_candidates)),
        "tested": False
    }

def process_crawl_results(input_path: Path, output_dir: Path, target_url: str):
    if not input_path.exists():
        raise FileNotFoundError(f"❌ Input file not found: {input_path}")

    with input_path.open("r", encoding="utf-8") as infile:
        data = json.load(infile)

    if isinstance(data, list):
        raw_endpoints = data
    elif isinstance(data, dict):
        raw_endpoints = data.get("endpoints", []) + data.get("captured_requests", [])
    else:
        raise ValueError("❌ Invalid crawl_result.json format")

    seen = set()
    deduped = []
    for ep in raw_endpoints:
        url = ep.get("url", "")
        method = ep.get("method", "GET").upper()
        sig = (method, urlparse(url).path)
        if sig not in seen:
            seen.add(sig)
            deduped.append(ep)

    grouped = {
        "SQLi_Candidates": [],
        "XSS_Candidates": [],
        "Redirects": [],
        "IDOR_Candidates": [],
        "Token_Endpoints": [],
        "Static": [],
        "Static_Asset": [],
        "Uncategorized": []
    }

    for ep in deduped:
        result = categorize_endpoint(ep)
        if "SQLi" in result["vuln_type_candidates"]:
            grouped["SQLi_Candidates"].append(result)
        if "XSS" in result["vuln_type_candidates"]:
            grouped["XSS_Candidates"].append(result)
        if "Redirect" in result["vuln_type_candidates"]:
            grouped["Redirects"].append(result)
        if "IDOR" in result["vuln_type_candidates"]:
            grouped["IDOR_Candidates"].append(result)
        if "CSRF" in result["vuln_type_candidates"]:
            grouped["Token_Endpoints"].append(result)
        if "Static_or_Display_Only" in result["categories"]:
            grouped["Static"].append(result)
        if "Static_Asset" in result["categories"]:
            grouped["Static_Asset"].append(result)
        if "Uncategorized" in result["categories"]:
            grouped["Uncategorized"].append(result)

    host = urlparse(target_url).netloc.replace(":", "_")
    output_file = output_dir / host / "categorized_endpoints.json"
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with output_file.open("w", encoding="utf-8") as outfile:
        json.dump({"target": target_url, "total": len(deduped), "grouped": grouped}, outfile, indent=2)

    print(f"✅ Grouped & categorized {len(deduped)} endpoints → {output_file}")
