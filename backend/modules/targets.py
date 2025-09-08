from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

@dataclass
class Target:
    url: str
    method: str
    param_in: str  # "query" | "form" | "json"
    param: str
    headers: Optional[Dict[str, str]] = None
    status: Optional[int] = None
    content_type: Optional[str] = None
    base_params: Optional[Dict[str, Any]] = None  # original params for that location

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_features(self) -> Dict[str, Any]:
        netloc = urlparse(self.url).netloc
        return {
            "method": self.method.upper(),
            "param_in": self.param_in,
            "content_type": (self.content_type or ""),
            "param_len": len(self.param or ""),
            "host": netloc,
            "status": int(self.status or 0),
        }

    def build_with_payload(self, payload: str) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
        params: Dict[str, Any] = {}
        data: Optional[Dict[str, Any]] = None
        json_body: Optional[Dict[str, Any]] = None
        base = dict(self.base_params or {})
        base[self.param] = payload
        if self.param_in == "query":
            params = base
        elif self.param_in == "form":
            data = base
        elif self.param_in == "json":
            json_body = base
        return params, data, json_body

def enumerate_targets_from_endpoints(endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Deterministic target enumeration from endpoints.
    For each endpoint, emit a target row for each parameter found in any location.
    """
    targets = []
    
    for endpoint in endpoints:
        method = str(endpoint.get("method", "GET")).upper()
        url = str(endpoint.get("url", ""))
        path = str(endpoint.get("path", ""))
        status = endpoint.get("status")
        content_type = endpoint.get("content_type")
        param_locs = endpoint.get("param_locs", {})
        
        # Extract parameter names from each location
        query_params = []
        form_params = []
        json_params = []
        
        # Handle param_locs structure
        if isinstance(param_locs, dict):
            # Extract names from Param objects, dicts, or strings
            def extract_param_name(p):
                if hasattr(p, 'name'):
                    return p.name
                elif isinstance(p, dict) and 'name' in p:
                    return p['name']
                else:
                    return str(p)
            
            query_params = [extract_param_name(p) for p in (param_locs.get("query") or [])]
            form_params = [extract_param_name(p) for p in (param_locs.get("form") or [])]
            json_params = [extract_param_name(p) for p in (param_locs.get("json") or [])]
        
        # Fallback: check legacy 'params' field
        if not any([query_params, form_params, json_params]) and isinstance(endpoint.get("params"), list):
            # Legacy format: params is a list of parameter names
            query_params = [str(p) for p in endpoint.get("params", [])]
        
        # Create targets for each parameter in each location
        for param_name in query_params:
            base_params = _build_query_base_params(url)
            targets.append({
                "url": url,
                "path": path,
                "method": method,
                "param_in": "query",
                "param": param_name,
                "headers": {},
                "status": status,
                "content_type": content_type,
                "base_params": base_params,
                "source": "persisted"
            })
        
        for param_name in form_params:
            targets.append({
                "url": url,
                "path": path,
                "method": method,
                "param_in": "form",
                "param": param_name,
                "headers": {},
                "status": status,
                "content_type": content_type,
                "base_params": {"__form_present__": True},
                "source": "persisted"
            })
        
        for param_name in json_params:
            targets.append({
                "url": url,
                "path": path,
                "method": method,
                "param_in": "json",
                "param": param_name,
                "headers": {},
                "status": status,
                "content_type": content_type,
                "base_params": {"__json_present__": True},
                "source": "persisted"
            })
    
    return targets


def _build_query_base_params(url: str) -> Dict[str, Any]:
    """Build base parameters for query string, preserving existing params."""
    from urllib.parse import urlparse, parse_qs
    
    try:
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        # Convert lists to single values and add sentinel for probed param
        base_params = {}
        for key, values in query_params.items():
            base_params[key] = values[0] if values else ""
        return base_params
    except Exception:
        return {}


def enumerate_targets(endpoint: Dict[str, Any]) -> Iterable[Target]:
    """Expand a crawled endpoint into concrete targets by param location."""
    _method = str(endpoint.get("method", "GET")).upper()
    url = str(endpoint.get("url") or endpoint.get("full_url") or endpoint.get("href") or "")
    status = endpoint.get("status")
    ctype = endpoint.get("content_type") or endpoint.get("contentType")
    headers = endpoint.get("headers") or {}
    param_locs = endpoint.get("param_locs") or {}
    results: List[Target] = []
    for loc in ("query", "form", "json"):
        params = (param_locs.get(loc) or []) if isinstance(param_locs, dict) else []
        for p in params:
            results.append(Target(url=url, method=_method, param_in=loc, param=p, headers=headers, status=status, content_type=ctype, base_params={}))
    # fallback: if legacy 'params' dict present
    if not results and isinstance(endpoint.get("params"), dict):
        for p in endpoint["params"].keys():
            results.append(Target(url=url, method=_method, param_in="query", param=p, headers=headers, status=status, content_type=ctype, base_params={}))
    return results