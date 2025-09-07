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