# backend/modules/injectors.py
from __future__ import annotations

"""
Utilities to inject payloads into HTTP requests in a consistent, typed way.

This module deliberately avoids making network calls. It only *constructs*
a request plan (method, URL, headers, data/json) after placing a payload
into a particular parameter *location* (query | form | json).

Why this exists
---------------
Different parts of the system (crawlers, fuzzers, verifiers) need a single,
bug-free way to:
  - Put a payload into a query param without corrupting other params.
  - Put a payload into a form or JSON body (when body_type is known).
  - Choose the best parameter *location* based on `param_locs` hints.
  - Apply simple encodings (raw, url-encoded, double-url-encoded, html-escaped).

The functions here are pure and side-effect free. They never mutate caller
inputs (headers/body), always returning copies.

Return conventions
------------------
`prepare_injected_request(...)` returns a `dict` shaped like:

{
  "method": "GET" | "POST" | ...,
  "url": "<final url>",
  "headers": {...},                      # normalized copy (never None)
  "data": { ... } | None,               # form body (when body_type="form")
  "json": { ... } | None,               # JSON body (when body_type="json")
  "location": "query" | "form" | "json",
  "encoding": "identity" | "url" | "url2" | "html" | "js",
}

which you can pass directly to an HTTP client (e.g., httpx.request(**plan)):

httpx.request(
    plan["method"], plan["url"],
    headers=plan["headers"],
    data=plan["data"], json=plan["json"]
)

Notes
-----
- If `location` is not specified, we try to infer it from `param_locs`, or
  we fall back to "query".
- If `body_type` is not one of {"form","json"}, we do not touch the body.
- We never attempt to rewrite raw string bodies; callers should convert them
  to dicts for "form" or "json" if they want body injection.

"""

from dataclasses import dataclass
from html import escape as html_escape
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse, quote as url_quote
import copy


# ----------------------------- public API ------------------------------------

__all__ = [
    "encode_payload",
    "inject_query_value",
    "inject_form_value",
    "inject_json_value",
    "choose_locations",
    "prepare_injected_request",
    "build_injection_plans",
    "InjectionPlan",
]


# ----------------------------- encoders --------------------------------------


def encode_payload(payload: str, encoding: str = "identity") -> str:
    """
    Return a transformed payload according to `encoding`.

    Supported encodings:
      - "identity" : return as-is
      - "url"      : percent-encode once (RFC3986; no safe chars)
      - "url2"     : double percent-encode
      - "html"     : HTML-escape (&, <, >, ", ')
      - "js"       : JS string-escape (simple; backslash + quotes + control)

    Unknown encodings fall back to identity.
    """
    p = payload if isinstance(payload, str) else str(payload)

    if encoding == "identity":
        return p
    if encoding == "url":
        return url_quote(p, safe="")
    if encoding == "url2":
        return url_quote(url_quote(p, safe=""), safe="")
    if encoding == "html":
        return html_escape(p, quote=True)
    if encoding == "js":
        # Very small JS-string escape for inline usage. For rigorous escaping,
        # consider a full JS escaper; this is sufficient for detector probes.
        out = []
        for ch in p:
            o = ord(ch)
            if ch in {'\\', '"', "'"}:
                out.append("\\" + ch)
            elif o < 0x20:
                out.append("\\x%02x" % o)
            else:
                out.append(ch)
        return "".join(out)

    # default
    return p


# ----------------------------- low-level injectors ---------------------------

def _rebuild_url_with_query(url: str, pairs: List[Tuple[str, str]]) -> str:
    up = urlparse(url)
    q = urlencode(pairs, doseq=True)
    return urlunparse((up.scheme, up.netloc, up.path, up.params, q, up.fragment))


def inject_query_value(url: str, param: str, value: str) -> str:
    """
    Replace (or append) a single query parameter's value in the URL.
    - preserves other params and fragments
    - preserves order except the replaced/added item goes to the end
    """
    up = urlparse(url)
    existing = [(k, v) for (k, v) in parse_qsl(up.query, keep_blank_values=True) if k != param]
    existing.append((param, value))
    return _rebuild_url_with_query(url, existing)


def inject_form_value(form: Optional[Dict[str, Any]], param: str, value: Any) -> Dict[str, Any]:
    """
    Return a new dict representing application/x-www-form-urlencoded body
    with `param` set to `value`. If form is None, start from {}.
    """
    d = dict(form or {})
    d[param] = value
    return d


def _set_in_flat_json(d: Dict[str, Any], key: str, value: Any) -> Dict[str, Any]:
    """
    Set d[key] = value (shallow).
    """
    out = dict(d)
    out[key] = value
    return out


def _set_in_path_json(d: Dict[str, Any], path: List[str], value: Any) -> Dict[str, Any]:
    """
    Set a nested path like ["user", "profile", "name"] to value,
    returning a deep-copied dict. Creates nested dicts as needed.
    """
    out = copy.deepcopy(d)
    cur = out
    for k in path[:-1]:
        nxt = cur.get(k)
        if not isinstance(nxt, dict):
            nxt = {}
        cur[k] = nxt
        cur = nxt
    cur[path[-1]] = value
    return out


def inject_json_value(js: Optional[Dict[str, Any]], param: str, value: Any) -> Dict[str, Any]:
    """
    Return a new dict representing application/json body with `param` set to value.

    Supports nested "dot notation" (e.g., "user.profile.name") creating objects
    as needed.
    """
    d = dict(js or {})
    if "." in param:
        path = [p for p in param.split(".") if p]
        if not path:
            return d
        return _set_in_path_json(d, path, value)
    return _set_in_flat_json(d, param, value)


# ----------------------------- location chooser ------------------------------

def choose_locations(
    param: str,
    param_locs: Optional[Dict[str, Iterable[str]]] = None,
    preferred: Optional[str] = None,
) -> List[str]:
    """
    Decide which locations to try for injecting `param`.

    Returns a list composed from {"query","form","json"}.

    Priority rules:
      1) If `preferred` is provided and valid, return [preferred].
      2) If param_locs is provided and includes param in a location, keep those
         locations in the order query -> form -> json (stable).
      3) Fallback to ["query"].
    """
    valid = {"query", "form", "json"}
    if preferred and preferred in valid:
        return [preferred]

    hits: List[str] = []
    if isinstance(param_locs, dict):
        if param in set(map(str, (param_locs.get("query") or []))):
            hits.append("query")
        if param in set(map(str, (param_locs.get("form") or []))):
            hits.append("form")
        if param in set(map(str, (param_locs.get("json") or []))):
            hits.append("json")

    if hits:
        # stable order
        order = ["query", "form", "json"]
        return [h for h in order if h in hits]

    return ["query"]


# ----------------------------- request planner -------------------------------

@dataclass(frozen=True)
class InjectionPlan:
    method: str
    url: str
    headers: Dict[str, str]
    data: Optional[Dict[str, Any]]
    json: Optional[Dict[str, Any]]
    location: str               # "query" | "form" | "json"
    encoding: str               # "identity" | "url" | "url2" | "html" | "js"
    param: str
    payload: str


def prepare_injected_request(
    *,
    method: str,
    url: str,
    param: str,
    payload: str,
    param_locs: Optional[Dict[str, Iterable[str]]] = None,
    preferred_location: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
    body: Optional[Dict[str, Any]] = None,
    body_type: Optional[str] = None,  # "form" | "json" | None
    encoding: str = "identity",
) -> InjectionPlan:
    """
    Build a single InjectionPlan with the payload placed in the chosen location.

    - Respects `param_locs` if available (or `preferred_location` if provided).
    - Applies `encoding` to the payload *before* insertion.
    - If body_type is not compatible with the chosen location, we fall back to "query".
    """
    method_u = (method or "GET").upper()
    hdrs = dict(headers or {})

    # Decide location
    locs = choose_locations(param, param_locs, preferred=preferred_location)
    loc = locs[0] if locs else "query"

    # Encode the payload
    encoded = encode_payload(payload, encoding=encoding)

    # Place into request based on location
    final_url = url
    form_data: Optional[Dict[str, Any]] = None
    json_data: Optional[Dict[str, Any]] = None

    if loc == "form" and (body_type or "").lower() == "form":
        form_data = inject_form_value(body if isinstance(body, dict) else {}, param, encoded)
    elif loc == "json" and (body_type or "").lower() == "json":
        json_data = inject_json_value(body if isinstance(body, dict) else {}, param, encoded)
    else:
        # Fallback to query (covers: unknown body_type, GET, or when requested location isn't compatible)
        final_url = inject_query_value(url, param, encoded)
        loc = "query"

    return InjectionPlan(
        method=method_u,
        url=final_url,
        headers=hdrs,
        data=form_data,
        json=json_data,
        location=loc,
        encoding=encoding,
        param=param,
        payload=payload,
    )


def build_injection_plans(
    *,
    method: str,
    url: str,
    param: str,
    payload: str,
    param_locs: Optional[Dict[str, Iterable[str]]] = None,
    headers: Optional[Dict[str, str]] = None,
    body: Optional[Dict[str, Any]] = None,
    body_type: Optional[str] = None,  # "form" | "json" | None
    preferred_location: Optional[str] = None,
    encodings: Optional[Iterable[str]] = None,
) -> List[InjectionPlan]:
    """
    Build a *small* set of plans varying the encoding while keeping the location stable.

    Parameters
    ----------
    - param_locs: if present, we choose the first applicable location
    - preferred_location: force a location ("query"|"form"|"json")
    - encodings: iterable of encodings to try. Default: ["identity","url","html"]

    Returns
    -------
    List[InjectionPlan] in a sensible order (identity -> url -> html -> url2 -> js).
    """
    encs = list(encodings or ["identity", "url", "html"])
    # Normalize set/order a bit
    canonical_order = ["identity", "url", "html", "url2", "js"]
    encs = [e for e in canonical_order if e in set(encs)]

    out: List[InjectionPlan] = []
    for enc in encs:
        out.append(
            prepare_injected_request(
                method=method,
                url=url,
                param=param,
                payload=payload,
                param_locs=param_locs,
                preferred_location=preferred_location,
                headers=headers,
                body=body,
                body_type=body_type,
                encoding=enc,
            )
        )
    return out


# ----------------------------- tiny demo (manual) ----------------------------

if __name__ == "__main__":  # pragma: no cover
    demo_url = "https://example.test/search?q=hello&page=1"
    plans = build_injection_plans(
        method="GET",
        url=demo_url,
        param="q",
        payload="' OR 1=1 --",
        param_locs={"query": ["q"]},
        headers={"X-Demo": "1"},
    )
    for p in plans:
        print(p.encoding, p.location, p.url)
