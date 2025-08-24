# backend/schemas.py
from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional
from enum import Enum
from urllib.parse import urlparse, urlunparse

from pydantic import BaseModel, Field, HttpUrl, field_validator, computed_field


# ------------------------------- core enums ---------------------------------

class HTTPMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


class PayloadFamily(str, Enum):
    # Keep this minimal for M0; extend later (sqli, open_redirect, etc.)
    XSS = "xss"


class XSSContext(str, Enum):
    RAW = "raw"              # literal reflection in HTML text
    HTML_ESCAPED = "html"    # reflected but escaped
    ATTR = "attr"            # attribute value context
    JS = "js"                # inside a JS string / script context
    ENCODED = "encoded"      # URL-encoded / HTML entity encoded
    DOM = "dom"              # client-side DOM sink observed (future)


# ------------------------------- auth config --------------------------------

class AuthMode(str, Enum):
    NONE = "none"
    COOKIE = "cookie"
    BASIC = "basic"
    BEARER = "bearer"
    FORM = "form"  # optional: scripted login; not required for M0


class AuthConfig(BaseModel):
    """
    Minimal auth for M0: cookie header passthrough is enough for Juice Shop.
    """
    mode: AuthMode = Field(default=AuthMode.NONE)
    cookie: Optional[str] = Field(
        default=None,
        description="Full Cookie header value e.g. 'sid=abc; jwt=eyJ...; theme=dark'"
    )
    basic_username: Optional[str] = None
    basic_password: Optional[str] = None
    bearer_token: Optional[str] = None
    # FORM mode fields can be added later (login url, selectors, creds, etc.)

    @field_validator("cookie")
    @classmethod
    def strip_cookie(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        s = v.strip()
        return s if s else None


# ------------------------------ parameter model -----------------------------

class Param(BaseModel):
    """
    A single fuzzable parameter identifier. For M0 we only need the name.
    'value' can seed baseline requests if you captured it; optional.
    """
    name: str = Field(..., min_length=1, description="Parameter key")
    value: Optional[str] = Field(default=None, description="Observed baseline value (optional)")
    required: bool = Field(default=False)
    priority: int = Field(default=0, description="Higher means fuzz earlier")
    notes: Optional[str] = None

    @field_validator("name")
    @classmethod
    def normalize_name(cls, v: str) -> str:
        return v.strip()


class ParamLocs(BaseModel):
    """
    Unified parameter carrier across pipeline.
    Keys are FIXED and exhaustive for M0: query, form, json.
    """
    query: List[Param] = Field(default_factory=list)
    form: List[Param]  = Field(default_factory=list)
    json: List[Param]  = Field(default_factory=list)

    @computed_field  # type: ignore[prop-decorator]
    def all_names(self) -> Dict[str, List[str]]:
        return {
            "query": [p.name for p in self.query],
            "form":  [p.name for p in self.form],
            "json":  [p.name for p in self.json],
        }

    @field_validator("query", "form", "json")
    @classmethod
    def dedupe_by_name(cls, v: List[Param]) -> List[Param]:
        seen = set()
        out: List[Param] = []
        for p in v:
            if p.name not in seen:
                seen.add(p.name)
                out.append(p)
        return out


# ----------------------------- endpoint shape -------------------------------

class EndpointOut(BaseModel):
    """
    Normalized, dedup-friendly endpoint emitted by the crawler/target builder.
    - url MUST NOT include a hash fragment.
    - origin/path are derived for UI and dedup keys.
    """
    method: HTTPMethod
    url: HttpUrl
    headers: Dict[str, str] = Field(default_factory=dict)
    param_locs: ParamLocs = Field(default_factory=ParamLocs)
    content_type_hint: Optional[str] = Field(
        default=None, description="Best-guess content-type for the baseline endpoint"
    )

    @field_validator("url")
    @classmethod
    def strip_fragment(cls, v: HttpUrl) -> HttpUrl:
        # remove #fragment to avoid SPA pseudo-URLs becoming endpoints
        parts = list(urlparse(str(v)))
        parts[5] = ""  # fragment
        clean = urlunparse(parts)
        return HttpUrl(clean)

    @field_validator("headers")
    @classmethod
    def lower_header_keys(cls, v: Dict[str, str]) -> Dict[str, str]:
        return {str(k).lower(): str(vv) for k, vv in (v or {}).items()}

    @computed_field  # type: ignore[prop-decorator]
    def origin(self) -> str:
        u = urlparse(str(self.url))
        return f"{u.scheme}://{u.netloc}"

    @computed_field  # type: ignore[prop-decorator]
    def path(self) -> str:
        return urlparse(str(self.url)).path or "/"

    @computed_field  # type: ignore[prop-decorator]
    def shape_key(self) -> str:
        """
        Stable dedup key: METHOD|PATH|Q=[sorted]|F=[sorted]|J=[sorted]
        """
        q = ",".join(sorted(self.param_locs.all_names["query"]))
        f = ",".join(sorted(self.param_locs.all_names["form"]))
        j = ",".join(sorted(self.param_locs.all_names["json"]))
        return f"{self.method}|{self.path}|Q=[{q}]|F=[{f}]|J=[{j}]"


# ---------------------------- fuzzing input (M0) -----------------------------

class FuzzTargets(BaseModel):
    """
    User-selected subset of parameter names to fuzz for each location.
    """
    query: List[str] = Field(default_factory=list)
    form: List[str]  = Field(default_factory=list)
    json: List[str]  = Field(default_factory=list)

    @field_validator("query", "form", "json")
    @classmethod
    def strip_names(cls, v: List[str]) -> List[str]:
        return [s.strip() for s in v if s and s.strip()]


class TestCaseIn(BaseModel):
    """
    Concrete fuzz test case derived from an EndpointOut + FuzzTargets.
    The fuzzer will create mutated requests for each selected parameter.
    """
    job_id: str
    method: HTTPMethod
    url: HttpUrl
    headers: Dict[str, str] = Field(default_factory=dict)
    param_locs: ParamLocs = Field(default_factory=ParamLocs)
    targets: FuzzTargets = Field(default_factory=FuzzTargets)
    payload_family: PayloadFamily = Field(default=PayloadFamily.XSS)
    timeout_s: float = Field(default=12.0, ge=1.0, le=60.0)

    @field_validator("url")
    @classmethod
    def strip_fragment(cls, v: HttpUrl) -> HttpUrl:
        parts = list(urlparse(str(v)))
        parts[5] = ""  # fragment
        clean = urlunparse(parts)
        return HttpUrl(clean)

    @field_validator("headers")
    @classmethod
    def lower_header_keys(cls, v: Dict[str, str]) -> Dict[str, str]:
        return {str(k).lower(): str(vv) for k, vv in (v or {}).items()}


# ------------------------------- evidence -----------------------------------

class RequestMeta(BaseModel):
    method: HTTPMethod
    url: HttpUrl
    headers: Dict[str, str] = Field(default_factory=dict)
    body_preview: Optional[str] = Field(
        default=None, description="First N bytes of request body (sanitized)"
    )
    body_sha1: Optional[str] = None

    @field_validator("headers")
    @classmethod
    def lower_header_keys(cls, v: Dict[str, str]) -> Dict[str, str]:
        return {str(k).lower(): str(vv) for k, vv in (v or {}).items()}


class ResponseMeta(BaseModel):
    status: int
    content_type: Optional[str] = None
    length: Optional[int] = None
    location: Optional[str] = Field(default=None, description="Redirect Location (if any)")
    body_preview: Optional[str] = Field(
        default=None, description="First N bytes of response body (sanitized)"
    )
    body_sha1: Optional[str] = None


class Signal(BaseModel):
    """
    Detection signal emitted by detectors. For M0 focus on XSS.
    """
    family: PayloadFamily = Field(default=PayloadFamily.XSS)
    name: str = Field(..., description="Short identifier for the signal rule")
    context: Optional[XSSContext] = Field(
        default=None, description="XSS context classification, if available"
    )
    weight: float = Field(default=1.0, ge=0.0, le=10.0)
    snippet: Optional[str] = Field(default=None, description="Tiny excerpt around reflection")


class EvidenceOut(BaseModel):
    """
    Canonical persisted record for a single fuzz result (one payload attempt).
    """
    id: Optional[int] = None
    job_id: str
    endpoint_shape: str = Field(..., description="EndpointOut.shape_key at test time")
    testcase_hash: str = Field(..., description="Stable hash for (req, payload)")
    request: RequestMeta
    response: ResponseMeta
    signals: List[Signal] = Field(default_factory=list)
    label: Optional[Literal["xss", "benign", "unknown"]] = Field(default=None)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    ts: Optional[str] = Field(default=None, description="ISO timestamp when recorded")


# ------------------------------- crawling -----------------------------------

class CrawlJobRequest(BaseModel):
    """
    Start a crawl for a single origin; same-origin enforced by the crawler.
    """
    job_id: str
    target_url: HttpUrl
    auth: AuthConfig = Field(default_factory=AuthConfig)
    max_pages: int = Field(default=150, ge=1, le=5000)
    same_origin_only: bool = Field(default=True)

    @field_validator("target_url")
    @classmethod
    def strip_fragment(cls, v: HttpUrl) -> HttpUrl:
        parts = list(urlparse(str(v)))
        parts[5] = ""  # fragment
        clean = urlunparse(parts)
        return HttpUrl(clean)


# ------------------------------- utilities ----------------------------------

class ErrorResponse(BaseModel):
    detail: str
