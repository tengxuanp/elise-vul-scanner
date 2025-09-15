# backend/schemas.py
from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional
from enum import Enum
from pydantic import BaseModel, Field

class HTTPMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"

class Param(BaseModel):
    name: str
    location: Literal["query", "form", "json"]
    value: Optional[str] = None

class ParamLocs(BaseModel):
    query: List[str] = Field(default_factory=list)
    form: List[str] = Field(default_factory=list)
    json_: List[str] = Field(default_factory=list, alias='json')

    class Config:
        allow_population_by_field_name = True

class EndpointOut(BaseModel):
    url: str
    method: HTTPMethod
    params: List[Param] = Field(default_factory=list)
    param_locs: ParamLocs = Field(default_factory=ParamLocs)
    status: Optional[int] = None
    content_type: Optional[str] = None
    headers: Dict[str, str] = Field(default_factory=dict)

class AuthConfig(BaseModel):
    mode: Literal["none", "bearer", "form", "manual"] = "none"
    bearer_token: Optional[str] = None
    login_url: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    username_selector: Optional[str] = None
    password_selector: Optional[str] = None
    submit_selector: Optional[str] = None
    wait_after_ms: int = 1500
