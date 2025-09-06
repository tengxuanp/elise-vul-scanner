from pydantic import BaseModel
from typing import Literal, Optional, List, Dict, Any
from urllib.parse import urlparse, parse_qs

ParamLoc = Literal["query", "form", "json"]

class Target(BaseModel):
    url: str
    path: str
    method: Literal["GET", "POST", "PUT", "DELETE", "PATCH"]
    param: str
    param_in: ParamLoc
    status: Optional[int] = None
    content_type: Optional[str] = None
    provenance_ids: List[int] = []  # from crawler network events (required, non-empty)

def enumerate_targets(endpoint: Dict[str, Any]) -> List[Target]:
    """
    Expands an endpoint into a list of individual parameter targets.
    Generates targets for query, form, and JSON parameters.
    """
    targets: List[Target] = []
    
    url = endpoint.get("url", "")
    path = endpoint.get("path", "")
    method = endpoint.get("method", "GET")
    status = endpoint.get("status", 0)
    content_type = endpoint.get("content_type", "")
    param_locs = endpoint.get("param_locs", {})

    if not url or not path:
        return []

    # 1. Query parameters
    query_params = param_locs.get("query", [])
    for param_name in query_params:
        targets.append(
            Target(
                url=url,
                path=path,
                method=method,
                param=param_name,
                param_in="query",
                status=status,
                content_type=content_type,
                provenance_ids=[1]  # TODO: Get real provenance IDs from crawler
            )
        )
    
    # 2. Form parameters
    form_params = param_locs.get("form", [])
    for param_name in form_params:
        targets.append(
            Target(
                url=url,
                path=path,
                method=method,
                param=param_name,
                param_in="form",
                status=status,
                content_type=content_type,
                provenance_ids=[1]  # TODO: Get real provenance IDs from crawler
            )
        )
    
    # 3. JSON parameters
    json_params = param_locs.get("json", [])
    for param_name in json_params:
        targets.append(
            Target(
                url=url,
                path=path,
                method=method,
                param=param_name,
                param_in="json",
                status=status,
                content_type=content_type,
                provenance_ids=[1]  # TODO: Get real provenance IDs from crawler
            )
        )
    
    return targets