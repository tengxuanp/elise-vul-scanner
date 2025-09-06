"""
Enhanced Features V1 - Strict Schema Feature Extractor

This module provides a frozen Pydantic schema for feature extraction
with consistent one-hot encodings and semantic parameter analysis.
"""

from __future__ import annotations

import re
import math
from typing import Dict, Any, Optional, Literal
from pydantic import BaseModel, Field


class EnhancedFeaturesV1(BaseModel):
    """
    Frozen schema for enhanced feature extraction v1.
    
    Features are organized into logical groups:
    - One-hot encodings for categorical variables
    - Parameter semantics analysis
    - Endpoint context features
    - Pre-signals from previous scans
    - Cheap probe differences
    """
    
    # Schema version identifier
    schema_version: Literal["enh-feats-v2"] = Field(default="enh-feats-v2", alias="_schema_version")
    
    # === ONE-HOT ENCODINGS ===
    # Location one-hots (exactly one should be 1)
    loc_query: int = Field(ge=0, le=1, description="Parameter is in query string")
    loc_form: int = Field(ge=0, le=1, description="Parameter is in form data")
    loc_json: int = Field(ge=0, le=1, description="Parameter is in JSON body")
    
    # Method one-hots (exactly one should be 1)
    method_get: int = Field(ge=0, le=1, description="HTTP method is GET")
    method_post: int = Field(ge=0, le=1, description="HTTP method is POST")
    method_other: int = Field(ge=0, le=1, description="HTTP method is other (PUT, DELETE, etc.)")
    
    # Content type one-hots (exactly one should be 1)
    ct_json: int = Field(ge=0, le=1, description="Content-Type is application/json")
    ct_form: int = Field(ge=0, le=1, description="Content-Type is form-urlencoded")
    ct_other: int = Field(ge=0, le=1, description="Content-Type is other")
    
    # === PARAMETER SEMANTICS ===
    param_len: int = Field(ge=0, description="Length of parameter name")
    param_entropy: float = Field(ge=0.0, le=1.0, description="Entropy of parameter name (normalized)")
    is_snake: int = Field(ge=0, le=1, description="Parameter name uses snake_case")
    is_camel: int = Field(ge=0, le=1, description="Parameter name uses camelCase")
    
    # Parameter name semantic flags
    name_has_id: int = Field(ge=0, le=1, description="Parameter name contains 'id'")
    name_has_token: int = Field(ge=0, le=1, description="Parameter name contains 'token'")
    name_has_q: int = Field(ge=0, le=1, description="Parameter name contains 'q' (query)")
    name_has_redirect: int = Field(ge=0, le=1, description="Parameter name contains 'redirect'")
    name_has_search: int = Field(ge=0, le=1, description="Parameter name contains 'search'")
    name_has_user: int = Field(ge=0, le=1, description="Parameter name contains 'user'")
    name_has_auth: int = Field(ge=0, le=1, description="Parameter name contains 'auth'")
    name_has_pass: int = Field(ge=0, le=1, description="Parameter name contains 'pass'")
    
    # === ENDPOINT CONTEXT ===
    path_depth: int = Field(ge=0, description="Number of path segments")
    has_admin: int = Field(ge=0, le=1, description="URL path contains 'admin'")
    has_login: int = Field(ge=0, le=1, description="URL path contains 'login'")
    has_cart: int = Field(ge=0, le=1, description="URL path contains 'cart'")
    has_profile: int = Field(ge=0, le=1, description="URL path contains 'profile'")
    
    # === PRE-SIGNALS ===
    prev_reflect_raw: int = Field(ge=0, le=1, description="Previous scan showed raw reflection")
    prev_reflect_html: int = Field(ge=0, le=1, description="Previous scan showed HTML reflection")
    prev_reflect_attr: int = Field(ge=0, le=1, description="Previous scan showed attribute reflection")
    prev_sql_error: int = Field(ge=0, le=1, description="Previous scan showed SQL error")
    prev_redirect_signal: int = Field(ge=0, le=1, description="Previous scan showed redirect signal")
    
    # === CHEAP PROBE DIFFS ===
    prev_status_delta: int = Field(description="Previous status code change (-999 to 999)")
    prev_len_delta: int = Field(description="Previous response length change (-999999 to 999999)")
    
    # === PROBE RESULTS ===
    # XSS reflection context
    reflect_html: int = Field(ge=0, le=1, description="XSS reflection in HTML context")
    reflect_attr: int = Field(ge=0, le=1, description="XSS reflection in attribute context")
    reflect_js: int = Field(ge=0, le=1, description="XSS reflection in JavaScript string context")
    
    # Redirect influence
    redirect_influence: int = Field(ge=0, le=1, description="Parameter influences redirect Location header")
    
    # SQLi detection
    sqli_error: int = Field(ge=0, le=1, description="SQLi error-based detection")
    sqli_db_mysql: int = Field(ge=0, le=1, description="SQLi detected MySQL database")
    sqli_db_postgres: int = Field(ge=0, le=1, description="SQLi detected PostgreSQL database")
    sqli_db_sqlite: int = Field(ge=0, le=1, description="SQLi detected SQLite database")
    sqli_db_oracle: int = Field(ge=0, le=1, description="SQLi detected Oracle database")
    sqli_db_mssql: int = Field(ge=0, le=1, description="SQLi detected MSSQL database")
    sqli_boolean_delta: float = Field(ge=0.0, le=1.0, description="SQLi boolean-based delta")
    sqli_time: int = Field(ge=0, le=1, description="SQLi time-based detection")
    
    class Config:
        frozen = True  # Make the schema immutable
        validate_assignment = True
        populate_by_name = True  # Allow both field name and alias


def _calculate_entropy(text: str) -> float:
    """Calculate normalized entropy of a string (0.0 to 1.0)."""
    if not text:
        return 0.0
    
    # Count character frequencies
    char_counts = {}
    for char in text.lower():
        char_counts[char] = char_counts.get(char, 0) + 1
    
    # Calculate entropy
    total_chars = len(text)
    entropy = 0.0
    for count in char_counts.values():
        probability = count / total_chars
        if probability > 0:
            entropy -= probability * math.log2(probability)
    
    # Normalize by maximum possible entropy (log2 of alphabet size)
    max_entropy = math.log2(len(char_counts)) if char_counts else 1.0
    return min(entropy / max_entropy, 1.0) if max_entropy > 0 else 0.0


def _detect_naming_convention(param_name: str) -> tuple[int, int]:
    """Detect if parameter name uses snake_case or camelCase."""
    if not param_name:
        return 0, 0
    
    is_snake = 1 if '_' in param_name and param_name.islower() else 0
    is_camel = 1 if any(c.isupper() for c in param_name[1:]) and '_' not in param_name else 0
    
    return is_snake, is_camel


def _extract_content_type_features(content_type: Optional[str]) -> tuple[int, int, int]:
    """Extract content type one-hot features."""
    if not content_type:
        return 0, 0, 1  # Default to "other"
    
    ct_lower = content_type.lower()
    if 'application/json' in ct_lower:
        return 1, 0, 0
    elif 'application/x-www-form-urlencoded' in ct_lower or 'multipart/form-data' in ct_lower:
        return 0, 1, 0
    else:
        return 0, 0, 1


def _extract_location_features(param_locs: Optional[Dict[str, Any]], param_name: str) -> tuple[int, int, int]:
    """Extract parameter location one-hot features."""
    if not param_locs or not param_name:
        return 0, 0, 0
    
    # Check each location type
    query_params = param_locs.get('query', [])
    form_params = param_locs.get('form', [])
    json_params = param_locs.get('json', [])
    
    # Convert to sets for easier lookup
    query_set = set(str(p) for p in query_params) if isinstance(query_params, list) else set()
    form_set = set(str(p) for p in form_params) if isinstance(form_params, list) else set()
    json_set = set(str(p) for p in json_params) if isinstance(json_params, list) else set()
    
    loc_query = 1 if param_name in query_set else 0
    loc_form = 1 if param_name in form_set else 0
    loc_json = 1 if param_name in json_set else 0
    
    return loc_query, loc_form, loc_json


def _extract_method_features(method: Optional[str]) -> tuple[int, int, int]:
    """Extract HTTP method one-hot features."""
    if not method:
        return 1, 0, 0  # Default to GET
    
    method_upper = method.upper()
    if method_upper == 'GET':
        return 1, 0, 0
    elif method_upper == 'POST':
        return 0, 1, 0
    else:
        return 0, 0, 1


def _extract_path_features(url: Optional[str]) -> tuple[int, int, int, int, int]:
    """Extract path context features."""
    if not url:
        return 0, 0, 0, 0, 0
    
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        path = parsed.path.lower()
        
        path_depth = len([seg for seg in path.split('/') if seg])
        has_admin = 1 if 'admin' in path else 0
        has_login = 1 if 'login' in path else 0
        has_cart = 1 if 'cart' in path else 0
        has_profile = 1 if 'profile' in path else 0
        
        return path_depth, has_admin, has_login, has_cart, has_profile
    except Exception:
        return 0, 0, 0, 0, 0


def _extract_pre_signals(pre: Optional[Dict[str, Any]]) -> tuple[int, int, int, int, int]:
    """Extract pre-signals from previous scans."""
    if not pre:
        return 0, 0, 0, 0, 0
    
    signals = pre.get('signals', {})
    
    # Reflection signals
    prev_reflect_raw = 1 if signals.get('xss_reflected', False) else 0
    prev_reflect_html = 1 if signals.get('xss_reflected', False) else 0  # Simplified
    prev_reflect_attr = 0  # Would need more specific detection
    
    # Other signals
    prev_sql_error = 1 if signals.get('sql_error', False) else 0
    prev_redirect_signal = 1 if signals.get('external_redirect', False) else 0
    
    return prev_reflect_raw, prev_reflect_html, prev_reflect_attr, prev_sql_error, prev_redirect_signal


def _extract_probe_diffs(pre: Optional[Dict[str, Any]]) -> tuple[int, int]:
    """Extract cheap probe differences."""
    if not pre:
        return 0, 0
    
    # Extract status and length deltas from previous results
    prev_status_delta = pre.get('status_delta', 0)
    prev_len_delta = pre.get('len_delta', 0)
    
    # Clamp values to reasonable ranges
    prev_status_delta = max(-999, min(999, int(prev_status_delta)))
    prev_len_delta = max(-999999, min(999999, int(prev_len_delta)))
    
    return prev_status_delta, prev_len_delta


def _extract_probe_features(probe_result: Optional[Dict[str, Any]]) -> tuple[int, int, int, int, int, int, int, int, int, int, float, int]:
    """Extract probe result features."""
    if not probe_result:
        return 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0.0, 0
    
    # XSS reflection context
    xss_context = probe_result.get('xss_context', 'none')
    reflect_html = 1 if xss_context == 'html' else 0
    reflect_attr = 1 if xss_context == 'attr' else 0
    reflect_js = 1 if xss_context == 'js_string' else 0
    
    # Redirect influence
    redirect_influence = 1 if probe_result.get('redirect_influence', False) else 0
    
    # SQLi detection
    sqli_error = 1 if probe_result.get('sqli_error_based', False) else 0
    sqli_boolean_delta = float(probe_result.get('sqli_boolean_delta', 0.0))
    sqli_time = 1 if probe_result.get('sqli_time_based', False) else 0
    
    # Database type detection
    sqli_db = probe_result.get('sqli_error_db', '')
    sqli_db_mysql = 1 if sqli_db == 'mysql' else 0
    sqli_db_postgres = 1 if sqli_db == 'postgres' else 0
    sqli_db_sqlite = 1 if sqli_db == 'sqlite' else 0
    sqli_db_oracle = 1 if sqli_db == 'oracle' else 0
    sqli_db_mssql = 1 if sqli_db == 'mssql' else 0
    
    return (reflect_html, reflect_attr, reflect_js, redirect_influence,
            sqli_error, sqli_db_mysql, sqli_db_postgres, sqli_db_sqlite, 
            sqli_db_oracle, sqli_db_mssql, sqli_boolean_delta, sqli_time)


def extract_features_v1(
    endpoint: Dict[str, Any], 
    param: Dict[str, Any], 
    family: Optional[str] = None, 
    pre: Optional[Dict[str, Any]] = None,
    probe_result: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Extract features using EnhancedFeaturesV2 schema.
    
    Args:
        endpoint: Endpoint dictionary with url, method, param_locs, etc.
        param: Parameter dictionary with name and other attributes
        family: Vulnerability family (sqli, xss, redirect, etc.)
        pre: Previous scan results for pre-signals and diffs
        probe_result: Probe engine results for feature enrichment
    
    Returns:
        Dictionary validated by EnhancedFeaturesV2 schema
    """
    
    # Extract basic information
    param_name = str(param.get('name', ''))
    method = endpoint.get('method', 'GET')
    url = endpoint.get('url', '')
    content_type = endpoint.get('content_type') or endpoint.get('content_type_hint')
    param_locs = endpoint.get('param_locs', {})
    
    # === ONE-HOT ENCODINGS ===
    loc_query, loc_form, loc_json = _extract_location_features(param_locs, param_name)
    method_get, method_post, method_other = _extract_method_features(method)
    ct_json, ct_form, ct_other = _extract_content_type_features(content_type)
    
    # === PARAMETER SEMANTICS ===
    param_len = len(param_name)
    param_entropy = _calculate_entropy(param_name)
    is_snake, is_camel = _detect_naming_convention(param_name)
    
    # Parameter name semantic flags
    param_lower = param_name.lower()
    name_has_id = 1 if 'id' in param_lower else 0
    name_has_token = 1 if 'token' in param_lower else 0
    name_has_q = 1 if 'q' in param_lower else 0
    name_has_redirect = 1 if 'redirect' in param_lower else 0
    name_has_search = 1 if 'search' in param_lower else 0
    name_has_user = 1 if 'user' in param_lower else 0
    name_has_auth = 1 if 'auth' in param_lower else 0
    name_has_pass = 1 if 'pass' in param_lower else 0
    
    # === ENDPOINT CONTEXT ===
    path_depth, has_admin, has_login, has_cart, has_profile = _extract_path_features(url)
    
    # === PRE-SIGNALS ===
    prev_reflect_raw, prev_reflect_html, prev_reflect_attr, prev_sql_error, prev_redirect_signal = _extract_pre_signals(pre)
    
    # === CHEAP PROBE DIFFS ===
    prev_status_delta, prev_len_delta = _extract_probe_diffs(pre)
    
    # === PROBE RESULTS ===
    (reflect_html, reflect_attr, reflect_js, redirect_influence,
     sqli_error, sqli_db_mysql, sqli_db_postgres, sqli_db_sqlite, 
     sqli_db_oracle, sqli_db_mssql, sqli_boolean_delta, sqli_time) = _extract_probe_features(probe_result)
    
    # Build feature dictionary
    features = {
        '_schema_version': 'enh-feats-v2',
        
        # One-hot encodings
        'loc_query': loc_query,
        'loc_form': loc_form,
        'loc_json': loc_json,
        'method_get': method_get,
        'method_post': method_post,
        'method_other': method_other,
        'ct_json': ct_json,
        'ct_form': ct_form,
        'ct_other': ct_other,
        
        # Parameter semantics
        'param_len': param_len,
        'param_entropy': param_entropy,
        'is_snake': is_snake,
        'is_camel': is_camel,
        'name_has_id': name_has_id,
        'name_has_token': name_has_token,
        'name_has_q': name_has_q,
        'name_has_redirect': name_has_redirect,
        'name_has_search': name_has_search,
        'name_has_user': name_has_user,
        'name_has_auth': name_has_auth,
        'name_has_pass': name_has_pass,
        
        # Endpoint context
        'path_depth': path_depth,
        'has_admin': has_admin,
        'has_login': has_login,
        'has_cart': has_cart,
        'has_profile': has_profile,
        
        # Pre-signals
        'prev_reflect_raw': prev_reflect_raw,
        'prev_reflect_html': prev_reflect_html,
        'prev_reflect_attr': prev_reflect_attr,
        'prev_sql_error': prev_sql_error,
        'prev_redirect_signal': prev_redirect_signal,
        
        # Cheap probe diffs
        'prev_status_delta': prev_status_delta,
        'prev_len_delta': prev_len_delta,
        
        # Probe results
        'reflect_html': reflect_html,
        'reflect_attr': reflect_attr,
        'reflect_js': reflect_js,
        'redirect_influence': redirect_influence,
        'sqli_error': sqli_error,
        'sqli_db_mysql': sqli_db_mysql,
        'sqli_db_postgres': sqli_db_postgres,
        'sqli_db_sqlite': sqli_db_sqlite,
        'sqli_db_oracle': sqli_db_oracle,
        'sqli_db_mssql': sqli_db_mssql,
        'sqli_boolean_delta': sqli_boolean_delta,
        'sqli_time': sqli_time,
    }
    
    # Validate and return
    validated_features = EnhancedFeaturesV1(**features)
    return validated_features.model_dump(by_alias=True)


def build_features_for_target(target: "Target", probe_result: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Build features for a Target object.
    
    Args:
        target: Target object with url, method, param, param_in, etc.
        probe_result: Optional probe results for feature enrichment
    
    Returns:
        Dictionary of features for ML prediction
    """
    # Convert Target to endpoint and param format
    endpoint = {
        "url": target.url,
        "method": target.method,
        "path": target.url.split("?")[0] if "?" in target.url else target.url,
        "param_locs": {
            "query": [target.param] if target.param_in == "query" else [],
            "form": [target.param] if target.param_in == "form" else [],
            "json": [target.param] if target.param_in == "json" else []
        }
    }
    
    param = {
        "name": target.param,
        "value": "test",  # Placeholder value
        "location": target.param_in
    }
    
    return extract_features_v1(endpoint, param, probe_result=probe_result)
