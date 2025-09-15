from .targets import Target

def gate_not_applicable(t: Target) -> bool:
    if not t.param: return True
    if not t.url or not t.method: return True
    return False

def gate_candidate_xss(t: Target) -> bool:
    ctype = (t.content_type or "").lower()
    return t.param_in in ("query", "form", "json")

def gate_candidate_sqli(t: Target) -> bool:
    """
    Gate for SQLi candidates with URL-param suppression.
    
    URL-like parameters are suppressed for SQLi unless hard SQL error evidence exists.
    This prevents false positives from redirect parameters like /go?url=.
    """
    print(f"SQLI_GATE_CHECK param={t.param} param_in={t.param_in} url={t.url}")
    
    # Basic parameter type check
    if t.param_in not in ("query", "form", "json"):
        print(f"SQLI_GATE_REJECTED param {t.param} rejected - not query/form/json")
        return False
    
    # URL-param suppression check
    from backend.triage.sqli_decider import should_suppress_sqli_for_param
    
    # Check if this parameter should be suppressed
    # Extract parameter value from URL if possible
    param_value = ''
    try:
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(t.url)
        if t.param_in == 'query' and parsed.query:
            query_params = parse_qs(parsed.query, keep_blank_values=True)
            if t.param in query_params:
                param_value = query_params[t.param][0] if query_params[t.param] else ''
    except:
        pass
    
    print(f"SQLI_GATE_CHECK param={t.param} param_value='{param_value}'")
    
    if should_suppress_sqli_for_param(t.param, param_value, has_error_evidence=False):
        print(f"SQLI_SUPPRESSED URL-like param {t.param} suppressed for SQLi")
        return False
    
    print(f"SQLI_GATE_ALLOWED param {t.param} allowed for SQLi")
    return True

def gate_candidate_redirect(t: Target) -> bool:
    return t.param.lower() in {"next","url","return","redirect","target","goto","dest","destination"}
