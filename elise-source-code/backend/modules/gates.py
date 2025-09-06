import re
from .targets import Target

REDIRECT_PARAM_RE = re.compile(r"(url|next|return|dest|redirect)", re.I)

def gate_not_applicable(t: Target) -> bool:
    if t.status in (405, 501):  # not allowed / not implemented
        return True
    if not t.param:  # no parameter, nothing to inject
        return True
    return False

def gate_candidate_xss(t: Target) -> bool:
    # Allow only HTML-like responses for XSS families
    if not t.content_type:
        return False
    ct = t.content_type.lower()
    return ct.startswith("text/html") or ct.startswith("text/plain")

def gate_candidate_redirect(t: Target) -> bool:
    # Must look like a redirect sink param name first; proof will come from oracle
    return bool(REDIRECT_PARAM_RE.fullmatch(t.param) or REDIRECT_PARAM_RE.search(t.param))

def gate_candidate_sqli(t: Target) -> bool:
    # JSON, HTML, text are acceptable; XHR endpoints included
    if not t.content_type:
        return True
    ct = t.content_type.lower()
    return any(ct.startswith(x) for x in ("application/json", "text/html", "text/plain"))

def is_attackable(t: Target) -> bool:
    """
    Determines if a target is attackable for any known vulnerability family.
    Returns False for 405 status or when param is missing.
    """
    # Always return False for 405 or when param is missing
    if t.status == 405 or not t.param:
        return False
    
    # Check if attackable for any specific family
    if gate_candidate_xss(t):
        return True
    if gate_candidate_redirect(t):
        return True
    if gate_candidate_sqli(t):
        return True
    
    # Add other families here as they are implemented
    
    return False