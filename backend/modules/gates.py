from .targets import Target

def gate_not_applicable(t: Target) -> bool:
    if not t.param: return True
    if not t.url or not t.method: return True
    return False

def gate_candidate_xss(t: Target) -> bool:
    ctype = (t.content_type or "").lower()
    return (t.param_in in ("query","form")) and ("json" not in ctype)

def gate_candidate_sqli(t: Target) -> bool:
    return t.param_in in ("query","form","json")

def gate_candidate_redirect(t: Target) -> bool:
    return t.param.lower() in {"next","url","return","redirect","target","goto","dest","destination"}