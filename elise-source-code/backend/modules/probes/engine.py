from dataclasses import dataclass
from typing import Optional
from ..targets import Target
from .xss_canary import classify_reflection, XSSContext
from .redirect_oracle import proves_open_redirect
from .sqli_triage import triage as sqli_triage

@dataclass
class ProbeResult:
    xss_context: XSSContext
    redirect_influence: bool
    redirect_status: Optional[int]
    redirect_location: Optional[str]
    sqli_error_based: bool
    sqli_error_db: Optional[str]
    sqli_boolean_delta: float
    sqli_time_based: bool
    sqli_time_delta_ms: float

def run_probes(t: Target) -> ProbeResult:
    xctx = classify_reflection(t.url, t.method, t.param_in, t.param)
    red_ok, red_status, red_loc = (False, None, None)
    # Only try redirect oracle if param name looks like redirect-ish and status was 30x recently (lightweight guard)
    from ..gates import gate_candidate_redirect
    if gate_candidate_redirect(t):
        ok, st, loc = proves_open_redirect(t.url, t.method, t.param)
        red_ok, red_status, red_loc = ok, st, loc
    s = sqli_triage(t.url, t.method, t.param_in, t.param)
    return ProbeResult(
        xss_context=xctx,
        redirect_influence=red_ok, redirect_status=red_status, redirect_location=red_loc,
        sqli_error_based=s.error_based, sqli_error_db=s.error_db,
        sqli_boolean_delta=s.boolean_delta, sqli_time_based=s.time_based, sqli_time_delta_ms=s.time_delta_ms
    )
