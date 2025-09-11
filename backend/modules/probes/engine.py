from dataclasses import dataclass
from .xss_canary import run_xss_probe, XssProbe
from .sqli_triage import run_sqli_probe, SqliProbe
from .redirect_oracle import run_redirect_probe, RedirectProbe
from ..targets import Target

# Family-scoped probe registries
PROBES = {
    "xss": {"canary": run_xss_probe},
    "sqli": {"triage": run_sqli_probe},
    "redirect": {"oracle": run_redirect_probe}
}

@dataclass
class ProbeBundle:
    xss: XssProbe
    sqli: SqliProbe
    redirect: RedirectProbe

def run_probes(t: Target, families: list = None, plan=None, ctx_mode: str = "auto", meta: dict = None) -> ProbeBundle:
    """
    Run probes for specified families with strict family scoping.
    
    Args:
        t: Target to probe
        families: List of families to probe. If None, runs all families.
        plan: Strategy plan for defensive checks
    """
    if families is None:
        families = ["xss", "sqli", "redirect"]
    
    # FAMILY ENFORCEMENT: Ensure no cross-family probe contamination
    if meta is None:
        meta = {}
    
    # Create probe results for each family with strict scoping
    if "xss" in families:
        # Only run XSS probe if XSS is in the families list
        xss_result = run_xss_probe(t.url, t.method, t.param_in, t.param, t.headers, job_id=None, plan=plan, ctx_mode=ctx_mode, meta=meta)
    else:
        # Create mock XSS probe result - no XSS canary generation for non-XSS families
        from unittest.mock import Mock
        xss_result = Mock()
        xss_result.reflected = False
        xss_result.context = None
        xss_result.xss_context = None
        xss_result.xss_escaping = None
        xss_result.xss_context_final = None
        xss_result.xss_context_source_detailed = None
        xss_result.xss_ml_proba = None
    
    if "sqli" in families:
        sqli_result = run_sqli_probe(t.url, t.method, t.param_in, t.param, t.headers, plan)
    else:
        # Create mock SQLi probe result
        from unittest.mock import Mock
        sqli_result = Mock()
        sqli_result.error_based = False
        sqli_result.time_based = False
        sqli_result.boolean_delta = 0
    
    if "redirect" in families:
        redirect_result = run_redirect_probe(t.url, t.method, t.param_in, t.param, t.headers, plan)
    else:
        # Create mock redirect probe result
        from unittest.mock import Mock
        redirect_result = Mock()
        redirect_result.influence = False
    
    return ProbeBundle(
        xss=xss_result,
        sqli=sqli_result,
        redirect=redirect_result,
    )