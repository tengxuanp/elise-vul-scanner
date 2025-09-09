from dataclasses import dataclass
from .xss_canary import run_xss_probe, XssProbe
from .sqli_triage import run_sqli_probe, SqliProbe
from .redirect_oracle import run_redirect_probe, RedirectProbe
from ..targets import Target

@dataclass
class ProbeBundle:
    xss: XssProbe
    sqli: SqliProbe
    redirect: RedirectProbe

def run_probes(t: Target, families: list = None, plan=None) -> ProbeBundle:
    """
    Run probes for specified families.
    
    Args:
        t: Target to probe
        families: List of families to probe. If None, runs all families.
        plan: Strategy plan for defensive checks
    """
    if families is None:
        families = ["xss", "sqli", "redirect"]
    
    # Create probe results for each family
    if "xss" in families:
        xss_result = run_xss_probe(t.url, t.method, t.param_in, t.param, t.headers, plan=plan)
    else:
        # Create mock XSS probe result
        from unittest.mock import Mock
        xss_result = Mock()
        xss_result.reflected = False
        xss_result.context = None
        xss_result.xss_context = None
        xss_result.xss_escaping = None
    
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