from dataclasses import dataclass
from .xss_canary import run_xss_probe, XssProbe
from .sqli_triage import run_sqli_probe, SqliProbe
from .redirect_oracle import run_redirect_probe, RedirectProbe
from backend.modules.targets import Target

@dataclass
class ProbeBundle:
    xss: XssProbe
    sqli: SqliProbe
    redirect: RedirectProbe

def run_probes(t: Target) -> ProbeBundle:
    return ProbeBundle(
        xss=run_xss_probe(t.url, t.method, t.param_in, t.param, t.headers),
        sqli=run_sqli_probe(t.url, t.method, t.param_in, t.param, t.headers),
        redirect=run_redirect_probe(t.url, t.method, t.param_in, t.param, t.headers),
    )