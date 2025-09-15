from dataclasses import dataclass
import os
from .xss_canary import run_xss_probe, XssProbe
from .sqli_triage import run_sqli_probe, SqliProbe
from .redirect_oracle import run_redirect_probe, RedirectProbe
from ..targets import Target
from .xss_dom import run_xss_probe_dom

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

def run_probes(t: Target, families: list = None, plan=None, ctx_mode: str = "auto", meta: dict = None, job_id: str = None) -> ProbeBundle:
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
        # Server-side probe (reflection in HTTP response bodies)
        # Pass base_params so server-side probe can include required form/json fields
        base_params = getattr(t, 'base_params', None)
        xss_result = run_xss_probe(
            t.url,
            t.method,
            t.param_in,
            t.param,
            t.headers,
            job_id=job_id,
            plan=plan,
            ctx_mode=ctx_mode,
            meta=meta,
            base_params=base_params,
        )
        # DOM-based probe for SPAs/pages (JS execution contexts)
        try:
            enable_dom = (os.getenv("ELISE_ENABLE_DOM_XSS", "1") == "1")
        except Exception:
            enable_dom = True
        if enable_dom:
            try:
                dom = run_xss_probe_dom(
                    base_url=t.url,
                    param_in=t.param_in,
                    param=t.param,
                    spa_view_url=t.spa_view_url,
                )
                # Augment XSS probe with DOM execution flags (non-breaking)
                if hasattr(xss_result, "__dict__"):
                    setattr(xss_result, "dom_executed", bool(dom.executed))
                    setattr(xss_result, "dom_dialogs", int(dom.dialogs))
                # Persist DOM XSS training event
                try:
                    if job_id:
                        from backend.app_state import DATA_DIR
                        import json
                        job_dir = DATA_DIR / "jobs" / job_id
                        job_dir.mkdir(parents=True, exist_ok=True)
                        with open(job_dir / "xss_dom_events.ndjson", "a", encoding="utf-8") as f:
                            f.write(json.dumps({
                                "url": dom.url_used or t.spa_view_url or t.url,
                                "param": t.param,
                                "executed": bool(dom.executed),
                                "dialogs": int(dom.dialogs),
                                "payload": dom.payload_used,
                            }) + "\n")
                except Exception:
                    pass
            except Exception:
                # Best-effort; DOM probe is optional
                pass
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
        xss_result.dom_executed = False
        xss_result.dom_dialogs = 0
    
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
