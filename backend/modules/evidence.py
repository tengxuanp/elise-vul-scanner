from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict
import json, time, re, os, base64, html
from backend.app_state import DATA_DIR

@dataclass
class EvidenceRow:
    family: str
    url: str
    method: str
    param_in: str
    param: str
    payload: str
    request_headers: Dict[str,Any]
    response_status: int
    response_snippet: str
    probe_signals: Dict[str,Any]
    why: list
    cvss: Dict[str,Any] | None = None
    score: float | None = None
    p_cal: float | None = None
    validation: Dict[str,bool] | None = None
    # New ML telemetry fields
    rank_source: str | None = None  # "ml" | "probe_only" | "defaults"
    ml_family: str | None = None    # "xss" | "sqli" | "redirect" | null
    ml_proba: float | None = None   # ML probability score
    ml_threshold: float | None = None  # Threshold used for this family
    model_tag: str | None = None    # Model filename or version
    # New response snippet fields
    response_snippet_text: str | None = None  # HTML-escaped safe text
    response_snippet_raw: str | None = None   # base64 encoded raw bytes
    # XSS Context fields
    xss_context: str | None = None  # "html_body|attr|js_string|url|css"
    xss_escaping: str | None = None  # "raw|html|url|js|unknown"
    xss_context_source: str | None = None  # "rule|ml"
    xss_context_ml_proba: float | None = None  # ML probability when source="ml"
    # Telemetry fields
    attempt_idx: int | None = None  # Attempt index for this payload
    top_k_used: int | None = None   # Number of top-k payloads used

    @staticmethod
    def _create_validation_flags(signals: Dict[str,Any]) -> Dict[str,bool]:
        """Create validation flags from probe signals."""
        if not signals:
            return {
                "xss_reflection": False,
                "sqli_error": False,
                "sqli_timing": False,
                "redirect_location": False,
            }
        
        return {
            "xss_reflection": (signals.get("xss_context") in {"html","js","attr"}) if signals else False,
            "sqli_error": bool(signals.get("sqli_error_based")) if signals else False,
            "sqli_timing": bool((signals.get("sql_boolean_delta") or 0) >= float(os.getenv("ELISE_TAU_SQLI","0.50"))) if signals else False,
            "redirect_location": bool(signals.get("redirect_influence") is True) if signals else False,
        }

    @classmethod
    def from_probe_confirm(cls, t, family, probe_bundle):
        p = probe_bundle
        signals = {
            "xss_context": getattr(p.xss, "context", None),
            "redirect_influence": getattr(p.redirect, "influence", None),
            "sqli_error_based": getattr(p.sqli, "error_based", None),
        }
        
        # Extract XSS context information
        xss_context = None
        xss_escaping = None
        xss_context_source = None
        xss_context_ml_proba = None
        
        if family == "xss" and hasattr(p, "xss") and p.xss:
            xss_context = getattr(p.xss, "xss_context", None)
            xss_escaping = getattr(p.xss, "xss_escaping", None)
            
            # Determine source and ML probability
            xss_context_ml = getattr(p.xss, "xss_context_ml", None)
            xss_context_rule = getattr(p.xss, "xss_context_rule", None)
            
            if xss_context_ml and xss_context_ml.get("pred"):
                xss_context_source = "ml"
                xss_context_ml_proba = xss_context_ml.get("proba")
            elif xss_context_rule:
                xss_context_source = "rule"
        
        # Sanitize response snippet
        response_snippet = "<probe_confirmed>"
        response_snippet_text = html.escape(response_snippet)
        response_snippet_raw = base64.b64encode(response_snippet.encode('utf-8')).decode('ascii')
        
        return cls(
            family, t.url, t.method, t.param_in, t.param, "<probe>", t.headers or {}, 200, response_snippet,
            signals,
            ["probe_proof"],
            validation=cls._create_validation_flags(signals),
            rank_source="probe_only",
            ml_family=None,
            ml_proba=None,
            ml_threshold=None,
            model_tag=None,
            response_snippet_text=response_snippet_text,
            response_snippet_raw=response_snippet_raw,
            xss_context=xss_context,
            xss_escaping=xss_escaping,
            xss_context_source=xss_context_source,
            xss_context_ml_proba=xss_context_ml_proba,
            attempt_idx=0,
            top_k_used=0
        )

    @classmethod
    def from_injection(cls, t, family, probe_bundle, rec, inj, rank_source="ml", ml_family=None, ml_proba=None, ml_threshold=None, model_tag=None):
        def _get(obj, attr, default=None):
            try: 
                return getattr(obj, attr)
            except Exception: 
                return default

        signals = {
            "xss_context": _get(_get(probe_bundle, "xss"), "context", None),
            "sql_boolean_delta": _get(_get(probe_bundle, "sqli"), "boolean_delta", None),
            "sqli_error_based": ("sql_error" in (getattr(inj, "why", []) or [])),
            "redirect_influence": bool(300 <= (getattr(inj, "status", 0) or 0) < 400 and str(getattr(inj, "redirect_location","")).startswith(("http://","https://"))),
        }

        # Extract XSS context information
        xss_context = None
        xss_escaping = None
        xss_context_source = None
        xss_context_ml_proba = None
        
        if family == "xss" and hasattr(probe_bundle, "xss") and probe_bundle.xss:
            xss_context = _get(probe_bundle.xss, "xss_context", None)
            xss_escaping = _get(probe_bundle.xss, "xss_escaping", None)
            
            # Determine source and ML probability
            xss_context_ml = _get(probe_bundle.xss, "xss_context_ml", None)
            xss_context_rule = _get(probe_bundle.xss, "xss_context_rule", None)
            
            if xss_context_ml and xss_context_ml.get("pred"):
                xss_context_source = "ml"
                xss_context_ml_proba = xss_context_ml.get("proba")
            elif xss_context_rule:
                xss_context_source = "rule"

        # Sanitize response snippet
        response_snippet = getattr(inj, "response_snippet", "")
        response_snippet_text = html.escape(response_snippet)
        response_snippet_raw = base64.b64encode(response_snippet.encode('utf-8')).decode('ascii')

        return cls(
            family, t.url, t.method, t.param_in, t.param, rec["payload"], t.headers or {}, inj.status, response_snippet,
            signals,
            ["ml_ranked"] + (getattr(inj, "why", []) or []),
            score=rec.get("score"),
            p_cal=rec.get("p_cal"),
            validation=cls._create_validation_flags(signals),
            rank_source=rank_source,
            ml_family=ml_family,
            ml_proba=ml_proba,
            ml_threshold=ml_threshold,
            model_tag=model_tag,
            response_snippet_text=response_snippet_text,
            response_snippet_raw=response_snippet_raw,
            xss_context=xss_context,
            xss_escaping=xss_escaping,
            xss_context_source=xss_context_source,
            xss_context_ml_proba=xss_context_ml_proba,
            attempt_idx=0,  # Will be set by caller
            top_k_used=0    # Will be set by caller
        )

    def to_dict(self, evidence_id: str = None) -> Dict[str, Any]:
        """Convert to dictionary, optionally including evidence_id."""
        d = asdict(self)
        if evidence_id:
            d["evidence_id"] = evidence_id
        
        # Ensure telemetry defaults are set
        if d.get("attempt_idx") is None:
            d["attempt_idx"] = 0
        if d.get("top_k_used") is None:
            d["top_k_used"] = 0
        if d.get("rank_source") is None:
            why = d.get("why", [])
            d["rank_source"] = "probe_only" if any("probe" in str(code) for code in why) else "none"
        
        return d

def _sanitize_filename_component(component: str) -> str:
    """Sanitize a filename component by replacing unsafe characters with underscores."""
    return re.sub(r'[^a-zA-Z0-9_.-]+', '_', component)

def write_evidence(job_id: str, ev: EvidenceRow, probe_bundle=None) -> str:
    """Write evidence to file and return evidence_id."""
    jid = f"{job_id}".replace("/", "_")
    outdir = DATA_DIR / "jobs" / jid
    outdir.mkdir(parents=True, exist_ok=True)
    ts = int(time.time() * 1000)
    
    # Sanitize the param name for safe filename usage
    safe_param = _sanitize_filename_component(ev.param)
    evidence_id = f"{ts}_{ev.family}_{safe_param}"
    path = outdir / f"{evidence_id}.json"
    
    # Prepare evidence data
    evidence_data = asdict(ev)
    
    # Add detailed XSS context data if available
    if ev.family == "xss" and probe_bundle and hasattr(probe_bundle, "xss") and probe_bundle.xss:
        xss_probe = probe_bundle.xss
        evidence_data["xss_context_details"] = {
            "fragment_left_64": getattr(xss_probe, "fragment_left_64", ""),
            "fragment_right_64": getattr(xss_probe, "fragment_right_64", ""),
            "raw_reflection": getattr(xss_probe, "raw_reflection", ""),
            "in_script_tag": getattr(xss_probe, "in_script_tag", False),
            "in_attr": getattr(xss_probe, "in_attr", False),
            "attr_name": getattr(xss_probe, "attr_name", ""),
            "in_style": getattr(xss_probe, "in_style", False),
            "attr_quote": getattr(xss_probe, "attr_quote", ""),
            "content_type": getattr(xss_probe, "content_type", ""),
            "xss_context_rule": getattr(xss_probe, "xss_context_rule", None),
            "xss_context_ml": getattr(xss_probe, "xss_context_ml", None),
            "xss_escaping_ml": getattr(xss_probe, "xss_escaping_ml", None)
        }
    
    with open(path, "w", encoding="utf-8") as f:
        json.dump(evidence_data, f, ensure_ascii=False, indent=2)
    return evidence_id

def read_evidence(job_id: str, evidence_id: str) -> Dict[str, Any]:
    """Read evidence by job_id and evidence_id."""
    jid = f"{job_id}".replace("/", "_")
    outdir = DATA_DIR / "jobs" / jid
    path = outdir / f"{evidence_id}.json"
    
    if not path.exists():
        raise FileNotFoundError(f"Evidence not found: {evidence_id}")
    
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)