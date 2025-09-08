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
            response_snippet_raw=response_snippet_raw
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
            response_snippet_raw=response_snippet_raw
        )

    def to_dict(self, evidence_id: str = None) -> Dict[str, Any]:
        """Convert to dictionary, optionally including evidence_id."""
        d = asdict(self)
        if evidence_id:
            d["evidence_id"] = evidence_id
        return d

def _sanitize_filename_component(component: str) -> str:
    """Sanitize a filename component by replacing unsafe characters with underscores."""
    return re.sub(r'[^a-zA-Z0-9_.-]+', '_', component)

def write_evidence(job_id: str, ev: EvidenceRow) -> str:
    """Write evidence to file and return evidence_id."""
    jid = f"{job_id}".replace("/", "_")
    outdir = DATA_DIR / "jobs" / jid
    outdir.mkdir(parents=True, exist_ok=True)
    ts = int(time.time() * 1000)
    
    # Sanitize the param name for safe filename usage
    safe_param = _sanitize_filename_component(ev.param)
    evidence_id = f"{ts}_{ev.family}_{safe_param}"
    path = outdir / f"{evidence_id}.json"
    
    with open(path, "w", encoding="utf-8") as f:
        json.dump(asdict(ev), f, ensure_ascii=False, indent=2)
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