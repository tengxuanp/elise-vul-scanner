from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict
import json, time, re, os
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
        return cls(
            family, t.url, t.method, t.param_in, t.param, "<probe>", t.headers or {}, 200, "<probe_confirmed>",
            signals,
            ["probe_proof"],
            validation=cls._create_validation_flags(signals)
        )

    @classmethod
    def from_injection(cls, t, family, probe_bundle, rec, inj):
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

        return cls(
            family, t.url, t.method, t.param_in, t.param, rec["payload"], t.headers or {}, inj.status, inj.response_snippet,
            signals,
            ["ml_ranked"] + (getattr(inj, "why", []) or []),
            score=rec.get("score"),
            p_cal=rec.get("p_cal"),
            validation=cls._create_validation_flags(signals)
        )

    def to_dict(self, path:str)->Dict[str,Any]:
        d = asdict(self); d["artifact_path"]=path; return d

def _sanitize_filename_component(component: str) -> str:
    """Sanitize a filename component by replacing unsafe characters with underscores."""
    return re.sub(r'[^a-zA-Z0-9_.-]+', '_', component)

def write_evidence(job_id:str, ev:EvidenceRow)->str:
    jid = f"{job_id}".replace("/","_")
    outdir = DATA_DIR / "jobs" / jid
    outdir.mkdir(parents=True, exist_ok=True)
    ts = int(time.time()*1000)
    
    # Sanitize the param name for safe filename usage
    safe_param = _sanitize_filename_component(ev.param)
    path = outdir / f"{ts}_{ev.family}_{safe_param}.json"
    
    with open(path,"w",encoding="utf-8") as f:
        json.dump(asdict(ev), f, ensure_ascii=False, indent=2)
    return str(path)