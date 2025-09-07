from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict
import json, time
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

    @classmethod
    def from_probe_confirm(cls, t, family, probe_bundle):
        p = probe_bundle
        return cls(
            family, t.url, t.method, t.param_in, t.param, "<probe>", t.headers or {}, 200, "<probe_confirmed>",
            {
              "xss_context": getattr(p.xss, "context", None),
              "redirect_influence": getattr(p.redirect, "influence", None),
              "sqli_error_based": getattr(p.sqli, "error_based", None),
            },
            ["probe_proof"],
        )

    @classmethod
    def from_injection(cls, t, family, probe_bundle, rec, inj):
        return cls(
            family, t.url, t.method, t.param_in, t.param, rec["payload"], t.headers or {}, inj.status, inj.response_snippet,
            {
              "xss_context": getattr(probe_bundle.xss, "context", None),
              "sql_boolean_delta": getattr(probe_bundle.sqli, "boolean_delta", None),
            },
            ["ml_ranked"] + inj.why,
        )

    def to_dict(self, path:str)->Dict[str,Any]:
        d = asdict(self); d["artifact_path"]=path; return d

def write_evidence(job_id:str, ev:EvidenceRow)->str:
    jid = f"{job_id}".replace("/","_")
    outdir = DATA_DIR / "jobs" / jid
    outdir.mkdir(parents=True, exist_ok=True)
    ts = int(time.time()*1000)
    path = outdir / f"{ts}_{ev.family}_{ev.param}.json"
    with open(path,"w",encoding="utf-8") as f:
        json.dump(asdict(ev), f, ensure_ascii=False, indent=2)
    return str(path)