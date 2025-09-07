from typing import Any, Dict, List, Optional
from backend.modules.targets import enumerate_targets, Target
from backend.modules.probes.engine import run_probes
from backend.modules.gates import gate_not_applicable, gate_candidate_xss, gate_candidate_sqli, gate_candidate_redirect
from backend.modules.ml.infer_ranker import rank_payloads
from backend.modules.injector import inject_once
from backend.modules.evidence import EvidenceRow, write_evidence
from backend.modules.cvss_rules import cvss_for

DECISION = dict(NA="not_applicable", POS="confirmed", SUS="suspected", NEG="tested_negative", ABS="abstain")

def _confirmed_family(p)->Optional[str]:
    if p.redirect.influence: return "redirect"
    if p.xss.reflected and p.xss.context in {"html","attr","js_string"}: return "xss"
    if p.sqli.error_based or p.sqli.time_based or p.sqli.boolean_delta>0.6: return "sqli"
    return None

def assess_endpoints(endpoints: List[Dict[str,Any]], job_id: str, top_k:int=3)->Dict[str,Any]:
    # Count endpoints and handle zero-parameter endpoints
    endpoints_crawled = len(endpoints)
    endpoints_without_params = 0
    results, findings = [], []
    
    # Process each endpoint
    for ep in endpoints:
        targets = list(enumerate_targets(ep))
        
        # If no targets (no parameters), mark as not_applicable
        if not targets:
            endpoints_without_params += 1
            results.append({
                "target": {
                    "url": ep.get("url", ""),
                    "method": ep.get("method", "GET"),
                    "param_in": "none",
                    "param": "none",
                    "headers": ep.get("headers", {}),
                    "status": ep.get("status"),
                    "content_type": ep.get("content_type"),
                    "base_params": {}
                },
                "decision": DECISION["NA"],
                "why": ["no_parameters_detected"]
            })
            continue
        
        # Process targets for this endpoint
        for t in targets:
            if gate_not_applicable(t):
                results.append({"target": t.to_dict(), "decision": DECISION["NA"], "why":["gate_not_applicable"]}); continue
            probe = run_probes(t)
            fam = _confirmed_family(probe)
            if fam:
                ev = EvidenceRow.from_probe_confirm(t, fam, probe)
                ev.cvss = cvss_for(fam, ev)
                path = write_evidence(job_id, ev)
                findings.append(ev.to_dict(path))
                results.append({"target": t.to_dict(), "family": fam, "decision": DECISION["POS"], "why":["probe_proof"]})
                continue
            candidates = []
            if gate_candidate_xss(t): candidates.append("xss")
            if gate_candidate_sqli(t): candidates.append("sqli")
            if gate_candidate_redirect(t): candidates.append("redirect")
            if not candidates:
                results.append({"target": t.to_dict(), "decision": DECISION["ABS"], "why":["no_candidates"]}); continue
            confirmed = False
            for fam in candidates:
                payloads = rank_payloads(fam, endpoint_meta=t.to_features(), top_k=top_k)
                for rec in payloads:
                    inj = inject_once(t, fam, rec["payload"])
                    if inj.confirmed:
                        ev = EvidenceRow.from_injection(t, fam, probe, rec, inj)
                        ev.cvss = cvss_for(fam, ev)
                        path = write_evidence(job_id, ev)
                        findings.append(ev.to_dict(path))
                        results.append({"target": t.to_dict(), "family": fam, "decision": DECISION["POS"], "why":["ml_ranked","inject_confirmed"], "p": rec.get("p_cal")})
                        confirmed = True; break
                if confirmed: break
            if not confirmed:
                results.append({"target": t.to_dict(), "decision": DECISION["NEG"], "why":["no_confirm_after_topk"]})
    
    # Calculate targets_enumerated (total targets that were actually tested)
    targets_enumerated = len(results) - endpoints_without_params
    
    summary = {
        "total": len(results),
        "positive": sum(r["decision"]==DECISION["POS"] for r in results),
        "suspected": sum(r["decision"]==DECISION["SUS"] for r in results),
        "abstain": sum(r["decision"]==DECISION["ABS"] for r in results),
        "na": sum(r["decision"]==DECISION["NA"] for r in results),
    }
    
    meta = {
        "endpoints_crawled": endpoints_crawled,
        "targets_enumerated": targets_enumerated,
        "endpoints_without_params": endpoints_without_params
    }
    
    return {"summary": summary, "results": results, "findings": findings, "job_id": job_id, "meta": meta}