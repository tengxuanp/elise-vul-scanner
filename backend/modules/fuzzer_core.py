# backend/modules/fuzzer_core.py
from __future__ import annotations

import json
import time
import os
from pathlib import Path
from typing import Dict, Any, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

from .targets import enumerate_targets, Target
from .probes.engine import run_probes
from .gates import gate_not_applicable, gate_candidate_xss, gate_candidate_sqli, gate_candidate_redirect
from .ml.infer_ranker import rank_payloads
from .injector import inject_once
from .evidence import EvidenceRow, write_evidence
from .cvss_rules import cvss_for
from .playwright_crawler import crawl_site
from backend.app_state import DATA_DIR

DECISION = dict(NA="not_applicable", POS="confirmed", SUS="suspected", NEG="tested_negative", ABS="abstain")

def _confirmed_family(probe_bundle) -> Optional[str]:
    """Determine if probe results confirm a vulnerability family."""
    if probe_bundle.redirect.influence:
        return "redirect"
    if probe_bundle.xss.reflected and probe_bundle.xss.context in {"html", "attr", "js_string"}:
        return "xss"
    if probe_bundle.sqli.error_based or probe_bundle.sqli.time_based or probe_bundle.sqli.boolean_delta > 0.6:
        return "sqli"
    return None

def _process_target(target: Target, job_id: str, top_k: int, results_lock: Lock, findings_lock: Lock) -> Dict[str, Any]:
    """Process a single target and return the result."""
    try:
        if gate_not_applicable(target):
            return {"target": target.to_dict(), "decision": DECISION["NA"], "why": ["gate_not_applicable"]}
        
        # Run probes
        probe_bundle = run_probes(target)
        fam = _confirmed_family(probe_bundle)
        
        if fam:
            # Probe confirmed vulnerability
            ev = EvidenceRow.from_probe_confirm(target, fam, probe_bundle)
            ev.cvss = cvss_for(fam, ev)
            path = write_evidence(job_id, ev)
            
            with findings_lock:
                # This would need to be handled differently in a real implementation
                # For now, we'll return the evidence data
                pass
            
            return {
                "target": target.to_dict(), 
                "family": fam, 
                "decision": DECISION["POS"], 
                "why": ["probe_proof"],
                "evidence": ev.to_dict(path)
            }
        
        # ML payload ranking and injection
        candidates = []
        if gate_candidate_xss(target):
            candidates.append("xss")
        if gate_candidate_sqli(target):
            candidates.append("sqli")
        if gate_candidate_redirect(target):
            candidates.append("redirect")
        
        if not candidates:
            return {"target": target.to_dict(), "decision": DECISION["ABS"], "why": ["no_candidates"]}
        
        confirmed = False
        for fam in candidates:
            # ML ranker
            payloads = rank_payloads(fam, endpoint_meta=target.to_features(), top_k=top_k)
            
            for rec in payloads:
                # Evidence sink
                inj = inject_once(target, fam, rec["payload"])
                if inj.confirmed:
                    ev = EvidenceRow.from_injection(target, fam, probe_bundle, rec, inj)
                    ev.cvss = cvss_for(fam, ev)
                    path = write_evidence(job_id, ev)
                    
                    with findings_lock:
                        # This would need to be handled differently in a real implementation
                        pass
                    
                    return {
                        "target": target.to_dict(), 
                        "family": fam, 
                        "decision": DECISION["POS"], 
                        "why": ["ml_ranked", "inject_confirmed"], 
                        "p": rec.get("p_cal"),
                        "evidence": ev.to_dict(path)
                    }
        
        return {"target": target.to_dict(), "decision": DECISION["NEG"], "why": ["no_confirm_after_topk"]}
        
    except Exception as e:
        return {"target": target.to_dict(), "decision": DECISION["ABS"], "why": [f"error: {str(e)}"]}

def run_job(target_url: str, job_id: str, max_depth: int = 2, max_endpoints: int = 30, top_k: int = 3) -> Dict[str, Any]:
    """
    Single entrypoint for vulnerability assessment job with parallelization.
    Handles: crawl → probe → ML ranker → evidence sink
    """
    start_time = time.time()
    job_budget_ms = int(os.getenv("ELISE_JOB_BUDGET_MS", "300000"))  # 5 minutes default
    
    # Step 1: Crawl the target
    crawl_result = crawl_site(
        target_url=target_url,
        max_depth=max_depth,
        max_endpoints=max_endpoints,
        submit_get_forms=True,
        submit_post_forms=True,
        click_buttons=True
    )
    
    endpoints = crawl_result.get("endpoints", [])
    endpoints_crawled = len(endpoints)
    endpoints_without_params = 0
    results, findings = [], []
    
    # Collect all targets for parallel processing
    all_targets = []
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
        else:
            all_targets.extend(targets)
    
    # Process targets in parallel with time budget
    if all_targets:
        max_workers = min(8, len(all_targets))  # Bounded to 8 workers
        results_lock = Lock()
        findings_lock = Lock()
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_target = {
                executor.submit(_process_target, target, job_id, top_k, results_lock, findings_lock): target
                for target in all_targets
            }
            
            # Collect results with time budget
            for future in as_completed(future_to_target, timeout=job_budget_ms/1000):
                if time.time() - start_time > job_budget_ms/1000:
                    break  # Time budget exceeded
                
                try:
                    result = future.result()
                    results.append(result)
                    
                    # Extract evidence if present
                    if "evidence" in result:
                        findings.append(result["evidence"])
                        
                except Exception as e:
                    target = future_to_target[future]
                    results.append({
                        "target": target.to_dict(), 
                        "decision": DECISION["ABS"], 
                        "why": [f"processing_error: {str(e)}"]
                    })
    
    # Calculate targets_enumerated (total targets that were actually tested)
    targets_enumerated = len(results) - endpoints_without_params
    
    summary = {
        "total": len(results),
        "positive": sum(r["decision"] == DECISION["POS"] for r in results),
        "suspected": sum(r["decision"] == DECISION["SUS"] for r in results),
        "abstain": sum(r["decision"] == DECISION["ABS"] for r in results),
        "na": sum(r["decision"] == DECISION["NA"] for r in results),
    }
    
    meta = {
        "endpoints_crawled": endpoints_crawled,
        "targets_enumerated": targets_enumerated,
        "endpoints_without_params": endpoints_without_params,
        "processing_time_ms": int((time.time() - start_time) * 1000)
    }
    
    return {
        "summary": summary, 
        "results": results, 
        "findings": findings, 
        "job_id": job_id, 
        "meta": meta
    }
