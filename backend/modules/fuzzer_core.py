# backend/modules/fuzzer_core.py
from __future__ import annotations

import json
import time
import os
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

from .targets import enumerate_targets, Target
from .probes.engine import run_probes
from .gates import gate_not_applicable, gate_candidate_xss, gate_candidate_sqli, gate_candidate_redirect
from .ml.infer_ranker import rank_payloads
from .ml.feature_spec import build_features
from .injector import inject_once
from .evidence import EvidenceRow, write_evidence
from .cvss_rules import cvss_for
from .playwright_crawler import crawl_site
from .confirmers import confirm_xss, confirm_sqli, confirm_redirect, oracle_from_signals
from backend.app_state import DATA_DIR

# Environment flags
REQUIRE_RANKER = os.getenv("ELISE_REQUIRE_RANKER", "0") == "1"

# Unified decision taxonomy
DECISION = dict(
    NA="not_applicable", 
    POS="positive",  # Changed from "confirmed" to "positive"
    SUS="suspected", 
    NEG="clean",  # Changed from "tested_negative" to "clean"
    ABS="abstain",
    ERR="error"  # New error state for network/infra failures
)

def unique_merge(existing_why, new_reasons):
    """Merge new reasons with existing ones, avoiding duplicates."""
    if not existing_why:
        return new_reasons
    combined = list(existing_why)
    for reason in new_reasons:
        if reason not in combined:
            combined.append(reason)
    return combined

def _confirmed_family(probe_bundle) -> Optional[tuple[str, str]]:
    """Determine if probe results confirm a vulnerability family using oracle-based confirmation."""
    signals = {
        "xss_context": getattr(probe_bundle.xss, "context", None),
        "redirect_influence": getattr(probe_bundle.redirect, "influence", None),
        "sqli_error_based": getattr(probe_bundle.sqli, "error_based", None),
        "sql_boolean_delta": getattr(probe_bundle.sqli, "boolean_delta", 0),
    }
    
    fired_family, reason_code = oracle_from_signals(signals)
    return (fired_family, reason_code) if fired_family else None

def _process_target(target: Target, job_id: str, top_k: int, results_lock: Lock, findings_lock: Lock, start_ts: float = None) -> Dict[str, Any]:
    """Process a single target and return the result."""
    try:
        if gate_not_applicable(target):
            return {"target": target.to_dict(), "decision": DECISION["NA"], "why": ["gate_not_applicable"]}
        
        # Run probes
        probe_bundle = run_probes(target)
        probe_result = _confirmed_family(probe_bundle)
        
        if probe_result:
            fam, reason_code = probe_result
            # Probe confirmed vulnerability - but still run ML for telemetry
            ev = EvidenceRow.from_probe_confirm(target, fam, probe_bundle)
            ev.cvss = cvss_for(fam, ev)
            ev.why = unique_merge(ev.why, [reason_code])
            
            # Run ML ranking for telemetry even for probe-confirmed vulnerabilities
            ctx = {
                "family": fam,
                "param_in": target.param_in,
                "param": target.param,
                "payload": "",
                "probe_sql_error": probe_bundle.sqli.error_based,
                "probe_timing_delta_gt2s": probe_bundle.sqli.time_based,
                "probe_reflection_html": probe_bundle.xss.reflected and probe_bundle.xss.context == "html",
                "probe_reflection_js": probe_bundle.xss.reflected and probe_bundle.xss.context == "js_string",
                "probe_redirect_location_reflects": probe_bundle.redirect.influence,
                "status_class": target.status // 100 if target.status else 0,
                "content_type_html": "text/html" in (target.content_type or ""),
                "content_type_json": "application/json" in (target.content_type or ""),
                "ctx_html": probe_bundle.xss.context == "html",
                "ctx_attr": probe_bundle.xss.context == "attr",
                "ctx_js": probe_bundle.xss.context == "js_string"
            }
            
            features = build_features(ctx)
            ranked = rank_payloads(fam, features, top_k=1)  # Just get ML telemetry
            
            # Extract ML telemetry
            rank_source = ranked[0].get("rank_source", "defaults") if ranked else "defaults"
            model_tag = ranked[0].get("model_tag") if ranked else None
            ml_proba = ranked[0].get("p_cal") if ranked else None
            threshold = {"xss": float(os.getenv("ELISE_TAU_XSS", "0.75")), 
                        "sqli": float(os.getenv("ELISE_TAU_SQLI", "0.70")), 
                        "redirect": float(os.getenv("ELISE_TAU_REDIRECT", "0.60"))}.get(fam, 0.5)
            
            # Log ML ranker usage
            if rank_source == "ml" and ranked:
                top_payload = ranked[0].get("payload", "")
                logging.info("ranker_used", extra={
                    "family": fam,
                    "model_tag": model_tag,
                    "threshold": threshold,
                    "top_payload": top_payload[:50] + "..." if len(top_payload) > 50 else top_payload,
                    "proba": ml_proba
                })
            
            evidence_id = write_evidence(job_id, ev)
            
            return {
                "target": target.to_dict(), 
                "family": fam, 
                "decision": DECISION["POS"], 
                "why": ["probe_proof", reason_code],
                "evidence_id": evidence_id,
                "cvss": ev.cvss,  # Pass through the CVSS from evidence
                "rank_source": rank_source,  # Use ML rank_source if available
                "ml_family": fam,
                "ml_proba": ml_proba,
                "ml_threshold": threshold,
                "model_tag": model_tag,
                "timing_ms": 0  # Probe-only results have no injection timing
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
        
        # Build context for ML ranking
        ctx = {
            "family": candidates[0] if candidates else "xss",  # Use first candidate for context
            "param_in": target.param_in,
            "param": target.param,
            "payload": "",  # Will be set per payload
            "probe_sql_error": probe_bundle.sqli.error_based,
            "probe_timing_delta_gt2s": probe_bundle.sqli.time_based,
            "probe_reflection_html": probe_bundle.xss.reflected and probe_bundle.xss.context == "html",
            "probe_reflection_js": probe_bundle.xss.reflected and probe_bundle.xss.context == "js_string",
            "probe_redirect_location_reflects": probe_bundle.redirect.influence,
            "status_class": target.status // 100 if target.status else 0,
            "content_type_html": "text/html" in (target.content_type or ""),
            "content_type_json": "application/json" in (target.content_type or ""),
            "ctx_html": probe_bundle.xss.context == "html",
            "ctx_attr": probe_bundle.xss.context == "attr",
            "ctx_js": probe_bundle.xss.context == "js_string"
        }
        
        # Build features and rank payloads
        features = build_features(ctx)
        
        # Check thresholds if configured
        tau_xss = float(os.getenv("ELISE_TAU_XSS", "0.75"))
        tau_sqli = float(os.getenv("ELISE_TAU_SQLI", "0.70"))
        tau_redirect = float(os.getenv("ELISE_TAU_REDIRECT", "0.60"))
        
        def below_threshold(fam, p_cal):
            """Check if p_cal is below family threshold."""
            threshold = {"xss": tau_xss, "sqli": tau_sqli, "redirect": tau_redirect}.get(fam, 0.5)
            return p_cal is not None and p_cal < threshold
        
        def budget_tight():
            """Check if budget is tight based on elapsed time."""
            if start_ts is None:
                return False
            job_budget_ms = int(os.getenv("ELISE_JOB_BUDGET_MS", "120000"))
            elapsed_ms = (time.time() - start_ts) * 1000.0
            return elapsed_ms >= 0.90 * job_budget_ms
        
        tried = []
        attempted_by_family = {}
        
        for fam in candidates:
            try:
                ranked = rank_payloads(fam, features, top_k=top_k or 3)
                attempted_by_family[fam] = len(ranked)
                
                # Get ML telemetry from first ranked item
                rank_source = ranked[0].get("rank_source", "defaults") if ranked else "defaults"
                model_tag = ranked[0].get("model_tag") if ranked else None
                
                # Get threshold for this family
                threshold = {"xss": tau_xss, "sqli": tau_sqli, "redirect": tau_redirect}.get(fam, 0.5)
                
                # Log ML ranker usage (once per family)
                if rank_source == "ml" and ranked:
                    top_payload = ranked[0].get("payload", "")
                    top_proba = ranked[0].get("p_cal", 0.0)
                    logging.info("ranker_used", extra={
                        "family": fam,
                        "model_tag": model_tag,
                        "threshold": threshold,
                        "top_payload": top_payload[:50] + "..." if len(top_payload) > 50 else top_payload,
                        "proba": top_proba
                    })
                
                for cand in ranked:
                    payload = cand.get("payload")
                    score = cand.get("score")
                    p_cal = cand.get("p_cal")
                    tried.append(payload)
                    
                    # Optional thresholds via env ELISE_TAU_*; if set and p_cal < tau, skip unless budget is abundant
                    if below_threshold(fam, p_cal) and budget_tight():
                        continue
                    
                    # Measure injection timing
                    inj_start = time.time()
                    inj = inject_once(target, fam, payload)
                    inj_timing_ms = int((time.time() - inj_start) * 1000)
                    
                    # Build comprehensive signals from probes + injection outcome
                    signals = {
                        "xss_context": getattr(probe_bundle.xss, "context", None) if probe_bundle else None,
                        "sql_boolean_delta": getattr(probe_bundle.sqli, "boolean_delta", None) if probe_bundle else None,
                        "sqli_error_based": ("sql_error" in (getattr(inj, "why", []) or [])),
                        "redirect_influence": bool(300 <= (getattr(inj, "status", 0) or 0) < 400 and str(getattr(inj, "redirect_location", "")).startswith(("http://","https://"))),
                    }
                    
                    # Determine which oracle actually fired (if any)
                    fired_family, reason_code = oracle_from_signals(signals)
                    
                    if fired_family:
                        # Create evidence with ML scores and correct family
                        ev = EvidenceRow.from_injection(
                            target, fired_family, probe_bundle, cand, inj,
                            rank_source=rank_source,
                            ml_family=fam,
                            ml_proba=p_cal,
                            ml_threshold=threshold,
                            model_tag=model_tag
                        )
                        ev.cvss = cvss_for(fired_family, ev)
                        ev.score = score
                        ev.p_cal = p_cal
                        ev.why = unique_merge(ev.why, ["ml_ranked", reason_code])
                        evidence_id = write_evidence(job_id, ev)
                        
                        return {
                            "target": target.to_dict(), 
                            "family": fired_family, 
                            "decision": DECISION["POS"], 
                            "why": unique_merge([], ["ml_ranked", reason_code]),
                            "evidence_id": evidence_id,
                            "cvss": ev.cvss,  # Pass through the CVSS from evidence
                            "rank_source": rank_source,
                            "ml_family": fam,
                            "ml_proba": p_cal,
                            "ml_threshold": threshold,
                            "model_tag": model_tag,
                            "timing_ms": inj_timing_ms
                        }
                        
            except RuntimeError as e:
                # If ranker fails and REQUIRE_RANKER is set, propagate the error
                if "ranker" in str(e).lower() and REQUIRE_RANKER:
                    raise e
                # Otherwise continue with next family
                continue
        
        # If none confirmed, mark auditable negative
        return {
            "target": target.to_dict(), 
            "decision": DECISION["NEG"], 
            "why": unique_merge([], ["ml_attempted", f"tried:{sum(attempted_by_family.values())}", "no_confirm_after_topk"]),
            "rank_source": "defaults",  # Default for negative results
            "ml_family": None,
            "ml_proba": None,
            "ml_threshold": None,
            "model_tag": None,
            "meta": {
                "ml_attempted_payloads": tried[:3],  # trim for payload privacy
                "attempted_by_family": attempted_by_family
            }
        }
        
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
    
    # Meta telemetry counters
    injections_attempted = 0
    injections_succeeded = 0
    errors_by_kind = {}
    rank_source_counts = {"probe_only": 0, "ml": 0, "defaults": 0}
    
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
                executor.submit(_process_target, target, job_id, top_k, results_lock, findings_lock, start_time): target
                for target in all_targets
            }
            
            # Collect results with time budget
            for future in as_completed(future_to_target, timeout=job_budget_ms/1000):
                if time.time() - start_time > job_budget_ms/1000:
                    break  # Time budget exceeded
                
                try:
                    result = future.result()
                    
                    # Track telemetry
                    if "meta" in result and "ml_attempted_payloads" in result["meta"]:
                        injections_attempted += len(result["meta"]["ml_attempted_payloads"])
                    if result.get("decision") == DECISION["POS"]:
                        injections_succeeded += 1
                    
                    # Track rank source counts
                    rank_source = result.get("rank_source")
                    if rank_source in rank_source_counts:
                        rank_source_counts[rank_source] += 1
                    
                    # Extract path from URL
                    from urllib.parse import urlparse
                    parsed_url = urlparse(result["target"]["url"])
                    path = parsed_url.path or "/"
                    
                    # Create slim result row
                    slim_result = {
                        "evidence_id": result.get("evidence_id"),
                        "url": result["target"]["url"],
                        "path": path,
                        "method": result["target"]["method"],
                        "param_in": result["target"]["param_in"],
                        "param": result["target"]["param"],
                        "family": result.get("family"),
                        "decision": result["decision"],
                        "why": result["why"],
                        "cvss": result.get("cvss", {"base": 0.0}),
                        "rank_source": result.get("rank_source"),
                        "ml_family": result.get("ml_family"),
                        "ml_proba": result.get("ml_proba"),
                        "ml_threshold": result.get("ml_threshold"),
                        "model_tag": result.get("model_tag"),
                        "timing_ms": result.get("timing_ms", 0),
                        "status": result["target"].get("status", 0)
                    }
                    results.append(slim_result)
                    
                    # Add to findings if positive
                    if result.get("decision") == DECISION["POS"] and result.get("evidence_id"):
                        findings.append(result["evidence_id"])
                        
                except Exception as e:
                    target = future_to_target[future]
                    error_type = "processing_error"
                    errors_by_kind[error_type] = errors_by_kind.get(error_type, 0) + 1
                    
                    results.append({
                        "evidence_id": None,
                        "url": target.url,
                        "path": "",
                        "method": target.method,
                        "param_in": target.param_in,
                        "param": target.param,
                        "family": None,
                        "decision": DECISION["ERR"],
                        "why": [f"processing_error: {str(e)}"],
                        "cvss": {"base": 0.0},
                        "rank_source": None,
                        "ml_family": None,
                        "ml_proba": None,
                        "ml_threshold": None,
                        "model_tag": None,
                        "timing_ms": 0,
                        "status": 0
                    })
    
    # Calculate targets_enumerated (total targets that were actually tested)
    targets_enumerated = len(results) - endpoints_without_params
    
    # Create findings aggregates by family
    findings_by_family = {}
    for result in results:
        if result.get("decision") == DECISION["POS"] and result.get("family"):
            family = result["family"]
            if family not in findings_by_family:
                findings_by_family[family] = {
                    "family": family,
                    "total": 0,
                    "positives": 0,
                    "suspected": 0,
                    "examples": []
                }
            findings_by_family[family]["total"] += 1
            findings_by_family[family]["positives"] += 1
            if result.get("evidence_id") and len(findings_by_family[family]["examples"]) < 3:
                findings_by_family[family]["examples"].append(result["evidence_id"])
    
    # Convert to list
    findings_aggregates = list(findings_by_family.values())
    
    meta = {
        "endpoints_supplied": endpoints_crawled,
        "targets_enumerated": targets_enumerated,
        "injections_attempted": injections_attempted,
        "injections_succeeded": injections_succeeded,
        "budget_ms_used": int((time.time() - start_time) * 1000),
        "errors_by_kind": errors_by_kind,
        "top_k_used": top_k,
        "rank_source_counts": rank_source_counts
    }
    
    return {
        "results": results, 
        "findings": findings_aggregates, 
        "job_id": job_id, 
        "meta": meta
    }
