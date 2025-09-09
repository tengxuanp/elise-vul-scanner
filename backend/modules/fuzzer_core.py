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
from collections import defaultdict
from unittest.mock import Mock

# Import the new event aggregator
from backend.modules.event_aggregator import get_aggregator

def record_probe_attempt(target_id: str, family: str, success: bool):
    """Record a probe attempt event."""
    aggregator = get_aggregator()
    aggregator.record_probe_attempt(success)

def record_inject_attempt(target_id: str, family: str, success: bool):
    """Record an injection attempt event."""
    aggregator = get_aggregator()
    aggregator.record_inject_attempt(success)

def get_event_totals() -> Dict[str, int]:
    """Get total counts from all events."""
    aggregator = get_aggregator()
    return {
        "probe_attempts": aggregator.probe_attempts,
        "probe_successes": aggregator.probe_successes,
        "inject_attempts": aggregator.inject_attempts,
        "inject_successes": aggregator.inject_successes
    }

def clear_event_aggregator():
    """Clear the event aggregator (for testing)."""
    aggregator = get_aggregator()
    aggregator.reset()

from .targets import enumerate_targets, Target
from .probes.engine import run_probes
from .gates import gate_not_applicable, gate_candidate_xss, gate_candidate_sqli, gate_candidate_redirect
from .ml.infer_ranker import rank_payloads
from .strategy import probe_enabled, injections_enabled
from .ml.feature_spec import build_features
from .injector import inject_once
from .evidence import EvidenceRow, write_evidence
from .cvss_rules import cvss_for
from .playwright_crawler import crawl_site
from .confirmers import confirm_xss, confirm_sqli, confirm_redirect, oracle_from_signals
from backend.app_state import DATA_DIR

def _ensure_telemetry_defaults(result: Dict[str, Any]) -> Dict[str, Any]:
    """Ensure all result rows have non-null telemetry defaults."""
    # Decision canonicalization
    CANON = {"clean": "abstain", "not_vulnerable": "abstain"}
    decision = result.get("decision", "")
    if isinstance(decision, str):
        result["decision"] = CANON.get(decision.lower(), decision)
    
    # Set attempt_idx default
    result.setdefault("attempt_idx", 0)
    
    # Set top_k_used default
    result.setdefault("top_k_used", 0)
    
    # Set rank_source default based on result type
    if result.get("rank_source") is None:
        # Determine rank_source based on decision and provenance
        decision = result.get("decision")
        why = result.get("why", [])
        if decision == DECISION["POS"] and any("probe" in str(code) for code in why):
            result["rank_source"] = "probe_only"
        else:
            result["rank_source"] = "none"
    
    return result

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

def _process_target(target: Target, job_id: str, top_k: int, results_lock: Lock, findings_lock: Lock, start_ts: float = None, plan = None) -> Dict[str, Any]:
    """Process a single target and return the result."""
    violations = []  # Track strategy violations
    try:
        if gate_not_applicable(target):
            target_dict = target.to_dict()
            # Ensure NA results have proper param_in and param values for UI display
            if not target_dict.get("param_in") or target_dict.get("param_in") == "":
                target_dict["param_in"] = "none"
            if not target_dict.get("param") or target_dict.get("param") == "":
                target_dict["param"] = "none"
            return _ensure_telemetry_defaults({"target": target_dict, "decision": DECISION["NA"], "why": ["gate_not_applicable"]})
        
        # Run probes (with strategy enforcement)
        probe_bundle = None
        probe_result = None
        target_id = f"{target.url}:{target.param_in}:{target.param}"
        
        # Check if probes are enabled for any family
        families_to_probe = []
        if plan is None:
            # Fallback behavior when no plan is provided
            families_to_probe = ["xss", "sqli", "redirect"]
            probe_bundle = run_probes(target, families_to_probe)
            probe_result = _confirmed_family(probe_bundle)
        else:
            # Only run probes for enabled families
            families_to_probe = [family for family in ["xss", "sqli", "redirect"] if probe_enabled(plan, family)]
            if families_to_probe:
                probe_bundle = run_probes(target, families_to_probe)
                probe_result = _confirmed_family(probe_bundle)
            else:
                # No probes enabled by strategy - create empty probe bundle
                families_to_probe = []
                # Create proper Mock objects for probe families
                xss_mock = Mock()
                xss_mock.reflected = False
                xss_mock.context = None
                xss_mock.xss_context = None
                xss_mock.xss_escaping = None
                
                sqli_mock = Mock()
                sqli_mock.error_based = False
                sqli_mock.time_based = False
                sqli_mock.boolean_delta = 0
                
                redirect_mock = Mock()
                redirect_mock.influence = False
                
                probe_bundle = Mock()
                probe_bundle.xss = xss_mock
                probe_bundle.sqli = sqli_mock
                probe_bundle.redirect = redirect_mock
                probe_bundle.error_based = None
                probe_result = None
        
        # Record probe attempts only for families that were actually probed
        if probe_result:
            fam, reason_code = probe_result
            if plan is None or probe_enabled(plan, fam):
                # For ml_with_context strategy, XSS probes are signals only, not successes
                if plan and plan.name == "ml_with_context" and fam == "xss":
                    record_probe_attempt(target_id, fam, False)  # Record as attempt but not success
                else:
                    record_probe_attempt(target_id, fam, True)
            else:
                # Strategy violation: probe ran for disabled family
                logging.warning(f"Strategy violation: {fam} probe ran when disabled by strategy {plan.name}")
        elif probe_bundle is not None:
            # Record probe attempt for each family that was probed
            for family in families_to_probe:
                if (plan is None or probe_enabled(plan, family)) and hasattr(probe_bundle, family) and getattr(probe_bundle, family):
                    record_probe_attempt(target_id, family, False)
                elif plan is not None and not probe_enabled(plan, family) and hasattr(probe_bundle, family) and getattr(probe_bundle, family):
                    # Strategy violation: probe ran for disabled family
                    logging.warning(f"Strategy violation: {family} probe ran when disabled by strategy {plan.name}")
        
        if probe_result:
            fam, reason_code = probe_result
            
            # For ml_with_context strategy, XSS probes are signals only, not confirmed findings
            if plan and plan.name == "ml_with_context" and fam == "xss":
                # XSS probe is a signal for context classification - don't create a confirmed result
                # Just record the probe attempt and continue to ML injections
                logging.info("XSS probe signal for context classification", extra={
                    "family": fam,
                    "reason_code": reason_code,
                    "strategy": plan.name
                })
                # Continue to ML injections below
                pass
            else:
                # Probe confirmed vulnerability - decision from probe proof, not ML
                ev = EvidenceRow.from_probe_confirm(target, fam, probe_bundle)
                ev.cvss = cvss_for(fam, ev)
                ev.why = unique_merge(ev.why, [reason_code])
                evidence_id = write_evidence(job_id, ev, probe_bundle)
                
                # Log confirm event
                logging.info("confirm", extra={
                    "family": fam,
                    "rank_source": "probe_only",
                    "reason_code": reason_code,
                    "evidence_id": evidence_id
                })

                result_dict = {
                    "target": target.to_dict(), 
                    "family": fam, 
                    "decision": DECISION["POS"], 
                    "why": ["probe_proof", reason_code],
                    "evidence_id": evidence_id,
                    "cvss": ev.cvss,  # Pass through the CVSS from evidence
                    "rank_source": "probe_only",  # Decision from probe, not ML
                    "ml_role": None,
                    "gated": False,
                    "ml_family": None,
                "ml_proba": None,
                "ml_threshold": None,
                "model_tag": None,
                "attempt_idx": None,
                "top_k_used": None,
                "timing_ms": 0  # Probe-only results have no injection timing
                }
                
                # Add XSS context fields if this is an XSS finding
                if fam == "xss":
                    result_dict.update({
                        "xss_context": ev.xss_context,
                        "xss_escaping": ev.xss_escaping,
                        "xss_context_source": ev.xss_context_source,
                        "xss_context_ml_proba": ev.xss_context_ml_proba
                    })
                    
                    # Add param information from XSS probe if available
                    if hasattr(probe_bundle, "xss") and probe_bundle.xss:
                        xss_probe = probe_bundle.xss
                        if hasattr(xss_probe, "param_in") and hasattr(xss_probe, "param"):
                            result_dict.update({
                                "param_in": xss_probe.param_in,
                                "param": xss_probe.param
                            })
                
                # Add param information for redirect findings
                elif fam == "redirect":
                    if hasattr(probe_bundle, "redirect") and probe_bundle.redirect:
                        redirect_probe = probe_bundle.redirect
                        if hasattr(redirect_probe, "param_in") and hasattr(redirect_probe, "param"):
                            result_dict.update({
                                "param_in": redirect_probe.param_in,
                                "param": redirect_probe.param
                            })
            
            # Optional demo flag: force one context injection after XSS reflection
            force_context_inject = os.getenv("XSS_FORCE_CONTEXT_INJECT_ON_REFLECTION", "false").lower() == "true"
            if force_context_inject and fam == "xss" and hasattr(probe_bundle, "xss") and probe_bundle.xss:
                xss_probe = probe_bundle.xss
                if hasattr(xss_probe, "xss_context") and hasattr(xss_probe, "xss_escaping"):
                    try:
                        from backend.modules.payloads import payload_pool_for_xss
                        context_payloads = payload_pool_for_xss(xss_probe.xss_context, xss_probe.xss_escaping)
                        if context_payloads:
                            # Try one context-aware payload
                            demo_payload = context_payloads[0]
                            record_inject_attempt(target_id, "xss", False)
                            
                            inj_start = time.perf_counter()
                            inj = inject_once(target, "xss", demo_payload)
                            inj_timing_ms = int((time.perf_counter() - inj_start) * 1000)
                            
                            # Check if it succeeded (simplified check)
                            if hasattr(inj, "status") and inj.status == 200:
                                record_inject_attempt(target_id, "xss", True)
                    except Exception as e:
                        logging.warning(f"Demo context injection failed: {e}")
            
            # For ml_with_context strategy, we still want to run ML injections
            # even when probes confirm vulnerabilities
            if plan and plan.name == "ml_with_context":
                # Continue to ML injections below, but store the probe result
                probe_confirmed_family = fam
                # Create a minimal result_dict for ml_with_context strategy
                probe_confirmed_evidence = {
                    "target": target.to_dict(),
                    "family": fam,
                    "decision": DECISION["POS"],
                    "why": ["probe_proof", reason_code],
                    "evidence_id": None,  # Will be set if needed
                    "cvss": None,
                    "rank_source": "probe_only",
                    "ml_role": None,
                    "gated": False,
                    "ml_family": None,
                    "ml_proba": None,
                    "ml_threshold": None,
                    "model_tag": None,
                    "attempt_idx": None,
                    "top_k_used": None,
                    "timing_ms": 0
                }
            else:
                # For other strategies, return probe result immediately
                return _ensure_telemetry_defaults(result_dict)
        
        # ML payload ranking and injection (with strategy enforcement)
        candidates = []
        if gate_candidate_xss(target):
            candidates.append("xss")
        if gate_candidate_sqli(target):
            candidates.append("sqli")
        
        # For ml_with_context strategy, exclude redirect family entirely
        if plan and plan.name == "ml_with_context":
            # Only XSS and SQLi candidates allowed
            if "redirect" in candidates:
                candidates.remove("redirect")
                violations.append("strategy_violation:redirect_under_ml_with_context")
        else:
            # For other strategies, include redirect
            if gate_candidate_redirect(target):
                candidates.append("redirect")
        
        # Check if injections are enabled by strategy
        if plan is not None and not injections_enabled(plan):
            # Strategy disables injections - return abstain
            return _ensure_telemetry_defaults({
                "target": target.to_dict(), 
                "decision": DECISION["ABS"], 
                "why": ["injections_disabled_by_strategy"],
                "cvss": None,
                "rank_source": "none",
                "ml_role": None,
                "gated": False,
                "ml_family": None,
                "ml_proba": None,
                "ml_threshold": None,
                "model_tag": None,
                "attempt_idx": 0,
                "top_k_used": 0,
                "timing_ms": 0
            })
        
        if not candidates:
            return _ensure_telemetry_defaults({
                "target": target.to_dict(), 
                "decision": DECISION["ABS"], 
                "why": ["no_candidates"],
                "cvss": None,
                "rank_source": None,  # No candidates means no ranking
                "ml_role": None,
                "gated": False,
                "ml_family": None,
                "ml_proba": None,
                "ml_threshold": None,
                "model_tag": None,
                "attempt_idx": None,
                "top_k_used": None,
                "timing_ms": 0
            })
        
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
        ml_used = False
        fallback_reason = None
        
        for fam in candidates:
            try:
                # Extract XSS context information if available
                xss_context = None
                xss_escaping = None
                if fam == "xss" and hasattr(probe_bundle, "xss") and probe_bundle.xss:
                    xss_context = getattr(probe_bundle.xss, "xss_context", None)
                    xss_escaping = getattr(probe_bundle.xss, "xss_escaping", None)
                
                ranked = rank_payloads(fam, features, top_k=top_k or 3, xss_context=xss_context, xss_escaping=xss_escaping)
                attempted_by_family[fam] = len(ranked)
                
                # Get ML telemetry from first ranked item
                rank_source = ranked[0].get("rank_source", "defaults") if ranked else "defaults"
                
                # Record context pool usage if ctx_pool is used
                if rank_source == "ctx_pool":
                    from backend.modules.event_aggregator import get_aggregator
                    aggregator = get_aggregator()
                    aggregator.record_context_pool_usage()
                model_tag = ranked[0].get("model_tag") if ranked else None
                
                # Get threshold for this family
                threshold = {"xss": tau_xss, "sqli": tau_sqli, "redirect": tau_redirect}.get(fam, 0.5)
                
                # Log ML ranker usage (once per family)
                if rank_source == "ml" and ranked:
                    ml_used = True
                    top_payload = ranked[0].get("payload", "")
                    top_proba = ranked[0].get("p_cal", 0.0)
                    logging.info("ranker_used", extra={
                        "family": fam,
                        "model_tag": model_tag,
                        "threshold": threshold,
                        "top_payload": top_payload[:50] + "..." if len(top_payload) > 50 else top_payload,
                        "proba": top_proba
                    })
                
                # Process ranked payloads for injection
                for attempt_idx, cand in enumerate(ranked):
                    payload = cand.get("payload")
                    score = cand.get("score")
                    p_cal = cand.get("p_cal")
                    tried.append(payload)
                    
                    # Optional thresholds via env ELISE_TAU_*; if set and p_cal < tau, skip unless budget is abundant
                    if below_threshold(fam, p_cal) and budget_tight():
                        continue
                    
                    # Measure injection timing using perf_counter for better precision
                    inj_start = time.perf_counter()
                    inj = inject_once(target, fam, payload)
                    inj_timing_ms = int((time.perf_counter() - inj_start) * 1000)
                    
                    # Record injection attempt
                    record_inject_attempt(target_id, fam, False)  # Will be updated to True if successful
                    
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
                        # Update injection attempt to success
                        record_inject_attempt(target_id, fam, True)
                        
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
                        evidence_id = write_evidence(job_id, ev, probe_bundle)
                        
                        # Log confirm event
                        logging.info("confirm", extra={
                            "family": fired_family,
                            "rank_source": rank_source,
                            "reason_code": reason_code,
                            "evidence_id": evidence_id,
                            "ml_proba": p_cal if rank_source == "ml" else None,
                            "attempt_idx": attempt_idx if rank_source == "ml" else None
                        })
                        
                        result_dict = {
                            "target": target.to_dict(), 
                            "family": fired_family, 
                            "decision": DECISION["POS"], 
                            "why": unique_merge([], ["ml_ranked", reason_code]),
                            "evidence_id": evidence_id,
                            "cvss": ev.cvss,  # Pass through the CVSS from evidence
                            "rank_source": rank_source,  # "ml" if ML ranked, "defaults" if fallback
                            "ml_role": "prioritization" if rank_source == "ml" else None,
                            "gated": False,
                            "ml_family": fam if rank_source == "ml" else None,
                            "ml_proba": p_cal if rank_source == "ml" else None,
                            "ml_threshold": threshold if rank_source == "ml" else None,
                            "model_tag": model_tag if rank_source == "ml" else None,
                            "attempt_idx": (attempt_idx + 1) if rank_source in ["ml", "ctx_pool"] else None,
                            "top_k_used": len(ranked) if rank_source in ["ml", "ctx_pool"] else None,
                            "timing_ms": inj_timing_ms
                        }
                        
                        # Add XSS context fields if this is an XSS finding
                        if fired_family == "xss":
                            result_dict.update({
                                "xss_context": ev.xss_context,
                                "xss_escaping": ev.xss_escaping,
                                "xss_context_source": ev.xss_context_source,
                                "xss_context_ml_proba": ev.xss_context_ml_proba
                            })
                        
                        return result_dict
                        
            except Exception as e:
                # If ML ranking fails, continue with next family
                logging.warning(f"ML ranking failed for family {fam}: {e}")
                fallback_reason = "ml_unavailable_or_disabled"
                continue
            except RuntimeError as e:
                # If ranker fails and REQUIRE_RANKER is set, propagate the error
                if "ranker" in str(e).lower() and REQUIRE_RANKER:
                    raise e
                # Otherwise continue with next family
                fallback_reason = "ranker_failed"
                continue
        
        # If none confirmed, mark auditable negative
        why_reasons = [f"tried:{sum(attempted_by_family.values())}", "no_confirm_after_topk"]
        if fallback_reason:
            why_reasons.append(fallback_reason)
        
        # Determine rank_source for clean rows
        clean_rank_source = "ml" if ml_used else "defaults"
        clean_ml_proba = None
        clean_attempt_idx = None
        
        # If ML was used, get the first attempt's ML telemetry
        if ml_used and tried:
            # Find the first ML-ranked payload that was attempted
            for fam in candidates:
                try:
                    ranked = rank_payloads(fam, features, top_k=1)
                    if ranked and ranked[0].get("rank_source") == "ml":
                        clean_ml_proba = ranked[0].get("p_cal")
                        clean_attempt_idx = 0
                        break
                except:
                    continue
        
        return _ensure_telemetry_defaults({
            "target": target.to_dict(), 
            "decision": DECISION["NEG"], 
            "why": unique_merge([], why_reasons),
            "cvss": None,  # No CVSS for non-positive results
            "rank_source": clean_rank_source,
            "ml_role": None,
            "gated": False,
            "ml_family": None,
            "ml_proba": clean_ml_proba,
            "ml_threshold": None,
            "model_tag": None,
            "attempt_idx": clean_attempt_idx,
            "top_k_used": None,
            "timing_ms": 0,
            "meta": {
                "ml_attempted_payloads": tried[:3],  # trim for payload privacy
                "attempted_by_family": attempted_by_family
            }
        })
        
    except Exception as e:
        logging.error(f"Error processing target {target.url}: {e}")
        import traceback
        logging.error(f"Traceback: {traceback.format_exc()}")
        logging.error(f"Error type: {type(e).__name__}")
        logging.error(f"Error message: {str(e)}")
        return _ensure_telemetry_defaults({
            "target": target.to_dict(), 
            "decision": DECISION["ERR"], 
            "why": ["error"],
            "error_message": str(e),
            "cvss": None,
            "rank_source": "defaults",
            "ml_role": None,
            "gated": False,
            "ml_family": None,
            "ml_proba": None,
            "ml_threshold": None,
            "model_tag": None,
            "attempt_idx": None,
            "top_k_used": None,
            "timing_ms": 0
        })

def run_job(target_url: str, job_id: str, max_depth: int = 2, max_endpoints: int = 30, top_k: int = 3, strategy: str = "auto") -> Dict[str, Any]:
    """
    Single entrypoint for vulnerability assessment job with parallelization.
    Handles: crawl → probe → ML ranker → evidence sink
    """
    from backend.modules.strategy import make_plan
    
    start_time = time.time()
    job_budget_ms = int(os.getenv("ELISE_JOB_BUDGET_MS", "300000"))  # 5 minutes default
    
    # Create strategy plan for enforcement
    plan = make_plan(strategy)
    
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
    rank_source_counts = {"probe_only": 0, "ml": 0, "ctx_pool": 0, "defaults": 0}
    
    # Collect all targets for parallel processing
    all_targets = []
    for ep in endpoints:
        targets = list(enumerate_targets(ep))
        
        # If no targets (no parameters), mark as not_applicable
        if not targets:
            endpoints_without_params += 1
            # Extract path from URL for NA rows
            from urllib.parse import urlparse
            parsed_url = urlparse(ep.get("url", ""))
            path = parsed_url.path or "/"
            
            results.append({
                "evidence_id": None,
                "url": ep.get("url", ""),
                "path": path,
                "method": ep.get("method", "GET"),
                "param_in": "none",
                "param": "none",
                "family": None,
                "decision": DECISION["NA"],
                "why": ["no_parameters_detected"],
                "cvss": None,
                "rank_source": None,  # NA rows have no rank_source
                "ml_role": None,
                "gated": False,
                "ml_family": None,
                "ml_proba": None,
                "ml_threshold": None,
                "model_tag": None,
                "attempt_idx": None,
                "top_k_used": None,
                "timing_ms": 0,
                "status": ep.get("status", 0)
            })
            all_targets.extend(targets)
    
    # Process targets in parallel with time budget
    if all_targets:
        max_workers = min(8, len(all_targets))  # Bounded to 8 workers
        results_lock = Lock()
        findings_lock = Lock()
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_target = {
                executor.submit(_process_target, target, job_id, top_k, results_lock, findings_lock, start_time, plan): target
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
                        "cvss": result.get("cvss"),
                        "rank_source": result.get("rank_source"),
                        "ml_role": result.get("ml_role"),
                        "gated": result.get("gated"),
                        "ml_family": result.get("ml_family"),
                        "ml_proba": result.get("ml_proba"),
                        "ml_threshold": result.get("ml_threshold"),
                        "model_tag": result.get("model_tag"),
                        "attempt_idx": result.get("attempt_idx"),
                        "top_k_used": result.get("top_k_used"),
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
                    
                    logging.error(f"Error processing target {target.url} in run_job: {e}")
                    import traceback
                    logging.error(f"Traceback: {traceback.format_exc()}")
                    
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
                        "cvss": None,
                        "rank_source": "defaults",
                        "ml_role": None,
                        "gated": False,
                        "ml_family": None,
                        "ml_proba": None,
                        "ml_threshold": None,
                        "model_tag": None,
                        "attempt_idx": None,
                        "top_k_used": None,
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
    
    # Get event-based counters from aggregator
    aggregator = get_aggregator()
    event_meta = aggregator.get_meta_data(results)
    
    meta = {
        "endpoints_supplied": endpoints_crawled,
        "targets_enumerated": targets_enumerated,
        "budget_ms_used": int((time.time() - start_time) * 1000),
        "errors_by_kind": errors_by_kind,
        "top_k_used": top_k,
        "rank_source_counts": rank_source_counts,
        # Strategy plan information
        "strategy": plan.name.value,
        "flags": {
            "probes_disabled": sorted(list(plan.probes_disabled)),
            "allow_injections": plan.allow_injections,
            "force_ctx_inject_on_probe": plan.force_ctx_inject_on_probe
        },
        # Event-based counters
        **event_meta
    }
    
    # Handle ml_with_context strategy: if we have a probe-confirmed result,
    # we still want to run ML injections and return the ML result instead
    if plan and plan.name == "ml_with_context" and 'probe_confirmed_evidence' in locals():
        # For ml_with_context, prefer ML results over probe results
        if results:  # If we have ML results, use them
            return {
                "results": results, 
                "findings": findings_aggregates, 
                "job_id": job_id, 
                "meta": meta
            }
        else:  # If no ML results, fall back to probe result
            return _ensure_telemetry_defaults(probe_confirmed_evidence)
    
    return {
        "results": results, 
        "findings": findings_aggregates, 
        "job_id": job_id, 
        "meta": meta
    }
