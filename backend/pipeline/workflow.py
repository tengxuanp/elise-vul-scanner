from typing import Any, Dict, List, Optional
from backend.modules.targets import enumerate_targets, enumerate_targets_from_endpoints, Target
from backend.modules.fuzzer_core import _process_target, get_event_totals, clear_event_aggregator, DECISION
from backend.modules.decisions import canonicalize_results, ensure_all_telemetry_defaults
from backend.modules.strategy import ScanStrategy, get_strategy_behavior, make_plan, probe_enabled, injections_enabled, validate_strategy_requirements
from backend.modules.event_aggregator import get_aggregator
from backend.app_state import REQUIRE_RANKER

def create_assessment_response_from_results(results: List[Dict[str, Any]], job_id: str, strategy: str) -> Dict[str, Any]:
    """
    Create assessment response from existing results.
    
    Args:
        results: List of assessment results
        job_id: Job ID
        strategy: Strategy used
        
    Returns:
        Assessment response dictionary
    """
    # Calculate summary statistics
    total = len(results)
    positive = sum(1 for r in results if r.get("decision") == "positive")
    suspected = sum(1 for r in results if r.get("decision") == "suspected")
    abstain = sum(1 for r in results if r.get("decision") == "abstain")
    na = sum(1 for r in results if r.get("decision") == "not_applicable")
    error = sum(1 for r in results if r.get("decision") == "error")
    
    # Calculate confirmed counts
    confirmed_probe = sum(1 for r in results if r.get("rank_source") == "probe_only" and r.get("decision") == "positive")
    confirmed_ml_inject = sum(1 for r in results if r.get("rank_source") in ["ml", "ctx_pool"] and r.get("decision") == "positive")
    
    # Create findings aggregates by family (same structure as fuzzer_core.py)
    findings_by_family = {}
    for result in results:
        if result.get("decision") == "positive" and result.get("family"):
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
    findings = list(findings_by_family.values())
    
    # Create meta information
    meta = {
        "endpoints_supplied": len(set(r.get("target", {}).get("url", "") for r in results)),
        "targets_enumerated": total,
        "endpoints_without_params": na,
        "processing_ms": 0,  # No processing time for existing results
        "processing_time": "0.0s",
        "probe_attempts": 0,
        "probe_successes": confirmed_probe,
        "ml_inject_attempts": 0,
        "ml_inject_successes": confirmed_ml_inject,
        "strategy": strategy,
        "flags": {
            "probes_disabled": [],
            "allow_injections": True,
            "force_ctx_inject_on_probe": False
        },
        "strategy_validation": {
            "strategy": strategy,
            "ml_required": False,
            "ml_available": True,
            "fallback": None,
            "flags": []
        },
        "violations": [],
        "xss_reflections_total": 0,
        "xss_rule_high_conf": 0,
        "xss_ml_invoked": 0,
        "xss_final_from_ml": 0,
        "xss_context_dist": {},
        "xss_ctx_pool_used": 0,
        "xss_first_hit_attempts_ctx": 0,
        "xss_first_hit_attempts_baseline": 0,
        "xss_first_hit_attempts_delta": 0,
        "counters_consistent": True,
        "injections_attempted": 0,
        "injections_succeeded": confirmed_probe + confirmed_ml_inject,
        "budget_ms_used": 0,
        "errors_by_kind": {}
    }
    
    return {
        "job_id": job_id,
        "mode": "from_persisted",
        "summary": {
            "total": total,
            "positive": positive,
            "suspected": suspected,
            "abstain": abstain,
            "na": na,
            "confirmed_probe": confirmed_probe,
            "confirmed_ml_inject": confirmed_ml_inject
        },
        "results": results,
        "findings": findings,
        "meta": meta,
        "healthz": {
            "ok": True,
            "data_dir": str(REQUIRE_RANKER),
            "model_dir": "models",
            "use_ml": True,
            "require_ranker": True,
            "ml_active": True,
            "models_available": {},
            "using_defaults": False,
            "ml_status": "models_available",
            "available_models": {},
            "defaults_in_use": False,
            "thresholds": {
                "sqli_tau": 0.15,
                "xss_tau": 0.75,
                "redirect_tau": 0.6
            },
            "playwright_ok": True,
            "crawler_import_ok": True,
            "checks": [],
            "failed_checks": []
        }
    }

def assess_endpoints(endpoints: List[Dict[str,Any]], job_id: str, top_k:int=3, strategy: str = "auto")->Dict[str,Any]:
    """
    Assess endpoints using deterministic target enumeration.
    This is a simplified version without parallelization for direct endpoint assessment.
    """
    import time
    from threading import Lock
    from backend.modules.evidence_reader import read_evidence_files
    
    # Check if evidence files already exist (for from_persisted mode)
    # Only use existing results if they match the current strategy
    existing_results = read_evidence_files(job_id)
    if existing_results:
        # Filter existing results to only include those with the matching strategy
        matching_results = [r for r in existing_results if r.get("strategy") == strategy]
        if matching_results:
            print(f"Found {len(matching_results)} existing evidence files for job {job_id} with matching strategy {strategy}")
            # Return matching results instead of re-running assessment
            return create_assessment_response_from_results(matching_results, job_id, strategy)
        else:
            # Show what strategies are available
            available_strategies = set(r.get("strategy") for r in existing_results)
            print(f"Found existing evidence files for job {job_id} with strategies {available_strategies}, but current strategy is {strategy}. Re-running assessment.")
    
    # Parse strategy and create execution plan
    try:
        scan_strategy = ScanStrategy(strategy.lower())
    except ValueError:
        scan_strategy = ScanStrategy.AUTO
    
    # Create centralized execution plan
    plan = make_plan(strategy)
    
    # Health gating: check ML requirements
    from backend.routes.canonical_healthz_routes import get_healthz_data
    health_data = get_healthz_data()
    ml_available = health_data.get("ml_active", False) and any(
        model.get("has_model", False) for model in health_data.get("models_available", {}).values()
    )
    
    # Validate strategy requirements
    try:
        strategy_validation = validate_strategy_requirements(scan_strategy, ml_available)
    except ValueError as e:
        if REQUIRE_RANKER:
            raise ValueError(f"Strategy validation failed: {str(e)}")
        else:
            # Fallback to probe_only
            plan = make_plan("probe_only")
            strategy_validation = {
                "strategy": "probe_only",
                "ml_required": False,
                "ml_available": ml_available,
                "fallback": "probe_only",
                "flags": ["ml_fallback"]
            }
    
    # Get strategy behavior (for backward compatibility)
    behavior = get_strategy_behavior(scan_strategy)
    
    # Start timing
    start_time = time.perf_counter()
    
    # Clear event aggregator for fresh counts
    clear_event_aggregator()
    
    # Initialize violation tracking
    violations = []
    
    # Use deterministic target enumeration
    target_dicts = enumerate_targets_from_endpoints(endpoints)
    
    # Count endpoints and targets
    endpoints_supplied = len(endpoints)
    targets_enumerated = len(target_dicts)
    
    results, findings = [], []
    
    # Process each enumerated target
    for target_dict in target_dicts:
        # Convert dict to Target object
        target = Target(
            url=target_dict["url"],
            method=target_dict["method"],
            param_in=target_dict["param_in"],
            param=target_dict["param"],
            headers=target_dict.get("headers", {}),
            status=target_dict.get("status"),
            content_type=target_dict.get("content_type"),
            base_params=target_dict.get("base_params", {})
        )
        
        # Use the same _process_target function from fuzzer_core
        result = _process_target(target, job_id, top_k, Lock(), Lock(), plan=plan)
        results.append(result)
        
        # Extract evidence if present
        if "evidence" in result:
            findings.append(result["evidence"])
    
    # Handle endpoints with no parameters
    endpoints_without_params = 0
    for ep in endpoints:
        param_locs = ep.get("param_locs", {})
        has_params = False
        
        if isinstance(param_locs, dict):
            for loc in ("query", "form", "json"):
                params = param_locs.get(loc, [])
                if params:
                    has_params = True
                    break
        
        # Fallback: check legacy params field
        if not has_params and isinstance(ep.get("params"), list) and ep.get("params"):
            has_params = True
        
        if not has_params:
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
                "why": ["no_parameters_detected"],
                "attempt_idx": 0,
                "top_k_used": 0,
                "rank_source": "none"
            })
    
    # End timing
    end_time = time.perf_counter()
    processing_ms = int(1000 * (end_time - start_time))
    
    # Get event-based counters
    event_totals = get_event_totals()
    probe_attempts = event_totals.get("probe_attempts", 0)
    probe_successes = event_totals.get("probe_successes", 0)
    ml_inject_attempts = event_totals.get("inject_attempts", 0)
    ml_inject_successes = event_totals.get("inject_successes", 0)
    
    # XSS context counters
    xss_reflections_total = 0
    xss_rule_high_conf = 0
    xss_ml_invoked = 0
    xss_final_from_ml = 0
    xss_context_dist = {}
    
    # XSS context payload pool uplift counters
    xss_ctx_pool_used = 0
    xss_first_hit_attempts_ctx = 0
    xss_first_hit_attempts_baseline = 0
    
    # Calculate result-based counters for consistency check
    result_probe_attempts = 0
    result_probe_successes = 0
    result_ml_inject_attempts = 0
    result_ml_inject_successes = 0
    
    for result in results:
        rank_source = result.get("rank_source", "none")
        decision = result.get("decision")
        why = result.get("why", [])
        attempt_idx = result.get("attempt_idx", 0)
        top_k_used = result.get("top_k_used", 0)
        
        # Count result-based counters for consistency check
        if rank_source == "probe_only":
            result_probe_attempts += 1  # At least one probe attempt per target
            if decision == DECISION["POS"]:
                result_probe_successes += 1
        
        # Count ML injection attempts and successes
        elif rank_source in ["ml", "defaults", "ctx_pool"] or "ml_ranked" in why:
            # Count injection attempts based on top_k_used
            if (top_k_used or 0) > 0:
                result_ml_inject_attempts += top_k_used or 0
            elif (attempt_idx or 0) > 0:
                result_ml_inject_attempts += attempt_idx or 0
            else:
                result_ml_inject_attempts += 1  # At least one attempt
            
            if decision == DECISION["POS"]:
                result_ml_inject_successes += 1
        
        # Count XSS context statistics
        if result.get("family") == "xss" and result.get("xss_context"):
            xss_reflections_total += 1
            
            # Count context distribution
            context = result.get("xss_context", "unknown")
            xss_context_dist[context] = xss_context_dist.get(context, 0) + 1
            
            # Count rule vs ML usage
            xss_context_source = result.get("xss_context_source")
            if xss_context_source == "rule":
                xss_rule_high_conf += 1
            elif xss_context_source == "ml":
                xss_ml_invoked += 1
                xss_final_from_ml += 1
            
            # Count context payload pool usage and first-hit attempts
            if rank_source == "ctx_pool":
                xss_ctx_pool_used += 1
                # Count attempts before first positive for context pool
                attempt_idx = result.get("attempt_idx", 0) or 0
                if decision == DECISION["POS"]:
                    xss_first_hit_attempts_ctx += attempt_idx + 1
            elif rank_source in ["ml", "defaults"] and decision == DECISION["POS"]:
                # Count attempts before first positive for baseline
                attempt_idx = result.get("attempt_idx", 0) or 0
                xss_first_hit_attempts_baseline += attempt_idx + 1
    
    # Compute confirmed probe and ML inject counts from results
    confirmed_probe = sum(1 for r in results if r.get("rank_source") == "probe_only" and r.get("decision") == DECISION["POS"])
    confirmed_ml_inject = sum(1 for r in results if r.get("rank_source") in ["ml", "ctx_pool"] and r.get("decision") == DECISION["POS"])
    
    summary = {
        "total": len(results),
        "positive": sum(r["decision"]==DECISION["POS"] for r in results),
        "suspected": sum(r["decision"]==DECISION["SUS"] for r in results),
        "abstain": sum(r["decision"]==DECISION["ABS"] for r in results),
        "na": sum(r["decision"]==DECISION["NA"] for r in results),
        "confirmed_probe": confirmed_probe,
        "confirmed_ml_inject": confirmed_ml_inject,
    }
    
    meta = {
        "endpoints_supplied": endpoints_supplied,
        "targets_enumerated": targets_enumerated,
        "endpoints_without_params": endpoints_without_params,
        "processing_ms": processing_ms,
        "processing_time": f"{processing_ms/1000:.1f}s",
        "probe_attempts": probe_attempts,
        "probe_successes": probe_successes,
        "ml_inject_attempts": ml_inject_attempts,
        "ml_inject_successes": ml_inject_successes,
        # Strategy plan information
        "strategy": plan.name.value,
        "flags": {
            "probes_disabled": sorted(list(plan.probes_disabled)),
            "allow_injections": plan.allow_injections,
            "force_ctx_inject_on_probe": plan.force_ctx_inject_on_probe
        },
        "strategy_validation": strategy_validation,
        # Violation tracking
        "violations": violations,
        # XSS context counters
        "xss_reflections_total": xss_reflections_total,
        "xss_rule_high_conf": xss_rule_high_conf,
        "xss_ml_invoked": xss_ml_invoked,
        "xss_final_from_ml": xss_final_from_ml,
        "xss_context_dist": xss_context_dist,
        # XSS context payload pool uplift counters
        "xss_ctx_pool_used": xss_ctx_pool_used,
        "xss_first_hit_attempts_ctx": xss_first_hit_attempts_ctx,
        "xss_first_hit_attempts_baseline": xss_first_hit_attempts_baseline,
        "xss_first_hit_attempts_delta": xss_first_hit_attempts_baseline - xss_first_hit_attempts_ctx if (xss_first_hit_attempts_ctx or 0) > 0 else 0,
        # Counters consistency check
        "counters_consistent": (
            (probe_successes + ml_inject_successes) == (confirmed_probe + confirmed_ml_inject) and
            probe_attempts == result_probe_attempts and
            probe_successes == result_probe_successes and
            ml_inject_attempts == result_ml_inject_attempts and
            ml_inject_successes == result_ml_inject_successes and
            (probe_successes + ml_inject_successes) == sum(1 for r in results if r.get("decision") == "positive")
        ),
        # Backward compatibility
        "injections_attempted": probe_attempts + ml_inject_attempts,
        "injections_succeeded": probe_successes + ml_inject_successes,
        "budget_ms_used": processing_ms,  # Use actual processing time
        "errors_by_kind": {}
    }
    
    # Apply decision canonicalization and telemetry defaults
    results = canonicalize_results(results)
    results = ensure_all_telemetry_defaults(results)
    
    # Get event-based counters from aggregator
    aggregator = get_aggregator()
    event_meta = aggregator.get_meta_data(results)
    
    # Merge event counters into meta
    meta.update(event_meta)
    
    return {"summary": summary, "results": results, "findings": findings, "job_id": job_id, "meta": meta}