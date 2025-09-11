from typing import Any, Dict, List, Optional, Tuple
from backend.modules.targets import enumerate_targets, enumerate_targets_from_endpoints, Target
from backend.modules.fuzzer_core import _process_target, get_event_totals, clear_event_aggregator, DECISION
from backend.modules.decisions import canonicalize_results, ensure_all_telemetry_defaults
from backend.modules.strategy import ScanStrategy, get_strategy_behavior, make_plan, probe_enabled, injections_enabled, validate_strategy_requirements
from backend.modules.event_aggregator import get_aggregator
from backend.app_state import REQUIRE_RANKER
from backend.pipeline.reasons import build_why
from backend.metrics.summary import finalize_xss_context_metrics
from backend.pipeline.telemetry import record_ctx_first_hit

def upsert_row(results: List[Dict[str, Any]], key: Tuple[str, str, str, str, str], patch: Dict[str, Any]) -> Dict[str, Any]:
    """
    Update an existing row or insert a new one based on the key.
    
    Args:
        results: List of result rows
        key: (family, method, path, param_in, param) tuple
        patch: Dictionary of fields to update/add
        
    Returns:
        The updated or newly created row
    """
    family, method, path, param_in, param = key
    
    # Look for existing row with matching key
    for r in results:
        if (r.get("family") == family and 
            r.get("method") == method and 
            r.get("path") == path and 
            r.get("param_in") == param_in and 
            r.get("param") == param):
            # Update existing row
            r.update(patch)
            return r
    
    # Not found -> insert a new one
    row = {
        "family": family,
        "method": method,
        "path": path,
        "param_in": param_in,
        "param": param,
        "decision": "abstain",
        "provenance": "Probe" if patch.get("provenance") == "Probe" else "Inject"
    }
    row.update(patch)
    results.append(row)
    return row

def create_assessment_response_from_results(results: List[Dict[str, Any]], job_id: str, strategy: str, ctx_mode: str = "auto") -> Dict[str, Any]:
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
    
    # Calculate confirmed counts from row-derived data
    confirmed_probe = sum(1 for r in results if r.get("decision") == "positive" and r.get("provenance") == "Probe")
    confirmed_ml_inject = sum(1 for r in results if r.get("decision") == "positive" and r.get("provenance") == "Inject")
    
    # Calculate XSS context statistics from persisted results
    xss_reflections_total = 0
    xss_rule_high_conf = 0
    xss_ml_invoked = 0
    xss_final_from_ml = 0
    xss_context_dist = {}
    xss_ctx_pool_used = 0
    xss_first_hit_attempts_ctx = 0
    xss_first_hit_attempts_baseline = 0
    
    for result in results:
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
            rank_source = result.get("rank_source")
            decision = result.get("decision")
            
            if rank_source == "ctx_pool":
                xss_ctx_pool_used += 1
                # Count first-hit attempts for context pool
                attempt_idx = result.get("attempt_idx", 0) or 0
                if decision == "positive" and attempt_idx == 0:  # Evidence files use 0-based indexing
                    xss_first_hit_attempts_ctx += 1
            # Count baseline attempts for all XSS positives (including ctx_pool)
            if result.get("family") == "xss" and decision == "positive":
                # For ctx_pool, use top_k_used or default to 3; for others, use attempt_idx + 1
                if rank_source == "ctx_pool":
                    top_k_used = result.get("top_k_used", 0)
                    if top_k_used == 0:
                        top_k_used = 3  # Default top_k for ctx_pool
                    xss_first_hit_attempts_baseline += top_k_used
                else:
                    attempt_idx = result.get("attempt_idx", 0) or 0
                    xss_first_hit_attempts_baseline += attempt_idx + 1
    
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
        "xss_reflections_total": xss_reflections_total,
        "xss_rule_high_conf": xss_rule_high_conf,
        "xss_ml_invoked": xss_ml_invoked,
        "xss_final_from_ml": xss_final_from_ml,
        "xss_context_dist": xss_context_dist,
        "xss_ctx_pool_used": xss_ctx_pool_used,
        "xss_first_hit_attempts_ctx": xss_first_hit_attempts_ctx,
        "xss_first_hit_attempts_baseline": xss_first_hit_attempts_baseline,
        "xss_first_hit_attempts_delta": xss_first_hit_attempts_baseline - xss_first_hit_attempts_ctx if (xss_first_hit_attempts_ctx or 0) > 0 else 0,
        "xss_ctx_invoke": ctx_mode,
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
    
    # Finalize XSS context metrics
    meta = finalize_xss_context_metrics(meta, results, ui_top_k_default=3)
    
    return {"summary": summary, "results": results, "findings": findings, "job_id": job_id, "meta": meta}

def assess_endpoints(endpoints: List[Dict[str,Any]], job_id: str, top_k:int=3, strategy: str = "auto", ctx_mode: str = "auto")->Dict[str,Any]:
    """
    Assess endpoints using deterministic target enumeration.
    This is a simplified version without parallelization for direct endpoint assessment.
    """
    import time
    from threading import Lock
    from backend.modules.evidence_reader import read_evidence_files
    from backend.modules.event_aggregator import set_current_job, reset_aggregator
    
    # Set up job context for aggregator
    set_current_job(job_id)
    reset_aggregator()  # Clear any previous state
    
    # Check if evidence files already exist (for from_persisted mode)
    # Only use existing results if they match the current strategy AND ctx_mode
    existing_results = read_evidence_files(job_id)
    if existing_results:
        # Filter existing results to only include those with the matching strategy AND ctx_mode
        matching_results = []
        for r in existing_results:
            if r.get("strategy") == strategy:
                # Check ctx_mode from telemetry
                telemetry = r.get("telemetry", {})
                existing_ctx_mode = telemetry.get("ctx_invoke", "auto")
                if existing_ctx_mode == ctx_mode:
                    matching_results.append(r)
        
        if matching_results:
            print(f"Found {len(matching_results)} existing evidence files for job {job_id} with matching strategy {strategy} and ctx_mode {ctx_mode}")
            # Return matching results instead of re-running assessment
            return create_assessment_response_from_results(matching_results, job_id, strategy, ctx_mode)
        else:
            # Show what strategies and ctx_modes are available
            available_strategies = set(r.get("strategy") for r in existing_results)
            available_ctx_modes = set()
            for r in existing_results:
                telemetry = r.get("telemetry", {})
                ctx_mode_from_telemetry = telemetry.get("ctx_invoke", "auto")
                available_ctx_modes.add(ctx_mode_from_telemetry)
            print(f"Found existing evidence files for job {job_id} with strategies {available_strategies} and ctx_modes {available_ctx_modes}, but current strategy is {strategy} and ctx_mode is {ctx_mode}. Re-running assessment.")
    
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
    
    # Start timing using monotonic nanoseconds
    start_time = time.monotonic_ns()
    
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
    raw_results = []
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
        result = _process_target(target, job_id, top_k, Lock(), Lock(), plan=plan, ctx_mode=ctx_mode, meta={})
        raw_results.append(result)
        
        # Extract evidence if present
        if "evidence" in result:
            findings.append(result["evidence"])
    
    # Apply upsert logic to create one-row-per-(target,family)
    # Do not create rows for NA/no-params. Keep them out of results; the NA badge is computed separately.
    results = []
    na_count = 0
    for result in raw_results:
        if result.get("decision") in ["positive", "suspected", "error"]:
            # Create key for upsert
            target = result.get("target", {})
            family = result.get("family", "unknown")
            method = target.get("method", "GET")
            path = target.get("url", "")
            param_in = target.get("param_in", "none")
            param = target.get("param", "none")
            
            key = (family, method, path, param_in, param)
            
            # Determine provenance
            provenance = "Probe" if result.get("rank_source") == "probe_only" else "Inject"
            
            # Create patch for upsert
            patch = {
                "decision": result.get("decision"),
                "provenance": provenance,
                "why": build_why(result),
                "cvss": result.get("cvss"),
                "evidence_id": result.get("evidence_id"),
                "rank_source": result.get("rank_source"),
                "ml_role": result.get("ml_role"),
                "gated": result.get("gated", False),
                "ml_family": result.get("ml_family"),
                "ml_proba": result.get("ml_proba"),
                "ml_threshold": result.get("ml_threshold"),
                "model_tag": result.get("model_tag"),
                "attempt_idx": result.get("attempt_idx"),
                "top_k_used": result.get("top_k_used"),
                "timing_ms": result.get("timing_ms", 0)
            }
            
            # Add XSS context fields if present
            if result.get("xss_context") is not None:
                patch.update({
                    "xss_context": result.get("xss_context"),
                    "xss_escaping": result.get("xss_escaping"),
                    "xss_context_source": result.get("xss_context_source"),
                    "xss_context_ml_proba": result.get("xss_context_ml_proba")
                })
            
            # Upsert the row
            row = upsert_row(results, key, patch)
            
            # Record ctx first-hit counter using centralized telemetry
            # Create a mock job object for the telemetry function
            class MockJob:
                def __init__(self):
                    self.meta = {}
            
            mock_job = MockJob()
            record_ctx_first_hit(mock_job, row)
        elif result.get("decision") == "not_applicable":
            # Count NA results but don't add them to results array
            na_count += 1
    
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
    
    # End timing
    end_time = time.monotonic_ns()
    elapsed_s = (end_time - start_time) / 1e9
    processing_ms = int(1000 * elapsed_s)
    
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
                # Count first-hit attempts for context pool
                attempt_idx = result.get("attempt_idx", 0) or 0
                if decision == DECISION["POS"] and attempt_idx == 1:
                    xss_first_hit_attempts_ctx += 1
            elif rank_source in ["ml", "defaults"] and decision == DECISION["POS"]:
                # Count attempts before first positive for baseline
                attempt_idx = result.get("attempt_idx", 0) or 0
                xss_first_hit_attempts_baseline += attempt_idx + 1
    
    # Compute confirmed probe and ML inject counts from row-derived data
    confirmed_probe = sum(1 for r in results if r.get("decision") == DECISION["POS"] and r.get("provenance") == "Probe")
    confirmed_ml_inject = sum(1 for r in results if r.get("decision") == DECISION["POS"] and r.get("provenance") == "Inject")
    
    # Strategy violation checks
    if plan.name == "ml_only":
        # ML-only: no probe positives allowed
        probe_positives = sum(1 for r in results if r.get("provenance") == "Probe" and r.get("decision") == DECISION["POS"])
        if probe_positives > 0:
            violations.append("strategy_violation:probe_positive_under_ml_only")
    
    elif plan.name == "ml_with_context":
        # ML-with-Context: XSS canary allowed, no probe positives; disable Redirect family
        probe_positives = sum(1 for r in results if r.get("provenance") == "Probe" and r.get("decision") == DECISION["POS"])
        if probe_positives > 0:
            violations.append("strategy_violation:probe_positive_under_ml_with_context")
        
        # Check for redirect family (should be disabled)
        redirect_results = [r for r in results if r.get("family") == "redirect"]
        if redirect_results:
            violations.append("strategy_violation:redirect_family_under_ml_with_context")
    
    # Use SSOT aggregator for summary (as required by patch)
    from backend.modules.event_aggregator import get_aggregator
    aggregator = get_aggregator()
    ssot_summary = aggregator.build_summary(results)
    
    # Adapt SSOT summary to expected API format
    summary = {
        "total": len(results) + na_count + endpoints_without_params,
        "positive": ssot_summary["totals"]["positives_total"],
        "suspected": ssot_summary["totals"]["suspected_total"],
        "abstain": ssot_summary["totals"]["clean_total"],
        "na": na_count + endpoints_without_params,
        "confirmed_probe": ssot_summary["provenance"]["confirmed_probe"],
        "confirmed_ml_inject": ssot_summary["provenance"]["confirmed_inject"],
    }
    
    meta = {
        "endpoints_supplied": endpoints_supplied,
        "targets_enumerated": targets_enumerated,
        "endpoints_without_params": endpoints_without_params,
        "processing_ms": processing_ms,
        "processing_time": f"{elapsed_s:.1f}s",
        "probe_attempts": probe_attempts,
        "probe_successes": probe_successes,
        "ml_inject_attempts": ml_inject_attempts,
        "ml_inject_successes": ml_inject_successes,
        # Strategy plan information
        "strategy": plan.name.value,
        "probes_disabled": sorted(list(plan.probes_disabled)),
        "canary_attempts": probe_attempts if plan.name.value == "ml_with_context" else 0,
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
        "xss_ctx_invoke": ctx_mode,
        # Counters consistency check - will be updated by SSOT aggregator
        "counters_consistent": True,  # Placeholder, will be overridden by aggregator
        # Backward compatibility
        "injections_attempted": probe_attempts + ml_inject_attempts,
        "injections_succeeded": probe_successes + ml_inject_successes,
        "budget_ms_used": processing_ms,  # Use actual processing time
        "errors_by_kind": {}
    }
    
    # Apply decision canonicalization and telemetry defaults
    results = canonicalize_results(results)
    results = ensure_all_telemetry_defaults(results)
    
    # Get event-based counters from aggregator (SSOT)
    aggregator = get_aggregator()
    event_meta = aggregator.get_meta_data(results)
    
    # Preserve manually incremented first-hit counter before merging event counters
    manually_incremented_ctx_counter = meta.get("xss_first_hit_attempts_ctx", 0)
    
    # Merge event counters into meta
    meta.update(event_meta)
    
    # Update counters_consistent from SSOT aggregator (reuse same summary)
    meta["counters_consistent"] = not ssot_summary["flags"].get("counts_inconsistent", False)
    
    # Restore manually incremented counter if it was overwritten
    if manually_incremented_ctx_counter > 0:
        meta["xss_first_hit_attempts_ctx"] = manually_incremented_ctx_counter
    
    # Finalize XSS context metrics
    meta = finalize_xss_context_metrics(meta, results, ui_top_k_default=3)
    
    return {"summary": summary, "results": results, "findings": findings, "job_id": job_id, "meta": meta}