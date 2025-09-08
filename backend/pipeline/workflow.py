from typing import Any, Dict, List, Optional
from backend.modules.targets import enumerate_targets, enumerate_targets_from_endpoints, Target
from backend.modules.fuzzer_core import _process_target, DECISION

def assess_endpoints(endpoints: List[Dict[str,Any]], job_id: str, top_k:int=3)->Dict[str,Any]:
    """
    Assess endpoints using deterministic target enumeration.
    This is a simplified version without parallelization for direct endpoint assessment.
    """
    import time
    from threading import Lock
    
    # Start timing
    start_time = time.perf_counter()
    
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
        result = _process_target(target, job_id, top_k, Lock(), Lock())
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
    
    # Calculate split counters
    probe_attempts = 0
    probe_successes = 0
    ml_inject_attempts = 0
    ml_inject_successes = 0
    
    for result in results:
        rank_source = result.get("rank_source", "none")
        decision = result.get("decision")
        why = result.get("why", [])
        attempt_idx = result.get("attempt_idx", 0)
        top_k_used = result.get("top_k_used", 0)
        
        # Count probe attempts and successes
        if rank_source == "probe_only":
            probe_attempts += 1  # At least one probe attempt per target
            if decision == DECISION["POS"]:
                probe_successes += 1
        
        # Count ML injection attempts and successes
        elif rank_source in ["ml", "defaults"] or "ml_ranked" in why:
            # Count injection attempts based on top_k_used
            if top_k_used > 0:
                ml_inject_attempts += top_k_used
            elif attempt_idx > 0:
                ml_inject_attempts += attempt_idx
            else:
                ml_inject_attempts += 1  # At least one attempt
            
            if decision == DECISION["POS"]:
                ml_inject_successes += 1
    
    summary = {
        "total": len(results),
        "positive": sum(r["decision"]==DECISION["POS"] for r in results),
        "suspected": sum(r["decision"]==DECISION["SUS"] for r in results),
        "abstain": sum(r["decision"]==DECISION["ABS"] for r in results),
        "na": sum(r["decision"]==DECISION["NA"] for r in results),
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
        # Backward compatibility
        "injections_attempted": probe_attempts + ml_inject_attempts,
        "injections_succeeded": probe_successes + ml_inject_successes,
        "budget_ms_used": processing_ms,  # Use actual processing time
        "errors_by_kind": {}
    }
    
    return {"summary": summary, "results": results, "findings": findings, "job_id": job_id, "meta": meta}