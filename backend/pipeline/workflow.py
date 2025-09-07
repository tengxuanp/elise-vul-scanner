from typing import Any, Dict, List, Optional
from backend.modules.targets import enumerate_targets, Target
from backend.modules.fuzzer_core import _process_target, DECISION

def assess_endpoints(endpoints: List[Dict[str,Any]], job_id: str, top_k:int=3)->Dict[str,Any]:
    """
    Assess endpoints using the same primitives as fuzzer_core.run_job.
    This is a simplified version without parallelization for direct endpoint assessment.
    """
    from threading import Lock
    
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
        
        # Process targets for this endpoint using the same primitives as fuzzer_core
        for target in targets:
            # Use the same _process_target function from fuzzer_core
            result = _process_target(target, job_id, top_k, Lock(), Lock())
            results.append(result)
            
            # Extract evidence if present
            if "evidence" in result:
                findings.append(result["evidence"])
    
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