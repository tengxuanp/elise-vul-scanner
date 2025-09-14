"""
Evidence reader module for converting evidence files to assessment results.
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Any
from backend.app_state import DATA_DIR

def read_evidence_files(job_id: str) -> List[Dict[str, Any]]:
    """
    Read all evidence files for a job and convert them to assessment results.
    
    Args:
        job_id: The job ID to read evidence files for
        
    Returns:
        List of assessment results converted from evidence files
    """
    job_dir = DATA_DIR / "jobs" / job_id
    
    if not job_dir.exists():
        return []
    
    results = []
    evidence_files = list(job_dir.glob("*.json"))
    
    for evidence_file in evidence_files:
        if evidence_file.name == "endpoints.json":
            continue
            
        try:
            with open(evidence_file, 'r') as f:
                evidence_data = json.load(f)
            
            # Add evidence_id from filename
            evidence_id = evidence_file.stem  # Remove .json extension
            evidence_data["evidence_id"] = evidence_id
            
            # Convert evidence to assessment result format
            result = convert_evidence_to_result(evidence_data)
            if result:
                results.append(result)
                
        except Exception as e:
            print(f"Error reading evidence file {evidence_file.name}: {e}")
            continue
    
    return results

def convert_evidence_to_result(evidence_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert evidence data to assessment result format.
    
    Args:
        evidence_data: Raw evidence data from file
        
    Returns:
        Assessment result in the expected format
    """
    # Extract basic information
    url = evidence_data.get("url", "")
    method = evidence_data.get("method", "GET")
    param_in = evidence_data.get("param_in", "query")
    param = evidence_data.get("param", "")
    family = evidence_data.get("family", "")
    
    # Determine decision based on CVSS score
    cvss = evidence_data.get("cvss", {})
    cvss_base = cvss.get("base", 0) if isinstance(cvss, dict) else 0
    
    if cvss_base > 0:
        decision = "positive"
    else:
        decision = "abstain"
    
    # Extract why reasons
    why = evidence_data.get("why", [])
    
    # Extract other fields
    rank_source = evidence_data.get("rank_source", "probe_only")
    ml_family = evidence_data.get("ml_family")
    ml_proba = evidence_data.get("ml_proba")
    ml_threshold = evidence_data.get("ml_threshold")
    model_tag = evidence_data.get("model_tag")
    attempt_idx = evidence_data.get("attempt_idx", 0)
    top_k_used = evidence_data.get("top_k_used", 0)
    
    # Create target dict
    target = {
        "url": url,
        "method": method,
        "param_in": param_in,
        "param": param,
        "headers": evidence_data.get("request_headers", {}),
        "status": evidence_data.get("response_status", 200),
        "content_type": evidence_data.get("content_type", "text/html"),
        "base_params": {}
    }
    
    # Determine provenance based on rank_source
    provenance = "Probe" if rank_source == "probe_only" else "Inject"
    
    # Create result dict
    result = {
        "target": target,
        "family": family,  # Add family field for findings aggregation
        "decision": decision,
        "why": why,
        "cvss": cvss if cvss_base > 0 else None,
        "rank_source": rank_source,
        "provenance": provenance,  # Add provenance field
        "ml_role": "prioritization" if rank_source == "ml" else None,
        "gated": False,
        "ml_family": ml_family,
        "ml_proba": ml_proba,
        "ml_threshold": ml_threshold,
        "model_tag": model_tag,
        "attempt_idx": attempt_idx,
        "top_k_used": top_k_used,
        "timing_ms": 0,
        "evidence_id": evidence_data.get("evidence_id"),
        "strategy": evidence_data.get("strategy"),  # Include strategy from evidence file
        "meta": {
            "ml_attempted_payloads": [],
            "attempted_by_family": {family: 1} if family else {}
        }
    }
    
    # Add family-specific fields
    if family == "xss":
        result.update({
            "xss_context": evidence_data.get("xss_context"),
            "xss_escaping": evidence_data.get("xss_escaping"),
            "xss_context_source": evidence_data.get("xss_context_source"),
            "xss_context_ml_proba": evidence_data.get("xss_context_ml_proba")
        })
    elif family == "sqli":
        result.update({
            "sqli_dialect": evidence_data.get("sqli_dialect"),
            "sqli_dialect_source": evidence_data.get("sqli_dialect_source"),
            "sqli_dialect_ml_proba": evidence_data.get("sqli_dialect_ml_proba")
        })
    
    return result
