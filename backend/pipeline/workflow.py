#!/usr/bin/env python3
"""
Orchestration pipeline for vulnerability assessment workflow
"""

from dataclasses import dataclass
from typing import List, Dict, Any, Optional
import logging

from modules.targets import Target, enumerate_targets
from modules.probes.engine import run_probes
from modules.gates import (
    gate_not_applicable, 
    gate_candidate_xss, 
    gate_candidate_redirect, 
    gate_candidate_sqli
)
from modules.ml.enhanced_features import build_features_for_target
from app_state import ml_state, P_MIN, ENTROPY_MAX
from modules.payload_recommender import recommend_for_target
from modules.cvss import build_cvss_vector
from modules.evidence_schema import EvidenceRow, write_evidence_row

# Decision constants
DECISION_NA = "not_applicable"
DECISION_CONFIRMED = "positive"
DECISION_ABSTAIN = "abstain"
DECISION_TESTED_NEG = "tested_negative"
DECISION_SUSPECTED = "suspected"

def _family_confirmed(probe) -> Optional[str]:
    """Determine if a vulnerability family is confirmed by probe results"""
    # Deterministic proofs
    if probe.redirect_influence: 
        return "redirect"
    if probe.xss_context in {"html", "attr", "js_string"}: 
        return "xss"
    if probe.sqli_error_based or probe.sqli_boolean_delta > 0.08 or probe.sqli_time_based: 
        return "sqli"
    return None

def assess_target(target: Target, job_id: str = None) -> Dict[str, Any]:
    """
    Assess a single target through the complete vulnerability assessment pipeline.
    
    Returns a dictionary with decision, reasoning, and recommendations.
    """
    logging.info(f"🎯 Assessing target: {target.url} {target.method} {target.param_in}:{target.param}")
    
    # Stage 1: hard NA gates
    if gate_not_applicable(target):
        logging.info(f"❌ Target {target.param} - not applicable (gate)")
        return {
            "decision": DECISION_NA, 
            "why": ["gate:not_applicable"], 
            "recommendations": []
        }

    # Stage 2: run probes
    probe = run_probes(target)
    fam = _family_confirmed(probe)
    
    if fam:
        # Confirmed vulnerability → craft minimal confirming payloads and write evidence
        logging.info(f"✅ Target {target.param} - CONFIRMED {fam}")
        
        cvss_data = build_cvss_vector(fam, {"xss_context": getattr(probe, "xss_context", None)})
        
        # Write evidence row
        evidence_row = EvidenceRow.from_confirmed(target, fam, probe, cvss_data, job_id)
        write_evidence_row(evidence_row)
        
        # Get recommendations for confirmed vulnerability
        recs = recommend_for_target(fam, target)
        
        return {
            "decision": DECISION_CONFIRMED, 
            "family": fam, 
            "proof": probe.__dict__, 
            "cvss": cvss_data, 
            "recommendations": recs
        }

    # Stage 3: if all family candidates fail, NA (don't ask ML to override rules)
    cand = any([
        gate_candidate_xss(target),
        gate_candidate_redirect(target),
        gate_candidate_sqli(target)
    ])
    
    if not cand:
        logging.info(f"❌ Target {target.param} - no family candidates")
        return {
            "decision": DECISION_NA, 
            "why": ["no_family_candidates"], 
            "recommendations": []
        }

    # Stage 4: ML triage (orchestration only)
    if not ml_state.ready or not ml_state.engine:
        logging.info(f"⚠️ Target {target.param} - ML unavailable")
        return {
            "decision": DECISION_ABSTAIN, 
            "why": ["ml_unavailable"], 
            "recommendations": []
        }

    # Build features and get ML prediction
    feats = build_features_for_target(target, probe)
    pred = ml_state.engine.predict_distribution(feats)  # returns {"probs":{...},"family":..., "entropy":...}
    
    probs = pred["probs"]
    top_family = pred["family"]
    H = float(pred.get("entropy", 0.0))
    max_prob = max(probs.values()) if probs else 0.0
    
    # Apply abstention thresholds
    if max_prob < P_MIN or H > ENTROPY_MAX:
        logging.info(f"⚠️ Target {target.param} - abstain (max_prob={max_prob:.2f}, H={H:.2f})")
        return {
            "decision": DECISION_ABSTAIN, 
            "why": [f"abstain:max_prob={max_prob:.2f},H={H:.2f}"], 
            "recommendations": []
        }

    # Plan next minimal action: one small, family-consistent attempt
    recs = recommend_for_target(top_family, target) or []
    
    logging.info(f"🔍 Target {target.param} - SUSPECTED {top_family} (prob={max_prob:.2f})")
    return {
        "decision": DECISION_SUSPECTED, 
        "family": top_family, 
        "ml": pred, 
        "probe": probe.__dict__, 
        "recommendations": recs
    }

def assess_endpoints(endpoints: List[Dict[str, Any]], job_id: str = None, top_k: int = 5) -> Dict[str, Any]:
    """
    Assess multiple endpoints by expanding them into targets and running the pipeline.
    
    Args:
        endpoints: List of endpoint dictionaries from crawler
        job_id: Job ID for evidence tracking
        top_k: Number of top results to return
        
    Returns:
        Dictionary with assessment results
    """
    logging.info(f"🧠 Pipeline: Analyzing {len(endpoints)} endpoints")
    
    # Generate job_id if not provided
    if job_id is None:
        import uuid
        job_id = str(uuid.uuid4())
    
    # Expand endpoints into targets
    all_targets = []
    for endpoint in endpoints:
        targets = enumerate_targets(endpoint)
        all_targets.extend(targets)
    
    logging.info(f"🎯 Pipeline: Expanded to {len(all_targets)} targets")
    
    # Assess each target
    results = []
    for target in all_targets:
        result = assess_target(target, job_id)
        result["target"] = {
            "url": target.url,
            "path": target.path,
            "method": target.method,
            "param": target.param,
            "param_in": target.param_in,
            "status": target.status,
            "content_type": target.content_type,
            "provenance_ids": target.provenance_ids
        }
        results.append(result)
    
    # Calculate summary statistics
    summary = {
        "targets_total": len(all_targets),
        "positive": sum(1 for r in results if r["decision"] == DECISION_CONFIRMED),
        "abstain": sum(1 for r in results if r["decision"] == DECISION_ABSTAIN),
        "not_applicable": sum(1 for r in results if r["decision"] == DECISION_NA),
        "suspected": sum(1 for r in results if r["decision"] == DECISION_SUSPECTED)
    }
    
    # Extract findings (only confirmed vulnerabilities)
    findings = [
        r for r in results 
        if r["decision"] == DECISION_CONFIRMED
    ]
    
    logging.info(f"📊 Pipeline: {summary['positive']} positive, {summary['suspected']} suspected, {summary['abstain']} abstain, {summary['not_applicable']} NA")
    
    return {
        "job_id": job_id,
        "total_endpoints": len(endpoints),
        "eligible_targets": len(all_targets),
        "summary": summary,
        "results": results,
        "findings": findings
    }
