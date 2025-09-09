"""
Decision canonicalization module for Elise.

Ensures consistent decision taxonomy across the system.
"""

from typing import Dict, Any

# Canonical decision mapping
CANONICAL_DECISIONS = {
    "clean": "abstain",
    "not_vulnerable": "abstain",
    "negative": "abstain",
    "safe": "abstain",
    "vulnerable": "positive",
    "exploitable": "positive",
    "confirmed": "positive",
    "detected": "positive",
    "found": "positive",
    "possible": "suspected",
    "likely": "suspected",
    "potential": "suspected",
    "maybe": "suspected",
    "unknown": "abstain",
    "unclear": "abstain",
    "inconclusive": "abstain",
    "failed": "error",
    "exception": "error",
    "timeout": "error",
    "skipped": "not_applicable",
    "na": "not_applicable",
    "n/a": "not_applicable",
    "none": "not_applicable",
    "no_params": "not_applicable",
    "no_parameters": "not_applicable"
}

# Valid canonical decisions
VALID_DECISIONS = {"positive", "suspected", "abstain", "not_applicable", "error"}

def canonical_decision(decision: str) -> str:
    """
    Canonicalize a decision string to the standard taxonomy.
    
    Args:
        decision: Raw decision string (can be None, empty, or any case)
        
    Returns:
        Canonical decision: one of {"positive", "suspected", "abstain", "not_applicable", "error"}
    """
    if not decision:
        return "abstain"
    
    # Normalize to lowercase
    normalized = str(decision).lower().strip()
    
    # Check if already canonical
    if normalized in VALID_DECISIONS:
        return normalized
    
    # Apply canonical mapping
    canonical = CANONICAL_DECISIONS.get(normalized, "abstain")
    
    return canonical

def canonicalize_result_row(row: Dict[str, Any]) -> Dict[str, Any]:
    """
    Canonicalize a result row's decision field.
    
    Args:
        row: Result row dictionary
        
    Returns:
        Updated row with canonical decision
    """
    if "decision" in row:
        row["decision"] = canonical_decision(row["decision"])
    
    return row

def canonicalize_results(results: list) -> list:
    """
    Canonicalize all decisions in a results list.
    
    Args:
        results: List of result dictionaries
        
    Returns:
        Updated results with canonical decisions
    """
    return [canonicalize_result_row(row) for row in results]

def ensure_telemetry_defaults(row: Dict[str, Any]) -> Dict[str, Any]:
    """
    Ensure non-null telemetry defaults on a result row.
    
    Args:
        row: Result row dictionary
        
    Returns:
        Updated row with telemetry defaults
    """
    # Set telemetry defaults
    row.setdefault("attempt_idx", 0)
    row.setdefault("top_k_used", 0)
    
    # Set rank_source based on decision and why codes
    if "rank_source" not in row:
        why_codes = row.get("why", [])
        if "probe_proof" in why_codes:
            row["rank_source"] = "probe_only"
        elif row.get("decision") == "not_applicable":
            row["rank_source"] = "none"
        else:
            row["rank_source"] = "ml_ranked"
    
    return row

def ensure_all_telemetry_defaults(results: list) -> list:
    """
    Ensure non-null telemetry defaults on all result rows.
    
    Args:
        results: List of result dictionaries
        
    Returns:
        Updated results with telemetry defaults
    """
    return [ensure_telemetry_defaults(row) for row in results]
