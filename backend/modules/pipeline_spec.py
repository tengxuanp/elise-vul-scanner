"""
Spec-compliant pipeline implementation following ELISE_SYSTEM_WORKFLOW_SPEC.md

This module implements the exact pipeline structure defined in Section 5 of the spec.
"""

import time
from typing import Dict, Any, List, Optional
from threading import Lock
from backend.modules.targets import Target
from backend.modules.strategy import Plan, probe_enabled, injections_enabled
from backend.modules.event_aggregator import AssessAggregator
from backend.modules.decisions import DECISION


class SpecCompliantPipeline:
    """
    Spec-compliant pipeline implementation.
    
    Follows the exact pseudocode from Section 5 of the spec:
    for target in enumerate_targets():
      for family in families_for(target):
        # PROBE (guarded by plan)
        if probe_enabled(plan, family):
            probe_positive = run_probe(family, target, agg)
        
        # INJECT (Top-K) according to strategy
        should_inject = (
            plan.name == "auto" and not probe_positive
        ) or (
            plan.name in {"ml_only"} and injections_enabled(plan)
        ) or (
            plan.name == "hybrid" and injections_enabled(plan) and (
                not probe_positive or family != "xss"
            )
        )
    """
    
    def __init__(self, plan: Plan, top_k: int = 3):
        self.plan = plan
        self.top_k = top_k
        self.agg = AssessAggregator()
        self.results = []
        self.findings = []
        self.violations = []
    
    def process_target(self, target: Target, job_id: str, start_ts: float = None) -> Dict[str, Any]:
        """
        Process a single target following the spec-compliant pipeline.
        
        Args:
            target: Target to process
            job_id: Job ID for evidence storage
            start_ts: Start timestamp for budget calculations
            
        Returns:
            Result dictionary for this target
        """
        target_id = f"{target.url}:{target.param_in}:{target.param}"
        
        # Check if target is applicable
        if self._gate_not_applicable(target):
            return self._create_na_result(target, "gate_not_applicable")
        
        # Get families for this target
        families = self._families_for(target)
        if not families:
            return self._create_na_result(target, "no_candidates")
        
        # Process each family according to spec
        for family in families:
            probe_positive = False
            
            # PROBE (guarded by plan & DISABLE_PROBES)
            if probe_enabled(self.plan, family):
                probe_positive = self._run_probe(family, target)
            else:
                # Check for strategy violations
                if self._probe_was_called_despite_disabled(family):
                    self.violations.append(f"strategy_violation:{family}_probe_ran")
            
            # INJECT (Top-K) according to strategy
            should_inject = self._should_inject(family, probe_positive)
            
            if should_inject:
                result = self._run_injections(family, target, job_id, probe_positive)
                if result:
                    return result
        
        # If no family confirmed, return clean result
        return self._create_clean_result(target)
    
    def _families_for(self, target: Target) -> List[str]:
        """Get families applicable to this target."""
        families = []
        
        # Check each family's gating function
        if self._gate_candidate_xss(target):
            families.append("xss")
        if self._gate_candidate_sqli(target):
            families.append("sqli")
        if self._gate_candidate_redirect(target):
            families.append("redirect")
        
        return families
    
    def _should_inject(self, family: str, probe_positive: bool) -> bool:
        """
        Determine if injections should run for this family.
        
        Implements the spec logic:
        - auto: inject only if probe not positive
        - ml_only: always inject if injections enabled
        - hybrid: inject if not probe_positive OR (probe_positive and family != "xss")
        - probe_only: never inject
        """
        if not injections_enabled(self.plan):
            return False
        
        if self.plan.name == "auto":
            return not probe_positive
        elif self.plan.name == "ml_only":
            return True
        elif self.plan.name == "hybrid":
            return not probe_positive or family != "xss"
        elif self.plan.name == "probe_only":
            return False
        
        return False
    
    def _run_probe(self, family: str, target: Target) -> bool:
        """Run probe for family and return if positive."""
        # TODO: Implement actual probe logic
        # This should call the existing probe functions
        return False
    
    def _run_injections(self, family: str, target: Target, job_id: str, probe_positive: bool) -> Optional[Dict[str, Any]]:
        """Run Top-K injections for family."""
        # TODO: Implement injection logic
        # This should call the existing injection functions
        return None
    
    def _gate_not_applicable(self, target: Target) -> bool:
        """Check if target is not applicable."""
        # TODO: Implement gating logic
        return False
    
    def _gate_candidate_xss(self, target: Target) -> bool:
        """Check if target is candidate for XSS."""
        # TODO: Implement XSS gating
        return True
    
    def _gate_candidate_sqli(self, target: Target) -> bool:
        """Check if target is candidate for SQLi."""
        # TODO: Implement SQLi gating
        return True
    
    def _gate_candidate_redirect(self, target: Target) -> bool:
        """Check if target is candidate for redirect."""
        # TODO: Implement redirect gating
        return True
    
    def _probe_was_called_despite_disabled(self, family: str) -> bool:
        """Check if probe was called despite being disabled."""
        # TODO: Implement violation detection
        return False
    
    def _create_na_result(self, target: Target, reason: str) -> Dict[str, Any]:
        """Create not applicable result."""
        return {
            "target": target.to_dict(),
            "decision": DECISION["NA"],
            "why": [reason],
            "rank_source": "none",
            "attempt_idx": 0,
            "top_k_used": 0,
            "timing_ms": 0
        }
    
    def _create_clean_result(self, target: Target) -> Dict[str, Any]:
        """Create clean (no vulnerabilities found) result."""
        return {
            "target": target.to_dict(),
            "decision": DECISION["NEG"],
            "why": ["no_confirm_after_topk"],
            "rank_source": "ml" if self.agg.inject_attempts > 0 else "defaults",
            "ml_proba": None,  # Will be set from ML telemetry
            "attempt_idx": 0,
            "top_k_used": 0,
            "timing_ms": 0
        }
    
    def get_meta_data(self) -> Dict[str, Any]:
        """Get metadata from aggregator."""
        return self.agg.get_meta_data(self.results)
