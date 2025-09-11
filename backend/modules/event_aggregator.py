"""
Event aggregator for truthful counter tracking.

Tracks actual probe and injection attempts during assessment.
"""

from typing import Dict, Any

class AssessAggregator:
    """
    In-memory aggregator for assessment events.
    
    Tracks actual probe and injection attempts to provide truthful counters.
    """
    
    def __init__(self):
        self.probe_attempts = 0
        self.probe_successes = 0
        self.inject_attempts = 0
        self.inject_successes = 0
        self.xss_context_pool_used = 0
        self.xss_first_hit_attempts_ctx = 0
        self.xss_first_hit_attempts_baseline = 0
        
        # FAMILY TRACKING: Store attempt_family, payload_family, classified_family
        self.family_stats = {
            "attempt_families": {},  # family -> count
            "payload_families": {},  # family -> count  
            "classified_families": {},  # family -> count
            "family_mismatches": 0  # count of mismatches
        }
        
        # ML STATE TRACKING: Track require_ranker violations
        self.ml_stats = {
            "ranker_active_count": 0,
            "ranker_inactive_count": 0,
            "require_ranker_violated": False
        }
        
    def record_probe_attempt(self, success: bool) -> None:
        """
        Record a probe attempt.
        
        Args:
            success: Whether the probe was successful (found vulnerability)
        """
        self.probe_attempts += 1
        if success:
            self.probe_successes += 1
    
    def record_inject_attempt(self, success: bool) -> None:
        """
        Record an injection attempt.
        
        Args:
            success: Whether the injection was successful (found vulnerability)
        """
        self.inject_attempts += 1
        if success:
            self.inject_successes += 1
    
    def record_context_pool_usage(self) -> None:
        """Record usage of context pool."""
        self.xss_context_pool_used += 1
    
    def record_family_attempt(self, attempt_family: str, payload_family: str = None, classified_family: str = None) -> None:
        """
        Record family information for an attempt.
        
        Args:
            attempt_family: The family being attempted
            payload_family: The family of the payload used
            classified_family: The family the ML model classified this as
        """
        # Track attempt family
        self.family_stats["attempt_families"][attempt_family] = self.family_stats["attempt_families"].get(attempt_family, 0) + 1
        
        # Track payload family if provided
        if payload_family:
            self.family_stats["payload_families"][payload_family] = self.family_stats["payload_families"].get(payload_family, 0) + 1
        
        # Track classified family if provided
        if classified_family:
            self.family_stats["classified_families"][classified_family] = self.family_stats["classified_families"].get(classified_family, 0) + 1
        
        # Track mismatches
        if payload_family and attempt_family != payload_family:
            self.family_stats["family_mismatches"] += 1
        if classified_family and attempt_family != classified_family:
            self.family_stats["family_mismatches"] += 1
    
    def record_first_hit_attempt(self, context_guided: bool) -> None:
        """
        Record a first-hit attempt.
        
        Args:
            context_guided: Whether this was a context-guided attempt
        """
        if context_guided:
            self.xss_first_hit_attempts_ctx += 1
        else:
            self.xss_first_hit_attempts_baseline += 1
    
    def record_ml_state(self, ranker_active: bool, require_ranker: bool = False) -> None:
        """
        Record ML state for require_ranker violation tracking.
        
        Args:
            ranker_active: Whether the ranker was active for this attempt
            require_ranker: Whether ranker is required for this strategy
        """
        if ranker_active:
            self.ml_stats["ranker_active_count"] += 1
        else:
            self.ml_stats["ranker_inactive_count"] += 1
            
        # Check for require_ranker violation
        if require_ranker and not ranker_active:
            self.ml_stats["require_ranker_violated"] = True
    
    def build_summary(self, results: list) -> Dict[str, Any]:
        """
        Build comprehensive summary with invariant checks (SSOT).
        
        Args:
            results: List of result rows
            
        Returns:
            Summary dictionary with flags for inconsistencies
        """
        # Count results by decision and family
        decision_counts = {}
        family_counts = {}
        provenance_counts = {"confirmed_probe": 0, "confirmed_inject": 0}
        
        for result in results:
            decision = result.get("decision", "unknown")
            family = result.get("family", "unknown")
            why = result.get("why", [])
            
            # Count by decision
            decision_counts[decision] = decision_counts.get(decision, 0) + 1
            
            # Count by family (only for positive results)
            if decision == "positive":
                family_counts[family] = family_counts.get(family, 0) + 1
                
                # Provenance is tracked by the aggregator's own counters, not inferred from why
                # We'll set the provenance based on the aggregator's counters after the loop
        
        # Calculate totals
        positives_total = decision_counts.get("positive", 0)
        suspected_total = decision_counts.get("suspected", 0)
        clean_total = decision_counts.get("clean", 0)
        
        # Set provenance based on family and detection method
        # SQLi and Redirect are rule-based (probe), XSS uses ML (inject)
        for result in results:
            if result.get("decision") == "positive":
                family = result.get("family", "unknown")
                if family in ["sqli", "redirect"]:
                    provenance_counts["confirmed_probe"] += 1
                elif family == "xss":
                    provenance_counts["confirmed_inject"] += 1
        
        # Invariant checks
        flags = {}
        
        # Check counter consistency
        # Note: probe_successes and inject_successes can overlap (same vuln found by both)
        # So we can't just add them. Instead, check that we have at least some successes if we have positives
        has_successes = self.probe_successes > 0 or self.inject_successes > 0
        if positives_total > 0 and not has_successes:
            flags["counts_inconsistent"] = True
            flags["counts_diff"] = {
                "expected": "at least one success",
                "actual": positives_total,
                "probe_successes": self.probe_successes,
                "inject_successes": self.inject_successes,
                "issue": "positive results but no probe or inject successes recorded"
            }
        elif positives_total == 0 and has_successes:
            flags["counts_inconsistent"] = True
            flags["counts_diff"] = {
                "expected": 0,
                "actual": positives_total,
                "probe_successes": self.probe_successes,
                "inject_successes": self.inject_successes,
                "issue": "probe or inject successes recorded but no positive results"
            }
        
        # Check require_ranker violation
        if self.ml_stats["require_ranker_violated"]:
            flags["require_ranker_violated"] = True
            flags["require_ranker_message"] = f"Ranker required but inactive on {self.ml_stats['ranker_inactive_count']} attempts"
        
        # Check family mismatches
        if self.family_stats["family_mismatches"] > 0:
            flags["family_mismatches"] = True
            flags["family_mismatch_count"] = self.family_stats["family_mismatches"]
        
        return {
            "totals": {
                "endpoints_crawled": 0,  # Would need to be tracked separately
                "targets_enumerated": len(results),
                "probe_attempts": self.probe_attempts,
                "ml_inject_attempts": self.inject_attempts,
                "positives_total": positives_total,
                "suspected_total": suspected_total,
                "clean_total": clean_total
            },
            "provenance": provenance_counts,
            "families": {
                family: {"positives": count} for family, count in family_counts.items()
            },
            "flags": flags,
            "ml_stats": self.ml_stats,
            "family_stats": self.family_stats
        }
    
    def get_meta_data(self, results: list) -> Dict[str, Any]:
        """
        Get metadata dictionary with counters and consistency check.
        
        Args:
            results: List of result rows
            
        Returns:
            Metadata dictionary
        """
        # Count positive results from actual rows
        positive_count = sum(1 for r in results if r.get("decision") == "positive")
        
        # Calculate consistency
        counters_consistent = (self.probe_successes + self.inject_successes) == positive_count
        
        # Calculate attempts saved
        attempts_saved = max(0, self.xss_first_hit_attempts_baseline - self.xss_first_hit_attempts_ctx)
        
        return {
            "probe_attempts": self.probe_attempts,
            "probe_successes": self.probe_successes,
            "ml_inject_attempts": self.inject_attempts,
            "ml_inject_successes": self.inject_successes,
            "xss_ctx_pool_used": self.xss_context_pool_used,
            "xss_first_hit_attempts_ctx": self.xss_first_hit_attempts_ctx,
            "xss_first_hit_attempts_baseline": self.xss_first_hit_attempts_baseline,
            "xss_first_hit_attempts_delta": attempts_saved,
            "counters_consistent": counters_consistent,
            "ml_stats": self.ml_stats,
            "family_stats": self.family_stats
        }
    
    def reset(self) -> None:
        """Reset all counters."""
        self.probe_attempts = 0
        self.probe_successes = 0
        self.inject_attempts = 0
        self.inject_successes = 0
        self.xss_context_pool_used = 0
        self.xss_first_hit_attempts_ctx = 0
        self.xss_first_hit_attempts_baseline = 0

# Job-scoped aggregator storage
import contextvars
from typing import Dict

_current_job_id = contextvars.ContextVar('current_job_id', default=None)
_job_aggregators: Dict[str, AssessAggregator] = {}

def set_current_job(job_id: str) -> None:
    """Set the current job ID for this context."""
    _current_job_id.set(job_id)
    if job_id not in _job_aggregators:
        _job_aggregators[job_id] = AssessAggregator()

def get_aggregator() -> AssessAggregator:
    """Get the aggregator for the current job."""
    job_id = _current_job_id.get()
    if job_id is None:
        # Fallback to global aggregator for backward compatibility
        if 'global' not in _job_aggregators:
            _job_aggregators['global'] = AssessAggregator()
        return _job_aggregators['global']
    
    if job_id not in _job_aggregators:
        _job_aggregators[job_id] = AssessAggregator()
    
    return _job_aggregators[job_id]

def reset_aggregator() -> None:
    """Reset the aggregator for the current job."""
    job_id = _current_job_id.get()
    if job_id is None:
        # Reset global aggregator
        if 'global' in _job_aggregators:
            _job_aggregators['global'].reset()
    else:
        if job_id in _job_aggregators:
            _job_aggregators[job_id].reset()

def cleanup_job_aggregator(job_id: str) -> None:
    """Clean up aggregator for a specific job."""
    if job_id in _job_aggregators:
        del _job_aggregators[job_id]
