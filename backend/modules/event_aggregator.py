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
            "counters_consistent": counters_consistent
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

# Global aggregator instance
_global_aggregator = AssessAggregator()

def get_aggregator() -> AssessAggregator:
    """Get the global aggregator instance."""
    return _global_aggregator

def reset_aggregator() -> None:
    """Reset the global aggregator."""
    _global_aggregator.reset()
