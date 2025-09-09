#!/usr/bin/env python3
"""
Test that ml_with_context strategy uses XSS canary as signal only.
"""

import pytest
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from backend.pipeline.workflow import assess_endpoints
from backend.modules.event_aggregator import get_aggregator, reset_aggregator

def test_strategy_canary_signal_only():
    """Test that ml_with_context uses XSS canary as signal only."""
    # Clear event aggregator
    reset_aggregator()
    
    # Mock endpoints with XSS parameters
    endpoints = [
        {
            "url": "http://127.0.0.1:5001/search?q=test",
            "method": "GET",
            "param_locs": {
                "query": ["q"]
            }
        }
    ]
    
    # Test ml_with_context strategy
    result = assess_endpoints(endpoints, "test-job", top_k=3, strategy="ml_with_context")
    
    # Check that we have results
    assert "results" in result
    assert "summary" in result
    assert "meta" in result
    
    # Check strategy
    meta = result["meta"]
    assert meta["strategy"] == "ml_with_context"
    
    # Check that no probe positives exist (XSS canary is signal only)
    summary = result["summary"]
    assert summary["confirmed_probe"] == 0
    
    # Check that no redirect family results exist
    results = result["results"]
    redirect_results = [r for r in results if r.get("family") == "redirect"]
    assert len(redirect_results) == 0
    
    # Check that probe attempts are recorded (for XSS canary signal)
    assert meta["probe_attempts"] > 0
    
    # Check for strategy violations
    violations = meta.get("violations", [])
    assert "strategy_violation:probe_positive_under_ml_with_context" not in violations
    assert "strategy_violation:redirect_family_under_ml_with_context" not in violations
    
    # Check that counters are consistent
    assert meta["counters_consistent"] == True

if __name__ == "__main__":
    test_strategy_canary_signal_only()
    print("✅ All tests passed!")
