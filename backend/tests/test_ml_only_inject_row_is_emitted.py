#!/usr/bin/env python3
"""
Test that ML-only strategy emits injection rows properly.
"""

import pytest
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from backend.pipeline.workflow import assess_endpoints
from backend.modules.event_aggregator import reset_aggregator

def test_ml_only_inject_row_is_emitted():
    """Test that ML-only strategy emits injection rows properly."""
    # Clear event aggregator
    reset_aggregator()
    
    # Mock endpoints with parameters
    endpoints = [
        {
            "url": "http://127.0.0.1:5001/test",
            "method": "GET",
            "param_locs": {
                "query": ["param1"]
            }
        }
    ]
    
    # Test ml_only strategy
    result = assess_endpoints(endpoints, "test-job", top_k=3, strategy="ml_only")
    
    # Check that we have results
    assert "results" in result
    assert "summary" in result
    assert "meta" in result
    
    # Check strategy
    meta = result["meta"]
    assert meta["strategy"] == "ml_only"
    
    # Check that no probe attempts were made
    assert meta["probe_attempts"] == 0
    
    # Check that ML injection attempts were made
    assert meta["ml_inject_attempts"] > 0
    
    # Check summary
    summary = result["summary"]
    
    # Check that counters are consistent
    assert meta["counters_consistent"] == True
    
    # Check that if we have positive results, they have provenance="Inject"
    results = result["results"]
    positive_results = [r for r in results if r.get("decision") == "positive"]
    
    for result_row in positive_results:
        assert result_row.get("provenance") == "Inject"
        assert result_row.get("rank_source") in ["ml", "ml_ranked", "ctx_pool"]
    
    # Check that confirmed_ml_inject matches positive results with provenance="Inject"
    inject_positives = [r for r in results if r.get("decision") == "positive" and r.get("provenance") == "Inject"]
    assert summary["confirmed_ml_inject"] == len(inject_positives)
    
    # Check that confirmed_probe is 0 (no probe positives allowed in ml_only)
    assert summary["confirmed_probe"] == 0
    
    # Check for strategy violations
    violations = meta.get("violations", [])
    probe_violations = [v for v in violations if "probe_positive_under_ml_only" in v]
    assert len(probe_violations) == 0  # No probe positives should exist

if __name__ == "__main__":
    test_ml_only_inject_row_is_emitted()
    print("✅ ML-only injection row test passed!")
