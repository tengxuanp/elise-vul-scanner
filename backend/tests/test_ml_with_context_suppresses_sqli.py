#!/usr/bin/env python3
"""
Test that ml_with_context strategy suppresses SQLi probes.
"""

import pytest
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from backend.pipeline.workflow import assess_endpoints
from backend.modules.event_aggregator import reset_aggregator

def test_ml_with_context_suppresses_sqli():
    """Test that ml_with_context strategy suppresses SQLi probes."""
    # Clear event aggregator
    reset_aggregator()
    
    # Mock endpoints with SQLi parameters
    endpoints = [
        {
            "url": "http://127.0.0.1:5001/product?id=1",
            "method": "GET",
            "param_locs": {
                "query": ["id"]
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
    
    # Check that no SQLi probe positives exist
    results = result["results"]
    sqli_probe_positives = [r for r in results if r.get("family") == "sqli" and r.get("provenance") == "Probe" and r.get("decision") == "positive"]
    assert len(sqli_probe_positives) == 0
    
    # Check that no redirect probe positives exist
    redirect_probe_positives = [r for r in results if r.get("family") == "redirect" and r.get("provenance") == "Probe" and r.get("decision") == "positive"]
    assert len(redirect_probe_positives) == 0
    
    # Check summary
    summary = result["summary"]
    
    # Check that confirmed_probe is 0 (no probe positives allowed except XSS canary as signal)
    assert summary["confirmed_probe"] == 0
    
    # Check for strategy violations
    violations = meta.get("violations", [])
    sqli_violations = [v for v in violations if "sqli" in v and "probe_positive" in v]
    assert len(sqli_violations) == 0  # No SQLi probe positives should exist
    
    redirect_violations = [v for v in violations if "redirect" in v and "family" in v]
    assert len(redirect_violations) == 0  # No redirect family should exist
    
    # Check that counters are consistent
    assert meta["counters_consistent"] == True
    
    # Check that if we have positive results, they should be from injections, not probes
    positive_results = [r for r in results if r.get("decision") == "positive"]
    for result_row in positive_results:
        if result_row.get("family") in ["sqli", "redirect"]:
            assert result_row.get("provenance") == "Inject"  # Should be injection, not probe

if __name__ == "__main__":
    test_ml_with_context_suppresses_sqli()
    print("✅ ML-with-context SQLi suppression test passed!")
