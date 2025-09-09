#!/usr/bin/env python3
"""
Test injection row creation and summary consistency.
"""

import pytest
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from backend.pipeline.workflow import assess_endpoints, upsert_row
from backend.modules.event_aggregator import get_aggregator, reset_aggregator

def test_inject_row_and_summary():
    """Test that injection success creates proper row and summary."""
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
    
    # Check summary structure
    summary = result["summary"]
    assert "total" in summary
    assert "positive" in summary
    assert "confirmed_probe" in summary
    assert "confirmed_ml_inject" in summary
    
    # Check meta structure
    meta = result["meta"]
    assert "strategy" in meta
    assert "probe_attempts" in meta
    assert "ml_inject_attempts" in meta
    assert "counters_consistent" in meta
    
    # For ml_only strategy, should have no probe attempts
    assert meta["probe_attempts"] == 0
    
    # Check that counters are consistent
    assert meta["counters_consistent"] == True
    
    # Check that summary counts match row counts
    results = result["results"]
    positive_count = sum(1 for r in results if r.get("decision") == "positive")
    assert summary["positive"] == positive_count
    
    # Check provenance field exists on positive results
    positive_results = [r for r in results if r.get("decision") == "positive"]
    for result_row in positive_results:
        assert "provenance" in result_row
        assert result_row["provenance"] in ["Probe", "Inject"]

def test_upsert_row_functionality():
    """Test the upsert_row helper function."""
    results = []
    
    # Test inserting new row
    key1 = ("xss", "GET", "http://test.com", "query", "param1")
    patch1 = {
        "decision": "positive",
        "provenance": "Inject",
        "cvss": {"base": 6.1},
        "evidence_id": "test-evidence-1"
    }
    
    row1 = upsert_row(results, key1, patch1)
    assert len(results) == 1
    assert row1["family"] == "xss"
    assert row1["decision"] == "positive"
    assert row1["provenance"] == "Inject"
    
    # Test updating existing row
    patch2 = {
        "decision": "positive",
        "provenance": "Probe",
        "cvss": {"base": 6.1},
        "evidence_id": "test-evidence-2"
    }
    
    row2 = upsert_row(results, key1, patch2)
    assert len(results) == 1  # Still only one row
    assert row2["family"] == "xss"
    assert row2["decision"] == "positive"
    assert row2["provenance"] == "Probe"  # Updated
    assert row2["evidence_id"] == "test-evidence-2"  # Updated
    
    # Test inserting different key
    key2 = ("sqli", "POST", "http://test.com", "form", "param2")
    patch3 = {
        "decision": "positive",
        "provenance": "Inject",
        "cvss": {"base": 9.1},
        "evidence_id": "test-evidence-3"
    }
    
    row3 = upsert_row(results, key2, patch3)
    assert len(results) == 2  # Now two rows
    assert row3["family"] == "sqli"
    assert row3["decision"] == "positive"
    assert row3["provenance"] == "Inject"

if __name__ == "__main__":
    test_inject_row_and_summary()
    test_upsert_row_functionality()
    print("✅ All tests passed!")
