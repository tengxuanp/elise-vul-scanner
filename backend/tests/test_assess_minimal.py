#!/usr/bin/env python3
"""
Minimal tests for the assessment workflow
"""

import json
import sys
import os
from pathlib import Path

# Add backend directory to path for imports
backend_dir = Path(__file__).parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from pipeline.workflow import assess_endpoints


def test_assess_no_params_creates_no_targets():
    """
    Test that endpoints with no parameters create no targets (correct behavior)
    """
    eps = [{
        "url": "http://localhost:5001/health",
        "path": "/health",
        "method": "GET",
        "status": 200,
        "params": [],
        "param_locs": {
            "query": [],
            "form": [],
            "json": []
        },
        "content_type": "text/html"
    }]
    
    out = assess_endpoints(eps, "job_x", 1)
    
    # Should have 0 results since no parameters = no targets to test
    assert out["summary"]["total"] == 0, f"Expected 0 total results, got {out['summary']['total']}"
    assert len(out["results"]) == 0, f"Expected 0 results, got {len(out['results'])}"
    
    # Verify the structure
    assert "summary" in out
    assert "results" in out
    assert "findings" in out
    assert "job_id" in out
    
    # Verify job_id is set correctly
    assert out["job_id"] == "job_x"
    
    print("✅ test_assess_no_params_creates_no_targets passed")


def test_assess_with_params_creates_targets():
    """
    Test that endpoints with parameters create targets for assessment
    """
    eps = [{
        "url": "http://localhost:5001/search?q=test",
        "path": "/search",
        "method": "GET",
        "status": 200,
        "params": ["q"],
        "param_locs": {
            "query": ["q"],
            "form": [],
            "json": []
        },
        "content_type": "text/html"
    }]
    
    out = assess_endpoints(eps, "job_y", 1)
    
    # Should have at least 1 result (the target with parameter)
    assert len(out["results"]) >= 1, f"Expected at least 1 result, got {len(out['results'])}"
    
    # Verify the result structure
    result = out["results"][0]
    assert "target" in result
    assert "decision" in result
    assert "why" in result
    
    # Verify target structure
    target = result["target"]
    assert target["param"] == "q"
    assert target["param_in"] == "query"
    assert target["method"] == "GET"
    
    print("✅ test_assess_with_params_creates_targets passed")


def test_assess_workflow_structure():
    """
    Test that the assessment workflow returns the expected structure
    """
    eps = [{
        "url": "http://localhost:5001/test",
        "path": "/test",
        "method": "GET",
        "status": 200,
        "params": [],
        "param_locs": {
            "query": [],
            "form": [],
            "json": []
        },
        "content_type": "text/html"
    }]
    
    out = assess_endpoints(eps, "job_structure_test", 1)
    
    # Verify top-level structure
    required_keys = ["summary", "results", "findings", "job_id"]
    for key in required_keys:
        assert key in out, f"Missing required key: {key}"
    
    # Verify summary structure
    summary = out["summary"]
    required_summary_keys = ["total", "positive", "suspected", "abstain", "na"]
    for key in required_summary_keys:
        assert key in summary, f"Missing required summary key: {key}"
        assert isinstance(summary[key], int), f"Summary key {key} should be int, got {type(summary[key])}"
    
    # Verify results is a list
    assert isinstance(out["results"], list), "Results should be a list"
    
    # Verify findings is a list
    assert isinstance(out["findings"], list), "Findings should be a list"
    
    print("✅ test_assess_workflow_structure passed")


if __name__ == "__main__":
    print("🧪 Running minimal assessment tests...")
    
    try:
        test_assess_no_params_creates_no_targets()
        test_assess_with_params_creates_targets()
        test_assess_workflow_structure()
        
        print("\n✅ All minimal assessment tests passed!")
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
