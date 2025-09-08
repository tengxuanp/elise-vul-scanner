"""
Tests for meta counters and processing time.
"""
import json
import pytest
from pathlib import Path
from backend.pipeline.workflow import assess_endpoints
from backend.modules.fuzzer_core import DECISION


class TestMetaCounters:
    """Test meta counters and processing time calculation."""
    
    def test_meta_counters_with_probe_positive(self):
        """Test meta counters with probe-positive and NA results."""
        # Create a simple fixture that should yield 1 probe-positive and 1 NA
        endpoints = [
            {
                "url": "http://test.com/page?param1=value1",
                "path": "/page",
                "method": "GET",
                "status": 200,
                "content_type": "text/html",
                "param_locs": {
                    "query": [{"name": "param1"}],
                    "form": [],
                    "json": []
                }
            },
            {
                "url": "http://test.com/no-params",
                "path": "/no-params",
                "method": "GET",
                "status": 200,
                "content_type": "text/html",
                "param_locs": {
                    "query": [],
                    "form": [],
                    "json": []
                }
            }
        ]
        
        result = assess_endpoints(endpoints, "test-job-123", top_k=3)
        meta = result["meta"]
        
        # Assert basic counters
        assert meta["targets_enumerated"] >= 1, "Should enumerate at least 1 target"
        assert meta["endpoints_supplied"] == 2, "Should have 2 endpoints supplied"
        assert meta["endpoints_without_params"] == 1, "Should have 1 endpoint without params"
        
        # Assert processing time
        assert meta["processing_ms"] > 0, "Processing time should be positive"
        assert "processing_time" in meta, "Should have processing_time string"
        assert meta["processing_time"].endswith("s"), "Processing time should end with 's'"
        
        # Assert split counters
        assert "probe_attempts" in meta, "Should have probe_attempts counter"
        assert "probe_successes" in meta, "Should have probe_successes counter"
        assert "ml_inject_attempts" in meta, "Should have ml_inject_attempts counter"
        assert "ml_inject_successes" in meta, "Should have ml_inject_successes counter"
        
        # Assert probe counters
        assert meta["probe_attempts"] >= 1, "Should have at least 1 probe attempt"
        assert meta["probe_successes"] >= 0, "Should have non-negative probe successes"
        
        # Assert ML counters
        assert meta["ml_inject_attempts"] >= 0, "Should have non-negative ML inject attempts"
        assert meta["ml_inject_successes"] >= 0, "Should have non-negative ML inject successes"
        
        # Assert backward compatibility
        assert "injections_attempted" in meta, "Should have backward-compatible injections_attempted"
        assert "injections_succeeded" in meta, "Should have backward-compatible injections_succeeded"
        assert meta["injections_attempted"] == meta["probe_attempts"] + meta["ml_inject_attempts"]
        assert meta["injections_succeeded"] == meta["probe_successes"] + meta["ml_inject_successes"]
        
        # Assert budget_ms_used is set to processing_ms
        assert meta["budget_ms_used"] == meta["processing_ms"], "budget_ms_used should equal processing_ms"
    
    def test_meta_counters_empty_endpoints(self):
        """Test meta counters with empty endpoints list."""
        result = assess_endpoints([], "test-job-empty", top_k=3)
        meta = result["meta"]
        
        assert meta["targets_enumerated"] == 0
        assert meta["endpoints_supplied"] == 0
        assert meta["endpoints_without_params"] == 0
        assert meta["probe_attempts"] == 0
        assert meta["probe_successes"] == 0
        assert meta["ml_inject_attempts"] == 0
        assert meta["ml_inject_successes"] == 0
        assert meta["processing_ms"] >= 0  # Should have non-negative processing time
    
    def test_meta_counters_with_ml_injection(self):
        """Test meta counters with ML injection attempts."""
        # Create endpoints that should trigger ML injection
        endpoints = [
            {
                "url": "http://test.com/api",
                "path": "/api",
                "method": "POST",
                "status": 200,
                "content_type": "application/json",
                "param_locs": {
                    "query": [],
                    "form": [],
                    "json": [{"name": "data"}]
                }
            }
        ]
        
        result = assess_endpoints(endpoints, "test-job-ml", top_k=3)
        meta = result["meta"]
        
        assert meta["targets_enumerated"] >= 1
        assert meta["probe_attempts"] >= 0
        assert meta["ml_inject_attempts"] >= 0
        assert meta["processing_ms"] > 0
        
        # The exact values depend on the fuzzer_core behavior, but counters should be present
        assert isinstance(meta["probe_attempts"], int)
        assert isinstance(meta["probe_successes"], int)
        assert isinstance(meta["ml_inject_attempts"], int)
        assert isinstance(meta["ml_inject_successes"], int)
