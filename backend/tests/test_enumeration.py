"""
Tests for deterministic target enumeration.
"""
import json
import pytest
from pathlib import Path
from backend.modules.targets import enumerate_targets_from_endpoints
from backend.modules.gates import gate_candidate_xss, gate_candidate_sqli, gate_not_applicable
from backend.modules.targets import Target


class TestTargetEnumeration:
    """Test deterministic target enumeration from endpoints."""
    
    def test_enumerate_from_fixture(self):
        """Test enumeration from sample endpoints fixture."""
        fixture_path = Path(__file__).parent / "fixtures" / "endpoints_sample.json"
        with open(fixture_path, 'r') as f:
            endpoints = json.load(f)
        
        targets = enumerate_targets_from_endpoints(endpoints)
        
        # Should have at least 7 targets (one per parameter)
        assert len(targets) >= 7, f"Expected >=7 targets, got {len(targets)}"
        
        # Check that we have targets for different param_in values
        param_ins = set(target["param_in"] for target in targets)
        assert "query" in param_ins, "Should have query parameters"
        assert "form" in param_ins, "Should have form parameters"
        assert "json" in param_ins, "Should have json parameters"
        
        # Check specific parameters are present
        param_names = [target["param"] for target in targets]
        assert "id" in param_names, "Should have 'id' parameter"
        assert "name" in param_names, "Should have 'name' parameter"
        assert "msg" in param_names, "Should have 'msg' parameter"
        assert "q" in param_names, "Should have 'q' parameter"
        assert "url" in param_names, "Should have 'url' parameter"
        assert "username" in param_names, "Should have 'username' parameter"
        assert "password" in param_names, "Should have 'password' parameter"
        assert "content" in param_names, "Should have 'content' parameter"
        
        # Check base_params are set correctly
        for target in targets:
            assert "base_params" in target, "Each target should have base_params"
            if target["param_in"] == "query":
                # Query params should have actual base params or empty dict
                assert isinstance(target["base_params"], dict)
            elif target["param_in"] == "form":
                assert target["base_params"] == {"__form_present__": True}
            elif target["param_in"] == "json":
                assert target["base_params"] == {"__json_present__": True}
    
    def test_enumerate_empty_endpoints(self):
        """Test enumeration with empty endpoints list."""
        targets = enumerate_targets_from_endpoints([])
        assert targets == []
    
    def test_enumerate_endpoints_no_params(self):
        """Test enumeration with endpoints that have no parameters."""
        endpoints = [
            {
                "url": "http://test.com/",
                "path": "/",
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
        targets = enumerate_targets_from_endpoints(endpoints)
        assert targets == []
    
    def test_enumerate_legacy_params_format(self):
        """Test enumeration with legacy params format."""
        endpoints = [
            {
                "url": "http://test.com/page?param1=value1&param2=value2",
                "path": "/page",
                "method": "GET",
                "status": 200,
                "content_type": "text/html",
                "params": ["param1", "param2"]  # Legacy format
            }
        ]
        targets = enumerate_targets_from_endpoints(endpoints)
        assert len(targets) == 2
        assert all(target["param_in"] == "query" for target in targets)
        param_names = [target["param"] for target in targets]
        assert "param1" in param_names
        assert "param2" in param_names


class TestGatesAcceptAllParamTypes:
    """Test that gates accept query, form, and json param_in values."""
    
    def test_candidate_xss_accepts_all_types(self):
        """Test that XSS gate accepts query, form, and json parameters."""
        for param_in in ["query", "form", "json"]:
            target = Target(
                url="http://test.com/page",
                method="GET",
                param_in=param_in,
                param="test_param",
                content_type="text/html"
            )
            assert gate_candidate_xss(target), f"XSS gate should accept {param_in} parameters"
    
    def test_candidate_sqli_accepts_all_types(self):
        """Test that SQLi gate accepts query, form, and json parameters."""
        for param_in in ["query", "form", "json"]:
            target = Target(
                url="http://test.com/api",
                method="POST",
                param_in=param_in,
                param="test_param",
                content_type="application/json"
            )
            assert gate_candidate_sqli(target), f"SQLi gate should accept {param_in} parameters"
    
    def test_gate_not_applicable_no_param(self):
        """Test that gate_not_applicable returns True for targets with no param."""
        target = Target(
            url="http://test.com/page",
            method="GET",
            param_in="query",
            param=None  # No parameter
        )
        assert gate_not_applicable(target), "Should be not applicable when param is None"
        
        target = Target(
            url="http://test.com/page",
            method="GET",
            param_in="query",
            param=""  # Empty parameter
        )
        assert gate_not_applicable(target), "Should be not applicable when param is empty"
    
    def test_gate_not_applicable_no_url(self):
        """Test that gate_not_applicable returns True for targets with no URL."""
        target = Target(
            url="",  # No URL
            method="GET",
            param_in="query",
            param="test_param"
        )
        assert gate_not_applicable(target), "Should be not applicable when URL is empty"
    
    def test_gate_not_applicable_no_method(self):
        """Test that gate_not_applicable returns True for targets with no method."""
        target = Target(
            url="http://test.com/page",
            method="",  # No method
            param_in="query",
            param="test_param"
        )
        assert gate_not_applicable(target), "Should be not applicable when method is empty"
