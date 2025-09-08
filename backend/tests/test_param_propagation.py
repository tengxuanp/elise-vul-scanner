"""
Tests for parameter propagation in XSS and redirect results.

Tests that param_in and param are properly propagated from targets
to result rows even when rank_source is "probe_only".
"""

import pytest
from unittest.mock import patch, MagicMock

from backend.modules.probes.xss_canary import run_xss_probe, XssProbe
from backend.modules.probes.redirect_oracle import run_redirect_probe, RedirectProbe
from backend.modules.fuzzer_core import _process_target
from backend.pipeline.workflow import assess_endpoints

class TestParamPropagation:
    """Test parameter propagation from targets to results."""
    
    def test_xss_probe_includes_param_info(self):
        """Test that XSS probe includes param_in and param information."""
        # Mock response with canary reflection
        mock_response = MagicMock()
        mock_response.text = '<input value="EliseXSSCanary123">'
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "text/html"}
        
        with patch('httpx.request', return_value=mock_response):
            probe = run_xss_probe(
                url="http://example.com/test?q=test",
                method="GET",
                param_in="query",
                param="q",
                headers={}
            )
        
        assert probe.reflected is True
        assert probe.param_in == "query"
        assert probe.param == "q"
    
    def test_xss_probe_fallback_param_info(self):
        """Test that XSS probe provides fallback param info when not provided."""
        # Mock response with canary reflection
        mock_response = MagicMock()
        mock_response.text = '<input value="EliseXSSCanary123">'
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "text/html"}
        
        with patch('httpx.request', return_value=mock_response):
            probe = run_xss_probe(
                url="http://example.com/test",
                method="GET",
                param_in=None,
                param=None,
                headers={}
            )
        
        assert probe.reflected is True
        assert probe.param_in == "unknown"
        assert probe.param == "<reflected>"
    
    def test_redirect_probe_includes_param_info(self):
        """Test that redirect probe includes param_in and param information."""
        # Mock response with redirect
        mock_response = MagicMock()
        mock_response.status_code = 302
        mock_response.headers = {"location": "https://example.com/"}
        
        with patch('httpx.request', return_value=mock_response):
            probe = run_redirect_probe(
                url="http://example.com/test?q=test",
                method="GET",
                param_in="query",
                param="q",
                headers={}
            )
        
        assert probe.influence is True
        assert probe.param_in == "header"
        assert probe.param == "location"
    
    def test_fuzzer_propagates_xss_param_info(self):
        """Test that fuzzer propagates param info from XSS probe to result."""
        # Create a mock target
        target = MagicMock()
        target.url = "http://example.com/test?q=test"
        target.method = "GET"
        target.param_in = "query"
        target.param = "q"
        target.headers = {}
        target.to_dict.return_value = {
            "url": "http://example.com/test?q=test",
            "method": "GET",
            "param_in": "query",
            "param": "q"
        }
        
        # Create mock probe bundle with XSS reflection
        probe_bundle = MagicMock()
        probe_bundle.xss = MagicMock()
        probe_bundle.xss.reflected = True
        probe_bundle.xss.param_in = "query"
        probe_bundle.xss.param = "q"
        probe_bundle.xss.xss_context = "attr"
        probe_bundle.xss.xss_escaping = "html"
        probe_bundle.sqli = MagicMock()
        probe_bundle.redirect = MagicMock()
        
        with patch('backend.modules.fuzzer_core.run_probes') as mock_run_probes:
            mock_run_probes.return_value = probe_bundle
            
            with patch('backend.modules.fuzzer_core._confirmed_family') as mock_confirmed:
                mock_confirmed.return_value = ("xss", "xss_reflection")
                
                result = _process_target(target, "test-job", 3, MagicMock(), MagicMock())
                
                # Check that param info is propagated
                assert result["param_in"] == "query"
                assert result["param"] == "q"
                assert result["family"] == "xss"
                assert result["decision"] == "positive"
                assert result["rank_source"] == "probe_only"
    
    def test_fuzzer_propagates_redirect_param_info(self):
        """Test that fuzzer propagates param info from redirect probe to result."""
        # Create a mock target
        target = MagicMock()
        target.url = "http://example.com/test?q=test"
        target.method = "GET"
        target.param_in = "query"
        target.param = "q"
        target.headers = {}
        target.to_dict.return_value = {
            "url": "http://example.com/test?q=test",
            "method": "GET",
            "param_in": "query",
            "param": "q"
        }
        
        # Create mock probe bundle with redirect
        probe_bundle = MagicMock()
        probe_bundle.xss = MagicMock()
        probe_bundle.sqli = MagicMock()
        probe_bundle.redirect = MagicMock()
        probe_bundle.redirect.influence = True
        probe_bundle.redirect.param_in = "header"
        probe_bundle.redirect.param = "location"
        
        with patch('backend.modules.fuzzer_core.run_probes') as mock_run_probes:
            mock_run_probes.return_value = probe_bundle
            
            with patch('backend.modules.fuzzer_core._confirmed_family') as mock_confirmed:
                mock_confirmed.return_value = ("redirect", "redirect_location_reflects")
                
                result = _process_target(target, "test-job", 3, MagicMock(), MagicMock())
                
                # Check that param info is propagated
                assert result["param_in"] == "header"
                assert result["param"] == "location"
                assert result["family"] == "redirect"
                assert result["decision"] == "positive"
                assert result["rank_source"] == "probe_only"
    
    def test_assess_endpoints_includes_param_info_in_results(self):
        """Test that assess_endpoints includes param info in final results."""
        endpoints = [
            {
                "url": "http://example.com/test?q=test",
                "method": "GET",
                "path": "/test",
                "param_locs": {"query": ["q"], "form": [], "json": []},
                "status": 200,
                "content_type": "text/html"
            }
        ]
        
        with patch('backend.modules.fuzzer_core.run_probes') as mock_run_probes:
            # Create mock probe bundle with XSS reflection
            probe_bundle = MagicMock()
            probe_bundle.xss = MagicMock()
            probe_bundle.xss.reflected = True
            probe_bundle.xss.param_in = "query"
            probe_bundle.xss.param = "q"
            probe_bundle.xss.xss_context = "attr"
            probe_bundle.xss.xss_escaping = "html"
            probe_bundle.sqli = MagicMock()
            probe_bundle.redirect = MagicMock()
            
            mock_run_probes.return_value = probe_bundle
            
            with patch('backend.modules.fuzzer_core._confirmed_family') as mock_confirmed:
                mock_confirmed.return_value = ("xss", "xss_reflection")
                
                result = assess_endpoints(endpoints, "test-job", top_k=3)
                
                # Check that results include param info
                assert len(result["results"]) > 0
                xss_result = next(r for r in result["results"] if r["family"] == "xss")
                assert xss_result["param_in"] == "query"
                assert xss_result["param"] == "q"
                assert xss_result["rank_source"] == "probe_only"

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
