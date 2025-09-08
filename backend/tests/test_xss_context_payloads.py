"""
Tests for XSS Context-Aware Payload Selection

Tests that XSS payloads are selected based on context and escaping,
and that uplift metrics are properly tracked.
"""

import pytest
from unittest.mock import patch, MagicMock

from backend.modules.payloads import payload_pool_for_xss, XSS_TAG, XSS_ATTR_QUOTE_BALANCED, XSS_JS_STRING, XSS_URL, XSS_CSS
from backend.modules.ml.infer_ranker import rank_payloads
from backend.modules.fuzzer_core import _process_target
from backend.pipeline.workflow import assess_endpoints

class TestXSSContextPayloadSelection:
    """Test XSS context-aware payload selection."""
    
    def test_payload_pool_for_xss_html_body_raw(self):
        """Test html_body context with raw escaping returns tag-based payloads."""
        payloads = payload_pool_for_xss("html_body", "raw")
        
        assert len(payloads) <= 3
        assert all(payload in XSS_TAG for payload in payloads)
        assert "<svg onload=alert(1)>" in payloads
        assert "<img src=x onerror=alert(1)>" in payloads
    
    def test_payload_pool_for_xss_attr_html(self):
        """Test attr context with html escaping returns quote-balanced payloads."""
        payloads = payload_pool_for_xss("attr", "html")
        
        assert len(payloads) <= 3
        assert all(payload in XSS_ATTR_QUOTE_BALANCED for payload in payloads)
        assert "\" onmouseover=\"alert(1)\" x=\"" in payloads
        assert "' autofocus onfocus=alert(1) x='" in payloads
    
    def test_payload_pool_for_xss_js_string_raw(self):
        """Test js_string context with raw escaping returns JS string breakouts."""
        payloads = payload_pool_for_xss("js_string", "raw")
        
        assert len(payloads) <= 3
        assert all(payload in XSS_JS_STRING for payload in payloads)
        assert "\";alert(1);//" in payloads
        assert "';alert(1);//" in payloads
    
    def test_payload_pool_for_xss_url_raw(self):
        """Test url context with raw escaping returns javascript: URIs."""
        payloads = payload_pool_for_xss("url", "raw")
        
        assert len(payloads) <= 3
        assert all(payload in XSS_URL for payload in payloads)
        assert "javascript:alert(1)" in payloads
    
    def test_payload_pool_for_xss_css_raw(self):
        """Test css context with raw escaping returns CSS-specific payloads."""
        payloads = payload_pool_for_xss("css", "raw")
        
        assert len(payloads) <= 3
        assert any(payload in XSS_CSS for payload in payloads)
        assert "expression(alert(1))" in payloads
    
    def test_payload_pool_for_xss_unknown_context(self):
        """Test unknown context falls back to general XSS pool."""
        payloads = payload_pool_for_xss("unknown", "raw")
        
        assert len(payloads) <= 3
        # Should return general XSS payloads
        assert any(payload in XSS_TAG for payload in payloads)
    
    def test_payload_pool_for_xss_empty_context(self):
        """Test empty context falls back to general XSS pool."""
        payloads = payload_pool_for_xss("", "raw")
        
        assert len(payloads) <= 3
        assert any(payload in XSS_TAG for payload in payloads)
    
    def test_payload_pool_for_xss_attr_other_escaping(self):
        """Test attr context with non-html escaping falls back to general attr."""
        payloads = payload_pool_for_xss("attr", "js")
        
        assert len(payloads) <= 3
        # Should include some general attr payloads
        assert any("\" onmouseover=" in payload for payload in payloads)

class TestXSSContextRankerIntegration:
    """Test integration of context-aware payloads with ranker."""
    
    def test_rank_payloads_uses_context_aware_payloads(self):
        """Test that rank_payloads uses context-aware payloads for XSS."""
        features = {
            "url": "http://example.com/test",
            "method": "GET",
            "param_in": "query",
            "param": "q"
        }
        
        # Test with attr + html context
        ranked = rank_payloads("xss", features, top_k=3, xss_context="attr", xss_escaping="html")
        
        assert len(ranked) <= 3
        assert all(item["rank_source"] == "ctx_pool" for item in ranked)
        
        # Check that payloads are context-appropriate
        payloads = [item["payload"] for item in ranked]
        assert any("\" onmouseover=" in payload for payload in payloads)
        assert any("autofocus onfocus=" in payload for payload in payloads)
    
    def test_rank_payloads_fallback_without_context(self):
        """Test that rank_payloads falls back to defaults without XSS context."""
        features = {
            "url": "http://example.com/test",
            "method": "GET",
            "param_in": "query",
            "param": "q"
        }
        
        ranked = rank_payloads("xss", features, top_k=3)
        
        assert len(ranked) <= 3
        assert all(item["rank_source"] == "defaults" for item in ranked)
    
    def test_rank_payloads_js_string_context(self):
        """Test rank_payloads with js_string context."""
        features = {
            "url": "http://example.com/test",
            "method": "GET",
            "param_in": "query",
            "param": "q"
        }
        
        ranked = rank_payloads("xss", features, top_k=3, xss_context="js_string", xss_escaping="raw")
        
        assert len(ranked) <= 3
        assert all(item["rank_source"] == "ctx_pool" for item in ranked)
        
        # Check that payloads are JS string breakouts
        payloads = [item["payload"] for item in ranked]
        assert any("\";alert(1);//" in payload for payload in payloads)
        assert any("';alert(1);//" in payload for payload in payloads)

class TestXSSContextFuzzerIntegration:
    """Test integration of context-aware payloads with fuzzer."""
    
    def test_fuzzer_uses_context_aware_payloads(self):
        """Test that fuzzer uses context-aware payloads when XSS context is available."""
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
        
        # Create mock probe bundle with XSS context
        probe_bundle = MagicMock()
        probe_bundle.xss = MagicMock()
        probe_bundle.xss.xss_context = "attr"
        probe_bundle.xss.xss_escaping = "html"
        probe_bundle.sqli = MagicMock()
        probe_bundle.redirect = MagicMock()
        
        with patch('backend.modules.fuzzer_core.run_probes') as mock_run_probes:
            mock_run_probes.return_value = probe_bundle
            
            with patch('backend.modules.fuzzer_core._confirmed_family') as mock_confirmed:
                mock_confirmed.return_value = None  # No probe confirmation
                
                with patch('backend.modules.fuzzer_core.rank_payloads') as mock_rank:
                    # Mock rank_payloads to return context-aware results
                    mock_rank.return_value = [
                        {"payload": "\" onmouseover=\"alert(1)\" x=\"", "score": 0.8, "p_cal": 0.8, "rank_source": "ctx_pool", "model_tag": None},
                        {"payload": "' autofocus onfocus=alert(1) x='", "score": 0.7, "p_cal": 0.7, "rank_source": "ctx_pool", "model_tag": None}
                    ]
                    
                    with patch('backend.modules.fuzzer_core.inject_once') as mock_inject:
                        mock_inject.return_value = MagicMock(
                            status=200,
                            response_snippet="<input value=\"\" onmouseover=\"alert(1)\" x=\"\">",
                            why=["xss_reflection"]
                        )
                        
                        result = _process_target(target, "test-job", 3, MagicMock(), MagicMock())
                        
                        # Verify that rank_payloads was called with XSS context
                        mock_rank.assert_called_once()
                        call_args = mock_rank.call_args
                        assert call_args[1]["xss_context"] == "attr"
                        assert call_args[1]["xss_escaping"] == "html"

class TestXSSContextUpliftMetrics:
    """Test XSS context uplift metrics tracking."""
    
    def test_pipeline_tracks_context_pool_usage(self):
        """Test that pipeline tracks context pool usage in meta."""
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
            # Create mock probe bundle with XSS context
            probe_bundle = MagicMock()
            probe_bundle.xss = MagicMock()
            probe_bundle.xss.xss_context = "attr"
            probe_bundle.xss.xss_escaping = "html"
            probe_bundle.sqli = MagicMock()
            probe_bundle.redirect = MagicMock()
            
            mock_run_probes.return_value = probe_bundle
            
            with patch('backend.modules.fuzzer_core._confirmed_family') as mock_confirmed:
                mock_confirmed.return_value = None  # No probe confirmation
                
                with patch('backend.modules.fuzzer_core.rank_payloads') as mock_rank:
                    # Mock rank_payloads to return context-aware results
                    mock_rank.return_value = [
                        {"payload": "\" onmouseover=\"alert(1)\" x=\"", "score": 0.8, "p_cal": 0.8, "rank_source": "ctx_pool", "model_tag": None}
                    ]
                    
                    with patch('backend.modules.fuzzer_core.inject_once') as mock_inject:
                        mock_inject.return_value = MagicMock(
                            status=200,
                            response_snippet="<input value=\"\" onmouseover=\"alert(1)\" x=\"\">",
                            why=["xss_reflection"]
                        )
                        
                        result = assess_endpoints(endpoints, "test-job", top_k=3)
                        
                        # Check that meta includes context pool metrics
                        meta = result["meta"]
                        assert "xss_ctx_pool_used" in meta
                        assert "xss_first_hit_attempts_ctx" in meta
                        assert "xss_first_hit_attempts_baseline" in meta
                        assert "xss_first_hit_attempts_delta" in meta
                        
                        # Should have used context pool
                        assert meta["xss_ctx_pool_used"] >= 0

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
