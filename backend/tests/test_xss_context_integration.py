"""
Tests for XSS Context Classifier Integration

Tests that XSS context fields are properly surfaced in results and evidence,
and that the UI displays them correctly.
"""

import pytest
import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

from backend.modules.evidence import EvidenceRow, write_evidence, read_evidence
from backend.modules.probes.xss_canary import XssProbe, run_xss_probe
from backend.pipeline.workflow import assess_endpoints
from backend.app_state import DATA_DIR

class TestXSSContextIntegration:
    """Test XSS context integration end-to-end."""
    
    def test_xss_probe_returns_context_fields(self):
        """Test that XSS probe returns all required context fields."""
        # Mock HTTP response with XSS reflection
        with patch('backend.modules.probes.xss_canary.httpx.request') as mock_request:
            mock_response = MagicMock()
            mock_response.text = '<script>var x = "EliseXSSCanary123";</script>'
            mock_request.return_value = mock_response
            
            result = run_xss_probe(
                "http://example.com/test", "GET", "query", "q",
                headers=None, job_id="test-job"
            )
            
            assert result.reflected == True
            assert result.xss_context == "js_string"
            assert result.xss_escaping == "raw"
            assert result.xss_context_rule is not None
            assert result.xss_context_rule["pred"] == "js_string"
            assert result.xss_context_rule["conf"] >= 0.9
            assert result.fragment_left_64 == '<script>var x = "'
            assert result.fragment_right_64 == '";</script>'
            assert result.raw_reflection == "EliseXSSCanary123"
            assert result.in_script_tag == True
            assert result.in_attr == False
            assert result.attr_name == ""
            assert result.in_style == False
            assert result.attr_quote == ""
    
    def test_evidence_row_includes_xss_context_fields(self):
        """Test that EvidenceRow includes XSS context fields."""
        # Create a mock probe bundle with XSS probe
        probe_bundle = MagicMock()
        probe_bundle.xss = XssProbe(
            context="html",
            reflected=True,
            xss_context="js_string",
            xss_escaping="raw",
            xss_context_rule={"pred": "js_string", "conf": 0.95},
            xss_context_ml=None,
            xss_escaping_ml=None,
            fragment_left_64='<script>var x = "',
            fragment_right_64='";</script>',
            raw_reflection="EliseXSSCanary123",
            in_script_tag=True,
            in_attr=False,
            attr_name="",
            in_style=False,
            attr_quote="",
            content_type="text/html"
        )
        
        # Create a mock target
        target = MagicMock()
        target.url = "http://example.com/test"
        target.method = "GET"
        target.param_in = "query"
        target.param = "q"
        target.headers = {}
        
        # Create evidence row
        ev = EvidenceRow.from_probe_confirm(target, "xss", probe_bundle)
        
        assert ev.xss_context == "js_string"
        assert ev.xss_escaping == "raw"
        assert ev.xss_context_source == "rule"
        assert ev.xss_context_ml_proba is None
    
    def test_evidence_row_with_ml_context(self):
        """Test that EvidenceRow includes ML context fields when ML is used."""
        # Create a mock probe bundle with XSS probe using ML
        probe_bundle = MagicMock()
        probe_bundle.xss = XssProbe(
            context="html",
            reflected=True,
            xss_context="html_body",
            xss_escaping="raw",
            xss_context_rule={"pred": "unknown", "conf": 0.3},
            xss_context_ml={"pred": "html_body", "proba": 0.85},
            xss_escaping_ml={"pred": "raw", "proba": 0.90},
            fragment_left_64='<div>',
            fragment_right_64='</div>',
            raw_reflection="EliseXSSCanary123",
            in_script_tag=False,
            in_attr=False,
            attr_name="",
            in_style=False,
            attr_quote="",
            content_type="text/html"
        )
        
        # Create a mock target
        target = MagicMock()
        target.url = "http://example.com/test"
        target.method = "GET"
        target.param_in = "query"
        target.param = "q"
        target.headers = {}
        
        # Create evidence row
        ev = EvidenceRow.from_probe_confirm(target, "xss", probe_bundle)
        
        assert ev.xss_context == "html_body"
        assert ev.xss_escaping == "raw"
        assert ev.xss_context_source == "ml"
        assert ev.xss_context_ml_proba == 0.85
    
    def test_evidence_file_includes_detailed_context_data(self):
        """Test that evidence file includes detailed XSS context data."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Mock DATA_DIR
            with patch('backend.modules.evidence.DATA_DIR', Path(temp_dir)):
                # Create a mock probe bundle with XSS probe
                probe_bundle = MagicMock()
                probe_bundle.xss = XssProbe(
                    context="html",
                    reflected=True,
                    xss_context="attr",
                    xss_escaping="html",
                    xss_context_rule={"pred": "attr", "conf": 0.8},
                    xss_context_ml=None,
                    xss_escaping_ml=None,
                    fragment_left_64='<input value="',
                    fragment_right_64='">',
                    raw_reflection="&lt;EliseXSSCanary123&gt;",
                    in_script_tag=False,
                    in_attr=True,
                    attr_name="value",
                    in_style=False,
                    attr_quote='"',
                    content_type="text/html"
                )
                
                # Create a mock target
                target = MagicMock()
                target.url = "http://example.com/test"
                target.method = "GET"
                target.param_in = "query"
                target.param = "q"
                target.headers = {"content-type": "text/html"}
                
                # Create evidence row
                ev = EvidenceRow.from_probe_confirm(target, "xss", probe_bundle)
                
                # Write evidence
                evidence_id = write_evidence("test-job", ev, probe_bundle)
                
                # Read evidence back
                evidence_data = read_evidence("test-job", evidence_id)
                
                # Check basic XSS context fields
                assert evidence_data["xss_context"] == "attr"
                assert evidence_data["xss_escaping"] == "html"
                assert evidence_data["xss_context_source"] == "rule"
                assert evidence_data["xss_context_ml_proba"] is None
                
                # Check detailed XSS context data
                assert "xss_context_details" in evidence_data
                details = evidence_data["xss_context_details"]
                assert details["fragment_left_64"] == '<input value="'
                assert details["fragment_right_64"] == '">'
                assert details["raw_reflection"] == "&lt;EliseXSSCanary123&gt;"
                assert details["in_script_tag"] == False
                assert details["in_attr"] == True
                assert details["attr_name"] == "value"
                assert details["in_style"] == False
                assert details["attr_quote"] == '"'
                assert details["content_type"] == "text/html"
                assert details["xss_context_rule"]["pred"] == "attr"
                assert details["xss_context_rule"]["conf"] == 0.8
    
    def test_pipeline_includes_xss_context_in_results(self):
        """Test that pipeline includes XSS context fields in results."""
        # Mock endpoints with XSS reflection
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
        
        # Mock the XSS probe to return a reflection
        with patch('backend.modules.fuzzer_core.run_probes') as mock_run_probes:
            # Create mock probe bundle
            probe_bundle = MagicMock()
            probe_bundle.xss = XssProbe(
                context="html",
                reflected=True,
                xss_context="js_string",
                xss_escaping="raw",
                xss_context_rule={"pred": "js_string", "conf": 0.95},
                xss_context_ml=None,
                xss_escaping_ml=None,
                fragment_left_64='<script>var x = "',
                fragment_right_64='";</script>',
                raw_reflection="EliseXSSCanary123",
                in_script_tag=True,
                in_attr=False,
                attr_name="",
                in_style=False,
                attr_quote="",
                content_type="text/html"
            )
            probe_bundle.sqli = MagicMock()
            probe_bundle.redirect = MagicMock()
            
            # Mock probe confirmation
            mock_run_probes.return_value = probe_bundle
            
            with patch('backend.modules.fuzzer_core._confirmed_family') as mock_confirmed:
                mock_confirmed.return_value = ("xss", "xss_reflection")
                
                # Run assessment
                result = assess_endpoints(endpoints, "test-job", top_k=3)
                
                # Check that results include XSS context fields
                assert len(result["results"]) > 0
                xss_result = None
                for r in result["results"]:
                    if r.get("family") == "xss":
                        xss_result = r
                        break
                
                assert xss_result is not None
                assert xss_result["xss_context"] == "js_string"
                assert xss_result["xss_escaping"] == "raw"
                assert xss_result["xss_context_source"] == "rule"
                assert xss_result["xss_context_ml_proba"] is None
    
    def test_pipeline_includes_xss_context_counters_in_meta(self):
        """Test that pipeline includes XSS context counters in meta."""
        # Mock endpoints with XSS reflection
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
        
        # Mock the XSS probe to return a reflection
        with patch('backend.modules.fuzzer_core.run_probes') as mock_run_probes:
            # Create mock probe bundle
            probe_bundle = MagicMock()
            probe_bundle.xss = XssProbe(
                context="html",
                reflected=True,
                xss_context="js_string",
                xss_escaping="raw",
                xss_context_rule={"pred": "js_string", "conf": 0.95},
                xss_context_ml=None,
                xss_escaping_ml=None,
                fragment_left_64='<script>var x = "',
                fragment_right_64='";</script>',
                raw_reflection="EliseXSSCanary123",
                in_script_tag=True,
                in_attr=False,
                attr_name="",
                in_style=False,
                attr_quote="",
                content_type="text/html"
            )
            probe_bundle.sqli = MagicMock()
            probe_bundle.redirect = MagicMock()
            
            # Mock probe confirmation
            mock_run_probes.return_value = probe_bundle
            
            with patch('backend.modules.fuzzer_core._confirmed_family') as mock_confirmed:
                mock_confirmed.return_value = ("xss", "xss_reflection")
                
                # Run assessment
                result = assess_endpoints(endpoints, "test-job", top_k=3)
                
                # Check that meta includes XSS context counters
                meta = result["meta"]
                assert "xss_reflections_total" in meta
                assert "xss_rule_high_conf" in meta
                assert "xss_ml_invoked" in meta
                assert "xss_final_from_ml" in meta
                assert "xss_context_dist" in meta
                
                assert meta["xss_reflections_total"] >= 1
                assert meta["xss_rule_high_conf"] >= 1
                assert meta["xss_ml_invoked"] >= 0
                assert meta["xss_final_from_ml"] >= 0
                assert "js_string" in meta["xss_context_dist"]
                assert meta["xss_context_dist"]["js_string"] >= 1

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
