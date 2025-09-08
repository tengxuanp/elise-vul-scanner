"""
Tests for telemetry defaults in probe-only results.

Tests that probe-only result rows include proper telemetry defaults
and that evidence includes these fields.
"""

import pytest
from unittest.mock import patch, MagicMock

from backend.modules.fuzzer_core import _ensure_telemetry_defaults, DECISION
from backend.modules.evidence import EvidenceRow
from backend.pipeline.workflow import assess_endpoints

class TestTelemetryDefaults:
    """Test telemetry defaults in results and evidence."""
    
    def test_ensure_telemetry_defaults_sets_probe_only_rank_source(self):
        """Test that _ensure_telemetry_defaults sets rank_source to probe_only for probe results."""
        result = {
            "decision": DECISION["POS"],
            "why": ["probe_proof"]
        }
        
        updated_result = _ensure_telemetry_defaults(result)
        
        assert updated_result["attempt_idx"] == 0
        assert updated_result["top_k_used"] == 0
        assert updated_result["rank_source"] == "probe_only"
    
    def test_ensure_telemetry_defaults_sets_none_rank_source(self):
        """Test that _ensure_telemetry_defaults sets rank_source to none for non-probe results."""
        result = {
            "decision": DECISION["NA"],
            "why": ["gate_not_applicable"]
        }
        
        updated_result = _ensure_telemetry_defaults(result)
        
        assert updated_result["attempt_idx"] == 0
        assert updated_result["top_k_used"] == 0
        assert updated_result["rank_source"] == "none"
    
    def test_ensure_telemetry_defaults_preserves_existing_values(self):
        """Test that _ensure_telemetry_defaults preserves existing telemetry values."""
        result = {
            "decision": DECISION["POS"],
            "why": ["ml_ranked"],
            "attempt_idx": 2,
            "top_k_used": 3,
            "rank_source": "ml"
        }
        
        updated_result = _ensure_telemetry_defaults(result)
        
        assert updated_result["attempt_idx"] == 2
        assert updated_result["top_k_used"] == 3
        assert updated_result["rank_source"] == "ml"
    
    def test_evidence_row_includes_telemetry_defaults(self):
        """Test that EvidenceRow includes telemetry defaults."""
        # Create a mock target
        target = MagicMock()
        target.url = "http://example.com/test"
        target.method = "GET"
        target.param_in = "query"
        target.param = "q"
        target.headers = {}
        
        # Create a mock probe bundle
        probe_bundle = MagicMock()
        probe_bundle.xss = MagicMock()
        probe_bundle.sqli = MagicMock()
        probe_bundle.redirect = MagicMock()
        
        # Create evidence row
        ev = EvidenceRow.from_probe_confirm(target, "xss", probe_bundle)
        
        # Check telemetry defaults
        assert ev.attempt_idx == 0
        assert ev.top_k_used == 0
        assert ev.rank_source == "probe_only"
    
    def test_evidence_to_dict_includes_telemetry_defaults(self):
        """Test that EvidenceRow.to_dict() includes telemetry defaults."""
        # Create a mock target
        target = MagicMock()
        target.url = "http://example.com/test"
        target.method = "GET"
        target.param_in = "query"
        target.param = "q"
        target.headers = {}
        
        # Create a mock probe bundle
        probe_bundle = MagicMock()
        probe_bundle.xss = MagicMock()
        probe_bundle.sqli = MagicMock()
        probe_bundle.redirect = MagicMock()
        
        # Create evidence row
        ev = EvidenceRow.from_probe_confirm(target, "xss", probe_bundle)
        
        # Convert to dict
        ev_dict = ev.to_dict("test-evidence-123")
        
        # Check telemetry defaults are included
        assert ev_dict["attempt_idx"] == 0
        assert ev_dict["top_k_used"] == 0
        assert ev_dict["rank_source"] == "probe_only"
        assert ev_dict["evidence_id"] == "test-evidence-123"
    
    def test_evidence_to_dict_handles_missing_telemetry(self):
        """Test that EvidenceRow.to_dict() handles missing telemetry fields."""
        # Create evidence row without telemetry fields
        ev = EvidenceRow(
            family="xss",
            url="http://example.com/test",
            method="GET",
            param_in="query",
            param="q",
            payload="<script>alert(1)</script>",
            request_headers={},
            response_status=200,
            response_snippet="<script>alert(1)</script>",
            probe_signals={},
            why=["probe_proof"]
        )
        
        # Convert to dict
        ev_dict = ev.to_dict("test-evidence-456")
        
        # Check telemetry defaults are set
        assert ev_dict["attempt_idx"] == 0
        assert ev_dict["top_k_used"] == 0
        assert ev_dict["rank_source"] == "probe_only"  # Because "probe" is in why
    
    def test_assess_endpoints_includes_telemetry_in_results(self):
        """Test that assess_endpoints includes telemetry defaults in final results."""
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
                
                # Check that results include telemetry defaults
                assert len(result["results"]) > 0
                xss_result = next(r for r in result["results"] if r["family"] == "xss")
                assert xss_result["attempt_idx"] == 0
                assert xss_result["top_k_used"] == 0
                assert xss_result["rank_source"] == "probe_only"
    
    def test_counters_consistent_flag_in_meta(self):
        """Test that counters_consistent flag is computed correctly."""
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
                
                # Check that counters_consistent flag is present
                meta = result["meta"]
                assert "counters_consistent" in meta
                assert isinstance(meta["counters_consistent"], bool)

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
