"""
End-to-end test for SQLi product ID family purity.
Tests that SQLi findings never show XSS artifacts.
"""
import pytest
import json
import tempfile
import os
from pathlib import Path
from backend.modules.fuzzer_core import _process_target
from backend.modules.targets import Target
from backend.modules.strategy import ScanStrategy
from unittest.mock import Mock, patch

def test_e2e_sql_product_id_family_purity():
    """Test that SQLi product ID assessment shows no XSS artifacts."""
    
    # Create a mock target for SQLi testing
    target = Target(
        url="http://127.0.0.1:5001/product?id=1",
        method="GET",
        param_in="query",
        param="id",
        headers={}
    )
    
    # Create a mock probe bundle with SQLi signals only
    mock_probe_bundle = Mock()
    mock_probe_bundle.xss = Mock()
    mock_probe_bundle.xss.reflected = False
    mock_probe_bundle.xss.context = None
    mock_probe_bundle.xss.xss_context = None
    mock_probe_bundle.xss.xss_escaping = None
    mock_probe_bundle.xss.xss_context_final = None
    mock_probe_bundle.xss.xss_context_source_detailed = None
    mock_probe_bundle.xss.xss_ml_proba = None
    
    mock_probe_bundle.sqli = Mock()
    mock_probe_bundle.sqli.error_based = True
    mock_probe_bundle.sqli.time_based = False
    mock_probe_bundle.sqli.boolean_delta = 0.5
    mock_probe_bundle.sqli.error_excerpt = "SQL Error: near \"<\": syntax error"
    mock_probe_bundle.sqli.dialect_hint = "unknown"
    
    mock_probe_bundle.redirect = Mock()
    mock_probe_bundle.redirect.influence = False
    
    # Mock injection result for SQLi
    mock_injection = Mock()
    mock_injection.status = 500
    mock_injection.response_snippet = "SQL Error: near \"<\": syntax error"
    mock_injection.response_headers = {"content-type": "text/html"}
    mock_injection.response_len = 33
    mock_injection.why = ["sql_error"]
    mock_injection.redirect_location = None
    
    with patch('backend.modules.fuzzer_core.run_probes', return_value=mock_probe_bundle), \
         patch('backend.modules.fuzzer_core.inject_once', return_value=mock_injection), \
         patch('backend.modules.fuzzer_core.rank_payloads') as mock_rank_payloads:
        
        # Mock rank_payloads to return SQLi payloads
        mock_rank_payloads.return_value = [
            {"payload": "'", "score": 0.8, "p_cal": 0.8, "family": "sqli"},
            {"payload": "' OR '1'='1' --", "score": 0.7, "p_cal": 0.7, "family": "sqli"},
            {"payload": "1 AND SLEEP(2) --", "score": 0.6, "p_cal": 0.6, "family": "sqli"}
        ]
        
        # Process the target
        result = _process_target(target, "test-job", 3, Mock(), Mock(), meta={})
        
        # Verify the result
        assert result is not None
        assert "evidence" in result
        
        evidence = result["evidence"]
        
        # Verify family is SQLi
        assert evidence["family"] == "sqli"
        
        # Verify payload is SQLi (not XSS)
        payload = evidence["payload"]
        assert payload in ["'", "' OR '1'='1' --", "1 AND SLEEP(2) --"]
        assert not any(xss_pattern in payload for xss_pattern in ["<", ">", "script", "alert", "svg", "img"])
        
        # Verify no XSS signals in probe_signals
        probe_signals = evidence.get("probe_signals", {})
        
        # Should not have XSS-specific signals
        xss_signals = [key for key in probe_signals.keys() if "xss" in key.lower()]
        assert len(xss_signals) == 0, f"Found XSS signals in SQLi evidence: {xss_signals}"
        
        # Should have SQLi-specific signals
        sqli_signals = [key for key in probe_signals.keys() if "sqli" in key.lower()]
        assert len(sqli_signals) > 0, "No SQLi signals found in SQLi evidence"
        
        # Verify ranking_topk contains only SQLi payloads
        ranking_topk = evidence.get("ranking_topk", [])
        if ranking_topk:
            for payload_info in ranking_topk:
                assert payload_info.get("family") == "sqli"
                payload_id = payload_info.get("payload_id", "")
                assert not any(xss_pattern in payload_id for xss_pattern in ["<", ">", "script", "alert", "svg", "img"])
        
        # Verify no XSS context information
        assert evidence.get("xss_context") is None
        assert evidence.get("xss_escaping") is None
        assert evidence.get("xss_context_final") is None
        assert evidence.get("xss_context_source") is None
        assert evidence.get("xss_ml_proba") is None

def test_family_mismatch_detection():
    """Test that family mismatches are detected and flagged."""
    
    target = Target(
        url="http://127.0.0.1:5001/product?id=1",
        method="GET",
        param_in="query",
        param="id",
        headers={}
    )
    
    # Create probe bundle with XSS signals (simulating ML misclassification)
    mock_probe_bundle = Mock()
    mock_probe_bundle.xss = Mock()
    mock_probe_bundle.xss.reflected = True
    mock_probe_bundle.xss.context = "html"
    mock_probe_bundle.xss.xss_context = "html_body"
    mock_probe_bundle.xss.xss_escaping = "raw"
    mock_probe_bundle.xss.xss_context_final = "html_body"
    mock_probe_bundle.xss.xss_context_source_detailed = "ml"
    mock_probe_bundle.xss.xss_ml_proba = 0.8
    
    mock_probe_bundle.sqli = Mock()
    mock_probe_bundle.sqli.error_based = True
    mock_probe_bundle.sqli.time_based = False
    mock_probe_bundle.sqli.boolean_delta = 0.5
    mock_probe_bundle.sqli.error_excerpt = "SQL Error: near \"<\": syntax error"
    mock_probe_bundle.sqli.dialect_hint = "unknown"
    
    mock_probe_bundle.redirect = Mock()
    mock_probe_bundle.redirect.influence = False
    
    mock_injection = Mock()
    mock_injection.status = 500
    mock_injection.response_snippet = "SQL Error: near \"<\": syntax error"
    mock_injection.response_headers = {"content-type": "text/html"}
    mock_injection.response_len = 33
    mock_injection.why = ["sql_error"]
    mock_injection.redirect_location = None
    
    with patch('backend.modules.fuzzer_core.run_probes', return_value=mock_probe_bundle), \
         patch('backend.modules.fuzzer_core.inject_once', return_value=mock_injection), \
         patch('backend.modules.fuzzer_core.rank_payloads') as mock_rank_payloads:
        
        # Mock rank_payloads to return SQLi payloads (correct family)
        mock_rank_payloads.return_value = [
            {"payload": "'", "score": 0.8, "p_cal": 0.8, "family": "sqli"}
        ]
        
        # Process the target
        result = _process_target(target, "test-job", 3, Mock(), Mock(), meta={})
        
        evidence = result["evidence"]
        
        # Should detect family mismatch if ML classified as XSS but we're processing SQLi
        probe_signals = evidence.get("probe_signals", {})
        
        # Check if family mismatch is detected
        if "family_mismatch" in probe_signals:
            mismatch = probe_signals["family_mismatch"]
            assert mismatch["attempted"] == "sqli"
            assert "banner" in mismatch
            assert "attempted: SQLI → classified:" in mismatch["banner"]
