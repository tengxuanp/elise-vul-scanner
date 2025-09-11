"""
Test that ranker defaults respect family boundaries.
"""
import pytest
from backend.modules.ml.infer_ranker import rank_payloads

def test_ranker_defaults_respect_family():
    """Test that rank_payloads returns only payloads for the specified family."""
    
    # Test XSS family
    xss_results = rank_payloads("xss", {}, top_k=5)
    assert len(xss_results) > 0
    for result in xss_results:
        assert result["family"] == "xss"
        # XSS payloads should contain typical XSS patterns
        payload = result["payload"]
        assert any(pattern in payload for pattern in ["<", ">", "script", "alert", "svg", "img"])
    
    # Test SQLi family
    sqli_results = rank_payloads("sqli", {}, top_k=5)
    assert len(sqli_results) > 0
    for result in sqli_results:
        assert result["family"] == "sqli"
        # SQLi payloads should contain typical SQLi patterns
        payload = result["payload"]
        assert any(pattern in payload for pattern in ["'", "OR", "AND", "UNION", "SELECT", "--"])
    
    # Test redirect family
    redirect_results = rank_payloads("redirect", {}, top_k=5)
    assert len(redirect_results) > 0
    for result in redirect_results:
        assert result["family"] == "redirect"
        # Redirect payloads should contain URLs
        payload = result["payload"]
        assert any(pattern in payload for pattern in ["http", "https", "//", "/"])
    
    # Test that families don't cross-contaminate
    all_xss_payloads = [r["payload"] for r in xss_results]
    all_sqli_payloads = [r["payload"] for r in sqli_results]
    all_redirect_payloads = [r["payload"] for r in redirect_results]
    
    # No XSS-specific patterns should appear in SQLi results
    xss_patterns = ["<script", "<svg", "<img", "onload=", "onerror=", "alert("]
    for sqli_payload in all_sqli_payloads:
        assert not any(pattern in sqli_payload for pattern in xss_patterns)
    
    # No SQLi-specific patterns should appear in XSS results
    sqli_patterns = ["' OR", "' AND", "UNION SELECT", "SLEEP(", "WAITFOR"]
    for xss_payload in all_xss_payloads:
        assert not any(pattern in xss_payload for pattern in sqli_patterns)

def test_ranker_unknown_family_fallback():
    """Test that rank_payloads handles unknown families gracefully."""
    
    # Test unknown family
    unknown_results = rank_payloads("unknown", {}, top_k=3)
    # Should return empty list or fallback gracefully
    assert isinstance(unknown_results, list)
    
    # Test empty family
    empty_results = rank_payloads("", {}, top_k=3)
    assert isinstance(empty_results, list)
