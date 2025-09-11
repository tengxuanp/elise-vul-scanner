"""
Test that probe engine scopes signals by family.
"""
import pytest
from unittest.mock import Mock, patch
from backend.modules.probes.engine import run_probes, PROBES
from backend.modules.targets import Target

def test_probe_engine_scopes_signals():
    """Test that probe engine only runs probes for specified families."""
    
    # Create a mock target
    target = Target(
        url="http://example.com/test",
        method="GET",
        param_in="query",
        param="test",
        headers={}
    )
    
    # Test XSS-only families
    with patch('backend.modules.probes.engine.run_xss_probe') as mock_xss, \
         patch('backend.modules.probes.engine.run_sqli_probe') as mock_sqli, \
         patch('backend.modules.probes.engine.run_redirect_probe') as mock_redirect:
        
        # Mock probe results
        mock_xss.return_value = Mock(reflected=True, context="html")
        mock_sqli.return_value = Mock(error_based=False, time_based=False, boolean_delta=0)
        mock_redirect.return_value = Mock(influence=False)
        
        # Run probes for XSS only
        bundle = run_probes(target, families=["xss"])
        
        # XSS probe should be called
        mock_xss.assert_called_once()
        # SQLi and redirect probes should not be called
        mock_sqli.assert_not_called()
        mock_redirect.assert_not_called()
        
        # Bundle should have XSS probe result
        assert bundle.xss is not None
        assert bundle.xss.reflected is True
        assert bundle.xss.context == "html"
    
    # Test SQLi-only families
    with patch('backend.modules.probes.engine.run_xss_probe') as mock_xss, \
         patch('backend.modules.probes.engine.run_sqli_probe') as mock_sqli, \
         patch('backend.modules.probes.engine.run_redirect_probe') as mock_redirect:
        
        # Mock probe results
        mock_xss.return_value = Mock(reflected=False, context=None)
        mock_sqli.return_value = Mock(error_based=True, time_based=False, boolean_delta=0.5)
        mock_redirect.return_value = Mock(influence=False)
        
        # Run probes for SQLi only
        bundle = run_probes(target, families=["sqli"])
        
        # SQLi probe should be called
        mock_sqli.assert_called_once()
        # XSS and redirect probes should not be called
        mock_xss.assert_not_called()
        mock_redirect.assert_not_called()
        
        # Bundle should have SQLi probe result
        assert bundle.sqli is not None
        assert bundle.sqli.error_based is True
        assert bundle.sqli.boolean_delta == 0.5

def test_probe_registry_family_scoping():
    """Test that probe registry is properly scoped by family."""
    
    # Check that PROBES registry has family-scoped entries
    assert "xss" in PROBES
    assert "sqli" in PROBES
    assert "redirect" in PROBES
    
    # Check that each family has appropriate probe types
    assert "canary" in PROBES["xss"]
    assert "triage" in PROBES["sqli"]
    assert "oracle" in PROBES["redirect"]
    
    # Check that probe functions are callable
    assert callable(PROBES["xss"]["canary"])
    assert callable(PROBES["sqli"]["triage"])
    assert callable(PROBES["redirect"]["oracle"])

def test_no_xss_canary_for_sqli():
    """Test that XSS canary is not generated for SQLi families."""
    
    target = Target(
        url="http://example.com/test",
        method="GET",
        param_in="query",
        param="test",
        headers={}
    )
    
    # Run probes for SQLi only (no XSS)
    bundle = run_probes(target, families=["sqli"])
    
    # XSS probe should be mocked (not real XSS probe)
    assert bundle.xss is not None
    # XSS context should be None for SQLi-only runs
    assert bundle.xss.xss_context is None
    assert bundle.xss.xss_escaping is None
    assert bundle.xss.xss_context_final is None
    assert bundle.xss.xss_context_source_detailed is None
    assert bundle.xss.xss_ml_proba is None
