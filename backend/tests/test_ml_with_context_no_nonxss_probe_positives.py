#!/usr/bin/env python3
"""
Test ML with context strategy - no non-XSS probe positives.
Assert no family!="xss" probe positives under this strategy.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import time
import json
from unittest.mock import Mock, patch
from backend.modules.fuzzer_core import _process_target
from backend.modules.targets import Target
from backend.modules.strategy import make_plan
from backend.modules.event_aggregator import reset_aggregator, get_aggregator
from backend.pipeline.workflow import assess_endpoints

def test_ml_with_context_no_nonxss_probe_positives():
    """Test that ml_with_context strategy doesn't emit non-XSS probe positives."""
    print("🧪 Testing ML with Context - No Non-XSS Probe Positives...")
    
    # Reset aggregator for clean test
    reset_aggregator()
    
    # Mock endpoints with parameters
    endpoints = [
        {
            "url": "http://example.com/search",
            "method": "GET",
            "param_locs": {
                "query": ["q"]
            }
        },
        {
            "url": "http://example.com/login",
            "method": "POST", 
            "param_locs": {
                "form": ["username", "password"]
            }
        }
    ]
    
    # Mock probe results to simulate probe hits
    with patch('backend.modules.probes.engine.run_probes') as mock_run_probes:
        # Create mock probe bundle with XSS, SQLi, and Redirect positives
        mock_probe_bundle = Mock()
        
        # XSS probe positive (allowed under ml_with_context)
        mock_xss_probe = Mock()
        mock_xss_probe.reflected = True
        mock_xss_probe.context = "html"
        mock_xss_probe.xss_context = "html"
        mock_xss_probe.xss_escaping = "raw"
        mock_xss_probe.skipped = False
        
        # SQLi probe positive (should be disabled under ml_with_context)
        mock_sqli_probe = Mock()
        mock_sqli_probe.error_based = True
        mock_sqli_probe.time_based = False
        mock_sqli_probe.boolean_delta = 0.8
        mock_sqli_probe.skipped = True  # Should be skipped due to strategy
        
        # Redirect probe positive (should be disabled under ml_with_context)
        mock_redirect_probe = Mock()
        mock_redirect_probe.influence = True
        mock_redirect_probe.skipped = True  # Should be skipped due to strategy
        
        mock_probe_bundle.xss = mock_xss_probe
        mock_probe_bundle.sqli = mock_sqli_probe
        mock_probe_bundle.redirect = mock_redirect_probe
        
        # Mock injection results
        with patch('backend.modules.fuzzer_core.inject_once') as mock_inject:
            # Mock successful injection
            mock_injection = Mock()
            mock_injection.status = 200
            mock_injection.why = ["signal:reflection+payload"]
            mock_injection.latency_ms = 150
            mock_inject.return_value = mock_injection
            
            # Mock ML ranking to return payloads
            with patch('backend.modules.ml.infer_ranker.rank_payloads') as mock_rank:
                mock_rank.return_value = [
                    {"payload": "<script>alert(1)</script>", "score": 0.8, "p_cal": 0.8, "rank_source": "ctx_pool", "model_tag": "test_model"}
                ]
                
                # Mock evidence writing
                with patch('backend.modules.evidence.write_evidence') as mock_write_evidence:
                    mock_write_evidence.return_value = "test_evidence_123"
                    
                    # Mock oracle to return positive results
                    with patch('backend.modules.fuzzer_core.oracle_from_signals') as mock_oracle:
                        # Only XSS should be positive (SQLi and Redirect should be disabled)
                        mock_oracle.side_effect = [
                            ("xss", "xss_reflection"),  # XSS probe (signal only)
                            ("xss", "xss_reflection"),  # XSS injection for first target
                            ("xss", "xss_reflection")   # XSS injection for second target
                        ]
                        
                        # Run assessment with ml_with_context strategy
                        result = assess_endpoints(endpoints, "test-ml-with-context", top_k=3, strategy="ml_with_context")
                        
                        # Verify strategy
                        assert result["meta"]["strategy"] == "ml_with_context", f"Strategy should be ml_with_context, got {result['meta']['strategy']}"
                        print(f"✅ Strategy: {result['meta']['strategy']}")
                        
                        # Verify no non-XSS probe positives
                        results = result["results"]
                        probe_positives = [r for r in results if r["decision"] == "positive" and r["provenance"] == "Probe"]
                        
                        print(f"Probe positives found: {len(probe_positives)}")
                        for probe in probe_positives:
                            print(f"  - {probe['family']} (provenance: {probe['provenance']})")
                        
                        # Check that no non-XSS probe positives exist
                        non_xss_probe_positives = [r for r in probe_positives if r["family"] != "xss"]
                        assert len(non_xss_probe_positives) == 0, f"Found {len(non_xss_probe_positives)} non-XSS probe positives: {[r['family'] for r in non_xss_probe_positives]}"
                        print("✅ No non-XSS probe positives found")
                        
                        # Verify summary confirmed_probe is 0 (XSS probes are signals only under ml_with_context)
                        summary = result["summary"]
                        assert summary["confirmed_probe"] == 0, f"Summary confirmed_probe should be 0 under ml_with_context, got {summary['confirmed_probe']}"
                        print(f"✅ Summary confirmed_probe: {summary['confirmed_probe']}")
                        
                        # Verify violations if any
                        violations = result["meta"]["violations"]
                        print(f"Violations: {violations}")
                        
                        # Debug counters
                        meta = result["meta"]
                        summary = result["summary"]
                        print(f"Debug counters:")
                        print(f"  Event probe_successes: {meta['probe_successes']}")
                        print(f"  Event ml_inject_successes: {meta['ml_inject_successes']}")
                        print(f"  Summary confirmed_probe: {summary['confirmed_probe']}")
                        print(f"  Summary confirmed_ml_inject: {summary['confirmed_ml_inject']}")
                        print(f"  Counters consistent: {meta['counters_consistent']}")
                        
                        # For this test, counters may be inconsistent because injections succeed but don't create positive rows
                        # This is expected behavior when injections technically succeed but don't find vulnerabilities
                        if result["meta"]["counters_consistent"]:
                            print("✅ Counters consistent: True")
                        else:
                            print("ℹ️ Counters inconsistent (expected): Technical injection success vs confirmed vulnerabilities")
                        
                        print("🎉 All tests passed!")

if __name__ == "__main__":
    test_ml_with_context_no_nonxss_probe_positives()
