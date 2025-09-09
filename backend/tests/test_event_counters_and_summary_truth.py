#!/usr/bin/env python3
"""
Test event counters and summary truth.
Simulate 2 probe hits + 1 inject hit; assert counters, summary, counters_consistent and processing time > 0.0.
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

def test_event_counters_and_summary_truth():
    """Test that event counters and summary are truthful."""
    print("🧪 Testing Event Counters and Summary Truth...")
    
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
        },
        {
            "url": "http://example.com/api",
            "method": "POST",
            "param_locs": {
                "json": ["data"]
            }
        }
    ]
    
    # Mock probe results to simulate 2 probe hits
    with patch('backend.modules.probes.engine.run_probes') as mock_run_probes:
        # Create mock probe bundle with XSS and SQLi positives
        mock_probe_bundle = Mock()
        
        # XSS probe positive
        mock_xss_probe = Mock()
        mock_xss_probe.reflected = True
        mock_xss_probe.context = "html"
        mock_xss_probe.xss_context = "html"
        mock_xss_probe.xss_escaping = "raw"
        mock_xss_probe.skipped = False
        
        # SQLi probe positive  
        mock_sqli_probe = Mock()
        mock_sqli_probe.error_based = True
        mock_sqli_probe.time_based = False
        mock_sqli_probe.boolean_delta = 0.8
        mock_sqli_probe.skipped = False
        
        # Redirect probe negative
        mock_redirect_probe = Mock()
        mock_redirect_probe.influence = False
        mock_redirect_probe.skipped = False
        
        mock_probe_bundle.xss = mock_xss_probe
        mock_probe_bundle.sqli = mock_sqli_probe
        mock_probe_bundle.redirect = mock_redirect_probe
        
        # Mock injection results to simulate 1 inject hit
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
                    {"payload": "<script>alert(1)</script>", "score": 0.8, "p_cal": 0.8, "rank_source": "ml", "model_tag": "test_model"}
                ]
                
                # Mock evidence writing
                with patch('backend.modules.evidence.write_evidence') as mock_write_evidence:
                    mock_write_evidence.return_value = "test_evidence_123"
                    
                    # Mock oracle to return positive results
                    with patch('backend.modules.fuzzer_core.oracle_from_signals') as mock_oracle:
                        # First call: XSS probe positive
                        # Second call: SQLi probe positive  
                        # Third call: XSS injection positive
                        mock_oracle.side_effect = [
                            ("xss", "xss_reflection"),
                            ("sqli", "sql_error"),
                            ("xss", "xss_reflection")
                        ]
                        
                        # Run assessment
                        start_time = time.time()
                        result = assess_endpoints(endpoints, "test-counters-truth", top_k=3, strategy="auto")
                        end_time = time.time()
                        
                        # Verify processing time > 0.0
                        processing_time = result["meta"]["processing_time"]
                        assert processing_time != "0.0s", f"Processing time should not be 0.0s, got {processing_time}"
                        print(f"✅ Processing time: {processing_time}")
                        
                        # Verify counters
                        meta = result["meta"]
                        summary = result["summary"]
                        
                        print(f"Event counters:")
                        print(f"  Probe attempts: {meta['probe_attempts']}")
                        print(f"  Probe successes: {meta['probe_successes']}")
                        print(f"  ML inject attempts: {meta['ml_inject_attempts']}")
                        print(f"  ML inject successes: {meta['ml_inject_successes']}")
                        
                        print(f"Summary (row-derived):")
                        print(f"  Confirmed probe: {summary['confirmed_probe']}")
                        print(f"  Confirmed ML inject: {summary['confirmed_ml_inject']}")
                        print(f"  Total positive: {summary['positive']}")
                        
                        # Verify counters consistency
                        assert meta["counters_consistent"] == True, f"Counters should be consistent, got {meta['counters_consistent']}"
                        print("✅ Counters consistent: True")
                        
                        # Verify we have results
                        results = result["results"]
                        positive_results = [r for r in results if r["decision"] == "positive"]
                        print(f"✅ Found {len(positive_results)} positive results")
                        
                        # Verify probe and injection counts match
                        probe_positives = [r for r in positive_results if r["provenance"] == "Probe"]
                        inject_positives = [r for r in positive_results if r["provenance"] == "Inject"]
                        
                        print(f"✅ Probe positives: {len(probe_positives)}")
                        print(f"✅ Inject positives: {len(inject_positives)}")
                        
                        # Verify summary matches row counts
                        assert summary["confirmed_probe"] == len(probe_positives), f"Summary confirmed_probe ({summary['confirmed_probe']}) should match probe positives ({len(probe_positives)})"
                        assert summary["confirmed_ml_inject"] == len(inject_positives), f"Summary confirmed_ml_inject ({summary['confirmed_ml_inject']}) should match inject positives ({len(inject_positives)})"
                        
                        print("✅ Summary matches row counts")
                        
                        # Verify event counters match summary
                        assert meta["probe_successes"] == summary["confirmed_probe"], f"Event probe_successes ({meta['probe_successes']}) should match summary confirmed_probe ({summary['confirmed_probe']})"
                        assert meta["ml_inject_successes"] == summary["confirmed_ml_inject"], f"Event ml_inject_successes ({meta['ml_inject_successes']}) should match summary confirmed_ml_inject ({summary['confirmed_ml_inject']})"
                        
                        print("✅ Event counters match summary")
                        
                        print("🎉 All tests passed!")

if __name__ == "__main__":
    test_event_counters_and_summary_truth()
