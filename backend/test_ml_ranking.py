#!/usr/bin/env python3
"""
Test script to verify ML ranking implementation works correctly.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from backend.modules.ml.feature_spec import build_features
from backend.modules.ml.infer_ranker import rank_payloads

def test_ml_ranking():
    """Test ML ranking with sample features."""
    
    # Test context for XSS
    ctx = {
        "family": "xss",
        "param_in": "query",
        "param": "search",
        "payload": "",
        "probe_sql_error": False,
        "probe_timing_delta_gt2s": False,
        "probe_reflection_html": True,
        "probe_reflection_js": False,
        "probe_redirect_location_reflects": False,
        "status_class": 2,
        "content_type_html": True,
        "content_type_json": False,
        "ctx_html": True,
        "ctx_attr": False,
        "ctx_js": False
    }
    
    # Build features
    features = build_features(ctx)
    print("Features built:", len(features), "features")
    print("Sample features:", {k: v for k, v in list(features.items())[:5]})
    
    # Test ranking
    results = rank_payloads("xss", features, top_k=3)
    print(f"\nRanking results for XSS:")
    for i, result in enumerate(results):
        print(f"  {i+1}. {result['payload'][:30]}... (score: {result['score']:.3f}, p_cal: {result['p_cal']:.3f})")
    
    # Verify structure
    assert len(results) <= 3, "Should return at most top_k results"
    assert all("payload" in r for r in results), "All results should have payload"
    assert all("score" in r for r in results), "All results should have score"
    assert all("p_cal" in r for r in results), "All results should have p_cal"
    assert all(0 <= r["p_cal"] <= 1 for r in results), "p_cal should be between 0 and 1"
    
    print("\n✅ ML ranking test passed!")
    return True

if __name__ == "__main__":
    test_ml_ranking()
