#!/usr/bin/env python3
"""
Test script to verify ML ranking functionality works correctly.
"""

import sys
import os
sys.path.append('backend')

from modules.ml.infer_ranker import rank_payloads

def test_ml_ranking():
    """Test ML ranking with mock data."""
    print("Testing ML ranking functionality...")
    
    # Test feature vector creation
    test_features = {
        'param_length': 10, 'url_length': 50, 'path_depth': 2, 'entropy': 0.5,
        'family_xss': 1, 'family_sqli': 0, 'family_redirect': 0,
        'param_in_query': 1, 'param_in_form': 0, 'param_in_json': 0,
        'probe_sql_error': 0, 'probe_timing_delta_gt2s': 0, 'probe_reflection_html': 1,
        'probe_reflection_attr': 0, 'probe_reflection_js': 0, 'probe_redirect_influence': 0,
        'status_class_2': 0, 'status_class_3': 0, 'status_class_4': 0, 'status_class_5': 0, 'status_class_other': 0,
        'content_type_html': 1, 'content_type_json': 0,
        'ctx_html': 1, 'ctx_attr': 0, 'ctx_js': 0,
        'param_len': 10, 'payload_len': 5, 'alnum_ratio': 0.8, 'digit_ratio': 0.2, 'symbol_ratio': 0.1,
        'url_encoded_ratio': 0.0, 'double_encoded_hint': 0, 'shannon_entropy': 0.5,
        'has_quote': 0, 'has_angle': 1, 'has_lt_gt': 1, 'has_script_tag': 0, 'has_event_handler': 0,
        'sql_kw_hits': 0, 'balanced_quotes': 1, 'has_comment_seq': 0,
        'payload_has_script': 0, 'payload_has_svg': 0, 'payload_has_img': 0
    }

    # Test XSS ranking
    print("\n=== Testing XSS ML Ranking ===")
    ranked = rank_payloads('xss', test_features, top_k=3, xss_context='html', xss_escaping='raw')
    print(f"Ranking successful: {len(ranked) if ranked else 0} payloads")
    
    if ranked:
        print("\nResults:")
        for i, payload in enumerate(ranked):
            print(f"  {i+1}. {payload['payload']} (score: {payload['score']:.3f}, p_cal: {payload['p_cal']:.3f}, source: {payload['rank_source']})")
        
        # Verify ML ranking is working
        ml_payloads = [p for p in ranked if p['rank_source'] == 'ml']
        if ml_payloads:
            print(f"\n✅ SUCCESS: {len(ml_payloads)} payloads ranked by ML model")
            print(f"   ML probabilities: {[p['p_cal'] for p in ml_payloads]}")
        else:
            print("\n❌ FAILED: No ML ranking found")
    
    # Test SQLi ranking
    print("\n=== Testing SQLi ML Ranking ===")
    sqli_features = test_features.copy()
    sqli_features['family_xss'] = 0
    sqli_features['family_sqli'] = 1
    
    ranked_sqli = rank_payloads('sqli', sqli_features, top_k=3)
    print(f"SQLi ranking successful: {len(ranked_sqli) if ranked_sqli else 0} payloads")
    
    if ranked_sqli:
        print("\nSQLi Results:")
        for i, payload in enumerate(ranked_sqli):
            print(f"  {i+1}. {payload['payload']} (score: {payload['score']:.3f}, p_cal: {payload['p_cal']:.3f}, source: {payload['rank_source']})")
    
    print("\n=== Test Complete ===")
    return True

if __name__ == "__main__":
    test_ml_ranking()
