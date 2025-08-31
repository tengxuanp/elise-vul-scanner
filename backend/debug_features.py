#!/usr/bin/env python3
"""
Debug script to test actual feature extraction and ML ranker
"""

import os
import sys

# Set environment variables for ML
os.environ["ELISE_USE_ML"] = "1"
os.environ["ELISE_ML_DEBUG"] = "1"
os.environ["ELISE_ML_MODEL_DIR"] = "/Users/raphaelpang/code/elise/backend/modules/ml"

print("Testing actual feature extraction and ML ranker...")

try:
    # Import the actual modules used in fuzzing
    from modules.fuzzer_core import _endpoint_features, _rank_payloads_for_family
    
    # Test with a real target like what would be used in fuzzing
    test_target = {
        "id": "test-1",
        "url": "http://localhost:8082/rest/products/search",
        "target_param": "q",
        "method": "GET",
        "in": "query",
        "content_type": "text/html",
        "headers": {},
        "control_value": "test"
    }
    
    print(f"\nTest target: {test_target}")
    
    # Extract features
    print("\n--- Extracting endpoint features ---")
    feats = _endpoint_features(test_target)
    print(f"Features extracted: {len(feats)} fields")
    print(f"Feature keys: {list(feats.keys())}")
    
    # Check for critical fields
    critical_fields = ['url', 'param', 'method', 'content_type', 'injection_mode', 'mode']
    for field in critical_fields:
        if field in feats:
            print(f"✅ {field}: {feats[field]}")
        else:
            print(f"❌ {field}: MISSING")
    
    # Test ML ranking
    print("\n--- Testing ML ranking ---")
    try:
        recs, meta = _rank_payloads_for_family(feats, 'sqli', top_n=3)
        print(f"✅ ML ranking successful!")
        print(f"Recommendations: {len(recs)}")
        print(f"Meta: {meta}")
        
        if meta.get("used_path") == "heuristic":
            print("❌ Still using heuristic fallback!")
        else:
            print("✅ ML ranker is working!")
            
    except Exception as e:
        print(f"❌ ML ranking failed: {e}")
        import traceback
        traceback.print_exc()
        
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()
