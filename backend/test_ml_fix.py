#!/usr/bin/env python3
"""
Test script to verify ML ranker is properly loaded in fuzzer_core
"""

import os
import sys

# Set environment variables for ML
os.environ["ELISE_USE_ML"] = "1"
os.environ["ELISE_ML_DEBUG"] = "1"
os.environ["ELISE_ML_MODEL_DIR"] = "/Users/raphaelpang/code/elise/backend/modules/ml"

print("Testing ML ranker integration in fuzzer_core...")
print(f"ELISE_USE_ML: {os.environ.get('ELISE_USE_ML')}")
print(f"ELISE_ML_DEBUG: {os.environ.get('ELISE_ML_DEBUG')}")
print(f"ELISE_ML_MODEL_DIR: {os.environ.get('ELISE_ML_MODEL_DIR')}")

try:
    # Import fuzzer_core to trigger the ML ranker loading
    from modules.fuzzer_core import _RECO, _rank_payloads_for_family
    
    print(f"\nML Recommender loaded: {_RECO is not None}")
    if _RECO:
        print(f"Recommender ready: {getattr(_RECO, 'ready', 'N/A')}")
        print(f"Recommender meta: {getattr(_RECO, 'meta', {})}")
    
    # Test the ranking function
    test_features = {
        "url": "http://localhost:8082/login",
        "param": "return_to",
        "method": "GET",
        "content_type": "text/html",
        "headers": {},
        "injection_mode": "query",
        "mode": "query"
    }
    
    print(f"\nTesting _rank_payloads_for_family with features: {test_features}")
    recs, meta = _rank_payloads_for_family(test_features, 'sqli', top_n=3)
    
    print(f"Ranking results: {recs}")
    print(f"Meta: {meta}")
    
    if meta.get("used_path") == "heuristic":
        print("❌ Still using heuristic fallback!")
    else:
        print("✅ ML ranker is working!")
        
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()
