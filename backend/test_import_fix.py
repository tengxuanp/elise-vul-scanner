#!/usr/bin/env python3
"""
Test script to verify Recommender import is working in fuzz_routes
"""

import os
import sys

# Set environment variables for ML
os.environ["ELISE_USE_ML"] = "1"
os.environ["ELISE_ML_DEBUG"] = "1"
os.environ["ELISE_ML_MODEL_DIR"] = "/Users/raphaelpang/code/elise/backend/modules/ml"

print("Testing Recommender import in fuzz_routes...")

try:
    # Test importing from fuzz_routes
    from routes.fuzz_routes import Recommender, _init_reco
    
    print(f"✅ Successfully imported Recommender: {Recommender}")
    
    # Test initializing the recommender
    reco = _init_reco()
    print(f"✅ Recommender initialized: {reco}")
    
    if reco:
        print(f"   - Type: {type(reco)}")
        print(f"   - Has load method: {hasattr(reco, 'load')}")
        print(f"   - Has recommend_with_meta method: {hasattr(reco, 'recommend_with_meta')}")
        
        # Test the recommend_with_meta method
        test_features = {
            "url": "http://localhost:8082/login",
            "param": "return_to",
            "method": "GET",
            "content_type": "text/html",
            "headers": {},
            "injection_mode": "query",
            "mode": "query"
        }
        
        print(f"\nTesting recommend_with_meta with features: {test_features}")
        recs, meta = reco.recommend_with_meta(
            test_features, 
            pool=["' OR 1=1--", "' OR 'a'='a' --"], 
            top_n=2, 
            threshold=0.2, 
            family="sqli"
        )
        
        print(f"Recommendations: {recs}")
        print(f"Meta: {meta}")
        
        if meta.get("used_path") == "heuristic":
            print("❌ Still using heuristic fallback!")
        else:
            print("✅ ML ranker is working in fuzz_routes!")
            
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()
