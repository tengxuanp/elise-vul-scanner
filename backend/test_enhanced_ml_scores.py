#!/usr/bin/env python3
"""
Test script to verify enhanced ML scores and debug the integration
"""

import os
import sys
from pathlib import Path

# Set environment variables
os.environ['ELISE_USE_ML'] = '1'
os.environ['ELISE_ML_DEBUG'] = '1'
os.environ['ELISE_ML_MODEL_DIR'] = '/Users/raphaelpang/code/elise/backend/modules/ml'

# Add backend to path
backend_path = Path(__file__).parent
sys.path.insert(0, str(backend_path))

def test_enhanced_ml_scores():
    """Test enhanced ML to see what scores it actually produces"""
    print("=== Testing Enhanced ML Score Generation ===")
    
    try:
        from modules.ml.enhanced_inference import EnhancedInferenceEngine
        from modules.fuzzer_core import _rank_payloads_for_family, _endpoint_features
        
        print("✅ Imports successful")
        
        # Create enhanced ML engine
        engine = EnhancedInferenceEngine()
        print(f"✅ Enhanced ML engine created: {len(engine.models)} models loaded")
        
        # Test with realistic fuzzing scenario
        test_endpoint = {
            "url": "http://localhost:8082/login",
            "method": "GET",
            "target_param": "return_to",
            "in": "query",
            "content_type": "text/html"
        }
        
        # Extract features like fuzzer_core does
        feats = _endpoint_features(test_endpoint)
        print(f"✅ Extracted features: {len(feats)} features")
        print(f"Sample features: {list(feats.keys())[:5]}")
        
        # Test payload ranking for SQLi
        print("\n=== Testing Payload Ranking (SQLi) ===")
        recs, meta = _rank_payloads_for_family(feats, "sqli", top_n=5)
        
        print(f"Results: {len(recs)} payloads ranked")
        print(f"Metadata: {meta}")
        
        for i, (payload, score) in enumerate(recs[:3]):
            print(f"  {i+1}. {payload[:30]}... -> Score: {score:.6f}")
            
        # Check if this is enhanced ML
        is_enhanced = meta.get("used_path") == "enhanced_ml"
        print(f"\n✅ Enhanced ML Used: {is_enhanced}")
        print(f"Used Path: {meta.get('used_path')}")
        print(f"Model IDs: {meta.get('model_ids')}")
        print(f"Ranker Score: {meta.get('ranker_score')}")
        
        # Test direct enhanced ML prediction
        print("\n=== Testing Direct Enhanced ML Prediction ===")
        endpoint_info = {
            "url": test_endpoint["url"],
            "method": test_endpoint["method"],
            "content_type": test_endpoint.get("content_type", "")
        }
        
        param_info = {
            "name": test_endpoint["target_param"],
            "value": "' OR '1'='1' --",
            "loc": test_endpoint["in"]
        }
        
        context = {"payload": "' OR '1'='1' --"}
        
        result = engine.predict_with_confidence(endpoint_info, param_info, "sqli", context)
        
        print(f"Direct prediction result:")
        print(f"  Raw probability: {result.get('raw_probability'):.6f}")
        print(f"  Calibrated probability: {result.get('calibrated_probability'):.6f}")
        print(f"  Confidence: {result.get('confidence'):.6f}")
        print(f"  Used path: {result.get('used_path')}")
        print(f"  Is ML prediction: {result.get('is_ml_prediction')}")
        print(f"  Fallback used: {result.get('fallback_used')}")
        
        # Test payload ranking directly
        print("\n=== Testing Direct Payload Ranking ===")
        payloads = ["' OR '1'='1' --", "admin'--", "1' UNION SELECT * FROM users--"]
        ranked = engine.rank_payloads(endpoint_info, param_info, "sqli", payloads, context, top_k=3)
        
        print(f"Direct ranking results:")
        for payload_result in ranked:
            print(f"  {payload_result['payload'][:30]}... -> Score: {payload_result['score']:.6f}, Fallback: {payload_result['fallback_used']}")
        
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    test_enhanced_ml_scores()
