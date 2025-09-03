#!/usr/bin/env python3
"""
Comprehensive test to identify why ML Ranker is showing "Heuristic" instead of real scores
"""

import os
import sys
from pathlib import Path

# Set up environment
backend_path = Path(__file__).parent
sys.path.insert(0, str(backend_path))

os.environ['ELISE_USE_ML'] = '1'
os.environ['ELISE_ML_DEBUG'] = '1'
os.environ['ELISE_ML_MODEL_DIR'] = str(backend_path / 'modules' / 'ml')

print("=== ML Ranker Investigation ===")
print(f"Backend path: {backend_path}")
print(f"ML model dir: {os.environ['ELISE_ML_MODEL_DIR']}")

def test_enhanced_ml_system():
    """Test the enhanced ML system directly"""
    print("\n🔍 Testing Enhanced ML System...")
    
    try:
        from modules.ml.enhanced_inference import EnhancedInferenceEngine
        from modules.ml.enhanced_features import EnhancedFeatureExtractor
        
        print("✅ Enhanced ML imports successful")
        
        # Initialize
        engine = EnhancedInferenceEngine()
        print(f"✅ Enhanced inference engine initialized")
        
        # Get model info
        model_info = engine.get_model_info()
        print(f"📊 Model info: {model_info}")
        
        # Test feature extraction
        extractor = EnhancedFeatureExtractor()
        endpoint = {"url": "http://test.com/api/user", "method": "GET"}
        param = {"name": "id", "value": "123", "loc": "query"}
        context = {"payload": "' OR 1=1 --"}
        
        features = extractor.extract_enhanced_features(endpoint, param, "sqli", context)
        print(f"✅ Feature extraction: {len(features)} features")
        
        non_zero_features = sum(1 for v in features.values() if v != 0.0)
        print(f"📈 Non-zero features: {non_zero_features}/{len(features)}")
        
        # Test prediction
        result = engine.predict_with_confidence(endpoint, param, "sqli", context)
        print(f"✅ Prediction result:")
        print(f"   Used path: {result.get('used_path')}")
        print(f"   Is ML prediction: {result.get('is_ml_prediction')}")
        print(f"   Fallback used: {result.get('fallback_used')}")
        print(f"   Score: {result.get('calibrated_probability', 0):.3f}")
        print(f"   Model type: {result.get('model_type')}")
        
        return True
        
    except Exception as e:
        print(f"❌ Enhanced ML test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_fuzzer_core_integration():
    """Test the fuzzer_core integration with enhanced ML"""
    print("\n🔍 Testing Fuzzer Core Integration...")
    
    try:
        from modules.fuzzer_core import (
            _ENHANCED_ML_AVAILABLE,
            _ENHANCED_ENGINE,
            _rank_payloads_for_family
        )
        
        print(f"Enhanced ML available in fuzzer_core: {_ENHANCED_ML_AVAILABLE}")
        print(f"Enhanced engine initialized: {_ENHANCED_ENGINE is not None}")
        
        if not _ENHANCED_ML_AVAILABLE:
            print("❌ Enhanced ML not available in fuzzer_core - this is the problem!")
            return False
        
        # Test the ranking function that's actually used during fuzzing
        test_features = {
            "url": "http://test.com/api/user",
            "method": "GET",
            "target_param": "id", 
            "control_value": "123",
            "in": "query",
            "content_type": "text/html"
        }
        
        print(f"🧪 Testing _rank_payloads_for_family with features: {test_features}")
        
        recommendations, metadata = _rank_payloads_for_family(
            test_features, "sqli", top_n=3
        )
        
        print(f"✅ Ranking successful: {len(recommendations)} payloads")
        print(f"📊 Metadata: {metadata}")
        
        for i, (payload, score) in enumerate(recommendations):
            print(f"   {i+1}. Score: {score:.3f}, Payload: {payload[:20]}...")
        
        # Check if this is where "Heuristic" is coming from
        used_path = metadata.get("used_path", "unknown")
        print(f"🔍 Used path: {used_path}")
        
        if used_path == "heuristic":
            print("❌ FOUND THE ISSUE: Fuzzer core is using heuristic fallback!")
            print("This means enhanced ML failed and fell back to heuristics")
        elif used_path == "enhanced_ml":
            print("✅ Enhanced ML is working correctly")
        else:
            print(f"⚠️ Unexpected used_path: {used_path}")
        
        return True
        
    except Exception as e:
        print(f"❌ Fuzzer core integration test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_legacy_ml_system():
    """Test the legacy ML system as a comparison"""
    print("\n🔍 Testing Legacy ML System...")
    
    try:
        from modules.ml_ranker import predict_proba
        
        test_data = {
            'status_delta': 500,
            'len_delta': 100, 
            'latency_ms_delta': 2000,
            'detector_hits': {'sql_error': True},
            'payload_family_used': 'sqli'
        }
        
        result = predict_proba(test_data)
        print(f"✅ Legacy ML prediction: {result}")
        
        return True
        
    except Exception as e:
        print(f"❌ Legacy ML test failed: {e}")
        return False

def test_ui_metadata_flow():
    """Test how metadata flows to the UI"""
    print("\n🔍 Testing UI Metadata Flow...")
    
    # Simulate what the fuzzer_core sends to the UI
    mock_result = {
        "ranker_meta": {
            "used_path": "enhanced_ml",
            "ranker_score": 0.85,
            "family_probs": {"sqli": 0.7, "xss": 0.2, "redirect": 0.1},
            "model_ids": {"ranker_path": "enhanced_sqli_xgboost"},
            "enhanced_ml": True
        }
    }
    
    print(f"✅ Mock enhanced ML result: {mock_result}")
    
    # Test heuristic fallback
    heuristic_result = {
        "ranker_meta": {
            "used_path": "heuristic", 
            "ranker_score": "Heuristic",
            "family_probs": None,
            "model_ids": "Heuristic"
        }
    }
    
    print(f"⚠️ Mock heuristic result: {heuristic_result}")
    print("This is what causes 'Heuristic' to appear in the UI")
    
    return True

if __name__ == "__main__":
    print("Starting comprehensive ML Ranker investigation...\n")
    
    # Run all tests
    enhanced_ok = test_enhanced_ml_system()
    fuzzer_ok = test_fuzzer_core_integration() 
    legacy_ok = test_legacy_ml_system()
    ui_ok = test_ui_metadata_flow()
    
    print(f"\n=== Investigation Results ===")
    print(f"Enhanced ML System: {'✅' if enhanced_ok else '❌'}")
    print(f"Fuzzer Core Integration: {'✅' if fuzzer_ok else '❌'}")
    print(f"Legacy ML System: {'✅' if legacy_ok else '❌'}")
    print(f"UI Metadata Flow: {'✅' if ui_ok else '❌'}")
    
    if not fuzzer_ok:
        print(f"\n🎯 ROOT CAUSE IDENTIFIED:")
        print(f"The enhanced ML system is not properly integrated into fuzzer_core")
        print(f"This causes fallback to heuristics, which sets ranker_score='Heuristic'")
    elif enhanced_ok and fuzzer_ok:
        print(f"\n✅ All systems working - issue may be in specific edge cases")
    else:
        print(f"\n⚠️ Mixed results - need deeper investigation")
