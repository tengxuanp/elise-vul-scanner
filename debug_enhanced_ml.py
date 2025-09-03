#!/usr/bin/env python3
"""
Debug script to test enhanced ML initialization step by step
"""

import sys
import os
from pathlib import Path

# Add backend to path
backend_dir = Path(__file__).parent / "backend"
sys.path.insert(0, str(backend_dir))

print("🔍 Debugging Enhanced ML Initialization")
print("=" * 50)

try:
    print("\n1. Testing imports...")
    from modules.ml.enhanced_inference import EnhancedInferenceEngine
    from modules.ml.enhanced_features import EnhancedFeatureExtractor
    print("✅ Imports successful")
except Exception as e:
    print(f"❌ Import failed: {e}")
    sys.exit(1)

try:
    print("\n2. Testing EnhancedInferenceEngine initialization...")
    engine = EnhancedInferenceEngine()
    print(f"✅ Engine created: {engine}")
    
    print("\n3. Testing model loading...")
    print(f"   Model directory: {engine.model_dir}")
    print(f"   Models loaded: {list(engine.models.keys())}")
    print(f"   Scalers loaded: {list(engine.scalers.keys())}")
    print(f"   Metadata loaded: {list(engine.metadata.keys())}")
    
    # Check specific models
    for family in ["sqli", "xss", "redirect"]:
        print(f"\n   {family.upper()} family:")
        print(f"     Model: {'✅' if family in engine.models else '❌'}")
        print(f"     Scaler: {'✅' if family in engine.scalers else '❌'}")
        print(f"     Metadata: {'✅' if family in engine.metadata else '❌'}")
        
        if family in engine.models:
            model = engine.models[family]
            print(f"     Model type: {type(model)}")
            if hasattr(model, 'predict_proba'):
                print(f"     Has predict_proba: ✅")
            else:
                print(f"     Has predict_proba: ❌")
                
        if family in engine.scalers:
            scaler = engine.scalers[family]
            print(f"     Scaler type: {type(scaler)}")
            if hasattr(scaler, 'n_features_in_'):
                print(f"     Expected features: {scaler.n_features_in_}")
            else:
                print(f"     Expected features: unknown")
    
    print("\n4. Testing feature extraction...")
    feature_extractor = EnhancedFeatureExtractor()
    print(f"✅ Feature extractor created: {feature_extractor}")
    
    # Test feature extraction
    test_endpoint = {
        "url": "http://localhost:8082/signup",
        "method": "GET",
        "content_type": "text/html"
    }
    test_param = {
        "name": "ref_page",
        "value": "test",
        "loc": "query"
    }
    
    print("\n5. Testing feature extraction...")
    features = feature_extractor.extract_enhanced_features(test_endpoint, test_param, "sqli")
    print(f"✅ Features extracted: {len(features)} features")
    print(f"   Feature keys: {list(features.keys())[:5]}...")
    
    print("\n6. Testing prediction...")
    result = engine.predict_with_confidence(test_endpoint, test_param, "sqli")
    print(f"✅ Prediction successful:")
    print(f"   Raw probability: {result.get('raw_probability', 'N/A')}")
    print(f"   Calibrated probability: {result.get('calibrated_probability', 'N/A')}")
    print(f"   Confidence: {result.get('confidence', 'N/A')}")
    print(f"   Uncertainty: {result.get('uncertainty', 'N/A')}")
    print(f"   Features used: {result.get('features_used', 'N/A')}")
    print(f"   Model type: {result.get('model_type', 'N/A')}")
    print(f"   Used path: {result.get('used_path', 'N/A')}")
    print(f"   Is ML prediction: {result.get('is_ml_prediction', 'N/A')}")
    
    print("\n7. Testing payload ranking...")
    test_payloads = ["' OR 1=1--", "' OR 'a'='a'--", "1' OR 1=1--"]
    ranked = engine.rank_payloads(test_endpoint, test_param, "sqli", test_payloads)
    print(f"✅ Payload ranking successful: {len(ranked)} results")
    
    for i, item in enumerate(ranked[:3]):
        print(f"   {i+1}. {item['payload']} (score: {item['score']:.3f}, confidence: {item['confidence']:.3f})")
    
    print("\n🎉 Enhanced ML system is fully functional!")
    
except Exception as e:
    print(f"\n❌ Error during testing: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
