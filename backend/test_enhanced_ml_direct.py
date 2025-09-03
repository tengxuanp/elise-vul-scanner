#!/usr/bin/env python3
"""
Direct test of the enhanced ML system to debug the issue
"""

import os
import sys

# Set environment variables
os.environ['ELISE_USE_ML'] = '1'
os.environ['ELISE_ML_DEBUG'] = '1'
os.environ['ELISE_ML_MODEL_DIR'] = '/Users/raphaelpang/code/elise/backend/modules/ml'

print("=== Testing Enhanced ML System ===")
print(f"ELISE_USE_ML: {os.environ.get('ELISE_USE_ML')}")
print(f"ELISE_ML_DEBUG: {os.environ.get('ELISE_ML_DEBUG')}")
print(f"ELISE_ML_MODEL_DIR: {os.environ.get('ELISE_ML_MODEL_DIR')}")

try:
    from modules.ml.enhanced_inference import EnhancedInferenceEngine
    from modules.ml.enhanced_features import EnhancedFeatureExtractor
    
    print('✅ Enhanced ML imports successful')
    
    # Test feature extraction
    extractor = EnhancedFeatureExtractor()
    endpoint = {'url': 'http://test.com/api/user', 'method': 'GET'}
    param = {'name': 'id', 'value': '123', 'loc': 'query'}
    context = {'payload': "' OR 1=1 --"}
    
    print(f"\n=== Testing Feature Extraction ===")
    print(f"Endpoint: {endpoint}")
    print(f"Param: {param}")
    print(f"Context: {context}")
    
    features = extractor.extract_enhanced_features(endpoint, param, 'sqli', context)
    print(f'✅ Feature extraction successful: {len(features)} features')
    print(f'First 5 features: {list(features.items())[:5]}')
    
    # Check if payload features are present
    payload_feature_count = 0
    for key, value in features.items():
        if value != 0.0:  # Non-zero features
            payload_feature_count += 1
    
    print(f"Non-zero features: {payload_feature_count}/{len(features)}")
    
    # Test inference engine
    print(f"\n=== Testing Enhanced ML Inference ===")
    engine = EnhancedInferenceEngine()
    result = engine.predict_with_confidence(endpoint, param, 'sqli', context)
    
    print(f'✅ Enhanced ML prediction successful')
    print(f'Calibrated probability: {result.get("calibrated_probability", "N/A")}')
    print(f'Raw probability: {result.get("raw_probability", "N/A")}')
    print(f'Confidence: {result.get("confidence", "N/A")}')
    print(f'Model type: {result.get("model_type", "N/A")}')
    print(f'Used path: {result.get("used_path", "N/A")}')
    print(f'Is ML prediction: {result.get("is_ml_prediction", "N/A")}')
    print(f'Fallback used: {result.get("fallback_used", "N/A")}')
    print(f'Features used: {result.get("features_used", "N/A")}')
    
    # Test payload ranking
    print(f"\n=== Testing Payload Ranking ===")
    candidates = ["' OR 1=1 --", "admin'--", "1' UNION SELECT * FROM users--"]
    ranked = engine.rank_payloads(endpoint, param, 'sqli', candidates, context, top_k=3)
    
    print(f'✅ Payload ranking successful: {len(ranked)} payloads ranked')
    for i, payload_result in enumerate(ranked):
        print(f"  {i+1}. {payload_result['payload'][:20]}... -> Score: {payload_result['score']:.3f}")
    
except Exception as e:
    import traceback
    print(f'❌ Error: {e}')
    traceback.print_exc()
