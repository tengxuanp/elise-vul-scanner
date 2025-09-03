#!/usr/bin/env python3
"""
Debug enhanced ML integration issues in fuzzer_core
"""

import sys
import os
from pathlib import Path

# Add backend to path
backend_path = Path(__file__).parent
sys.path.insert(0, str(backend_path))

# Set environment variables
os.environ['ELISE_USE_ML'] = '1'
os.environ['ELISE_ML_DEBUG'] = '1' 
os.environ['ELISE_ML_MODEL_DIR'] = str(backend_path / 'modules' / 'ml')

print("=== Debugging Enhanced ML Integration ===")
print(f"Backend path: {backend_path}")
print(f"ML model dir: {os.environ['ELISE_ML_MODEL_DIR']}")

try:
    # Test basic imports
    print("\n1. Testing basic imports...")
    from modules.ml.enhanced_inference import EnhancedInferenceEngine
    print("✅ EnhancedInferenceEngine imported")
    
    from modules.ml.enhanced_features import EnhancedFeatureExtractor  
    print("✅ EnhancedFeatureExtractor imported")
    
    # Test initialization
    print("\n2. Testing initialization...")
    engine = EnhancedInferenceEngine()
    print("✅ Enhanced inference engine created")
    
    extractor = EnhancedFeatureExtractor()
    print("✅ Enhanced feature extractor created")
    
    # Test basic prediction
    print("\n3. Testing basic prediction...")
    endpoint = {"url": "http://test.com/api/user", "method": "GET"}
    param = {"name": "id", "value": "123", "loc": "query"}
    context = {"payload": "' OR 1=1 --"}
    
    result = engine.predict_with_confidence(endpoint, param, "sqli", context)
    print(f"✅ Prediction successful: {result}")
    
    # Test payload ranking
    print("\n4. Testing payload ranking...")
    candidates = ["' OR 1=1 --", "admin'--", "1' UNION SELECT NULL--"]
    ranked = engine.rank_payloads(endpoint, param, "sqli", candidates, context, top_k=3)
    print(f"✅ Ranking successful: {len(ranked)} payloads")
    for i, p in enumerate(ranked):
        print(f"  {i+1}. Score: {p['score']:.3f}, Payload: {p['payload'][:20]}")
    
    # Test fuzzer_core integration
    print("\n5. Testing fuzzer_core integration...")
    from modules.fuzzer_core import (
        _ENHANCED_ML_AVAILABLE, 
        _ENHANCED_ENGINE, 
        _rank_payloads_for_family
    )
    
    print(f"Enhanced ML available: {_ENHANCED_ML_AVAILABLE}")
    print(f"Enhanced engine: {_ENHANCED_ENGINE is not None}")
    
    if _ENHANCED_ML_AVAILABLE and _ENHANCED_ENGINE:
        # Test the actual function that's used in fuzzing
        test_feats = {
            "url": "http://test.com/api/user",
            "method": "GET", 
            "target_param": "id",
            "control_value": "123",
            "in": "query"
        }
        
        recs, meta = _rank_payloads_for_family(test_feats, "sqli", top_n=3)
        print(f"✅ Fuzzer core ranking: {len(recs)} recommendations")
        print(f"Meta: {meta}")
        
        for i, (payload, score) in enumerate(recs):
            print(f"  {i+1}. Score: {score:.3f}, Payload: {payload[:20]}")
    else:
        print("❌ Enhanced ML not available in fuzzer_core")
        
except Exception as e:
    import traceback
    print(f"❌ Error: {e}")
    traceback.print_exc()
