
import sys
import os
import json

# Add project root to the Python path
backend_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(backend_dir)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from backend.modules.ml.enhanced_inference import EnhancedInferenceEngine

def run_test():
    print("--- Running Enhanced Inference Engine Test ---")
    
    # Initialize the engine
    engine = EnhancedInferenceEngine()
    
    # Sample data for prediction
    sample_endpoint = {"path": "/api/search", "method": "GET"}
    sample_param = {"name": "query", "value": "test"}
    sample_family = "sqli"
    
    print(f"Predicting for family: {sample_family}")
    
    # Run prediction
    result = engine.predict_with_confidence(sample_endpoint, sample_param, sample_family)
    
    print("\n--- Prediction Result ---")
    print(json.dumps(result, indent=2))
    
    if result.get("fallback_used"):
        print("\n--- 🚨 TEST FAILED: Fallback prediction was used. ---")
    elif result.get("features_used", 0) > 1:
        print(f"\n--- ✅ TEST PASSED: Successfully used ML model with {result['features_used']} features. ---")
    else:
        print("\n--- 🚨 TEST FAILED: Unknown state. ---")

if __name__ == "__main__":
    run_test()
