#!/usr/bin/env python3
"""
Test script to check ML environment variables and model loading
"""
import os
import sys
from pathlib import Path

# Add the current directory to the path so we can import modules
sys.path.insert(0, str(Path(__file__).parent))

def test_ml_environment():
    print("=== Testing ML Environment ===")
    print(f"Current working directory: {os.getcwd()}")
    print(f"Python path: {sys.path[:3]}")
    print()
    
    print("=== Environment Variables ===")
    print(f"ELISE_USE_ML: {os.getenv('ELISE_USE_ML', 'NOT_SET')}")
    print(f"ELISE_ML_DEBUG: {os.getenv('ELISE_ML_DEBUG', 'NOT_SET')}")
    print(f"ELISE_ML_MODEL_DIR: {os.getenv('ELISE_ML_MODEL_DIR', 'NOT_SET')}")
    print(f"ELISE_REQUIRE_RANKER: {os.getenv('ELISE_REQUIRE_RANKER', 'NOT_SET')}")
    print()
    
    print("=== Testing ML Ranker Import ===")
    try:
        from modules.ml_ranker import predict_proba, model_info
        print("✓ ML ranker imported successfully")
        
        info = model_info()
        print(f"✓ Model info: {info}")
        
        # Test prediction
        test_data = {
            'status_delta': 500, 
            'len_delta': 100, 
            'latency_ms_delta': 2000, 
            'detector_hits': {'sql_error': True}, 
            'payload_family_used': 'sqli'
        }
        result = predict_proba(test_data)
        print(f"✓ Prediction result: {result}")
        
    except Exception as e:
        print(f"✗ ML ranker failed: {e}")
        import traceback
        traceback.print_exc()
    
    print()
    print("=== Testing Fuzzer Core Import ===")
    try:
        from modules.fuzzer_core import _ML_AVAILABLE, _ranker_predict
        print(f"✓ Fuzzer core imported successfully")
        print(f"✓ _ML_AVAILABLE: {_ML_AVAILABLE}")
        
        # Test the ranker predict function
        test_data = {
            'status_delta': 500, 
            'len_delta': 100, 
            'latency_ms_delta': 2000, 
            'detector_hits': {'sql_error': True}, 
            'payload_family_used': 'sqli'
        }
        result = _ranker_predict(test_data)
        print(f"✓ Fuzzer ranker result: {result}")
        
    except Exception as e:
        print(f"✗ Fuzzer core failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_ml_environment()
