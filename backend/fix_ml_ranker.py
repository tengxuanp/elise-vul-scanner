#!/usr/bin/env python3
"""
Script to fix and test the ML ranker
"""
import os
import sys
from pathlib import Path

def fix_ml_environment():
    """Set the correct environment variables for ML ranker"""
    print("=== Fixing ML Environment ===")
    
    # Set ML environment variables
    os.environ["ELISE_USE_ML"] = "1"
    os.environ["ELISE_ML_DEBUG"] = "1"
    
    # Ensure the model directory is set correctly
    backend_dir = Path(__file__).parent
    ml_dir = backend_dir / "modules" / "ml"
    os.environ["ELISE_ML_MODEL_DIR"] = str(ml_dir)
    
    print(f"✓ Set ELISE_USE_ML=1")
    print(f"✓ Set ELISE_ML_DEBUG=1") 
    print(f"✓ Set ELISE_ML_MODEL_DIR={ml_dir}")
    
    # Test ML ranker
    print("\n=== Testing ML Ranker ===")
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
        
        if result.get('source', '').startswith('ml:'):
            print("🎉 ML ranker is working correctly!")
        else:
            print("❌ ML ranker is not working - source:", result.get('source'))
            
    except Exception as e:
        print(f"❌ ML ranker failed: {e}")
        import traceback
        traceback.print_exc()
    
    # Test fuzzer core
    print("\n=== Testing Fuzzer Core ===")
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
        
        if result.get('source', '').startswith('ml:'):
            print("🎉 Fuzzer ML ranker is working correctly!")
        else:
            print("❌ Fuzzer ML ranker is not working - source:", result.get('source'))
            
    except Exception as e:
        print(f"❌ Fuzzer core failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    fix_ml_environment()
