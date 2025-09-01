#!/usr/bin/env python3
"""
Test the trained enhanced model
"""

from enhanced_inference import EnhancedInferenceEngine

def test_trained_model():
    """Test enhanced inference with trained model."""
    print("Testing Enhanced Inference with Trained Model...")
    
    try:
        # Initialize enhanced inference engine
        engine = EnhancedInferenceEngine()
        
        # Test endpoint and parameter
        endpoint = {'url': 'https://example.com/api/users', 'method': 'GET'}
        param = {'name': 'user_id', 'value': '123', 'loc': 'query'}
        
        # Make prediction
        result = engine.predict_with_confidence(endpoint, param, 'sqli')
        
        print("✅ Enhanced inference with trained model successful!")
        print(f"Prediction: {result['prediction']}")
        print(f"Raw Probability: {result['raw_probability']:.4f}")
        print(f"Calibrated Probability: {result['calibrated_probability']:.4f}")
        print(f"Confidence: {result['confidence']:.4f}")
        print(f"Uncertainty: {result['uncertainty']:.4f}")
        print(f"Model Type: {result['model_type']}")
        print(f"Features Used: {result['features_used']}")
        
        # Test payload ranking
        print("\nTesting Payload Ranking...")
        payloads = ["' OR 1=1--", "' UNION SELECT NULL--", "1 OR 1=1--"]
        ranked = engine.rank_payloads(endpoint, param, 'sqli', payloads, top_k=2)
        
        print(f"✅ Payload ranking successful! Ranked {len(ranked)} payloads")
        for i, payload_info in enumerate(ranked):
            print(f"  {i+1}. {payload_info['payload']} (Score: {payload_info['score']:.4f})")
        
        return True
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    test_trained_model()
