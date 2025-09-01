#!/usr/bin/env python3
"""
Comprehensive test for all enhanced ML models
"""

from enhanced_inference import EnhancedInferenceEngine

def test_all_models():
    """Test all three enhanced models."""
    print("🧪 Testing All Enhanced ML Models")
    print("=" * 60)
    
    # Initialize enhanced inference engine
    engine = EnhancedInferenceEngine()
    
    # Test data for each family
    test_cases = {
        'sqli': {
            'endpoint': {'url': 'https://example.com/api/users', 'method': 'GET'},
            'param': {'name': 'user_id', 'value': '123', 'loc': 'query'}
        },
        'xss': {
            'endpoint': {'url': 'https://example.com/api/comments', 'method': 'POST'},
            'param': {'name': 'comment_text', 'value': 'Hello world', 'loc': 'json'}
        },
        'redirect': {
            'endpoint': {'url': 'https://example.com/api/auth', 'method': 'GET'},
            'param': {'name': 'next_url', 'value': 'https://example.com/dashboard', 'loc': 'query'}
        }
    }
    
    # Test payloads for each family
    test_payloads = {
        'sqli': ["' OR 1=1--", "' UNION SELECT NULL--", "1 OR 1=1--"],
        'xss': ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg/onload=alert(1)>"],
        'redirect': ["https://evil.com", "//evil.com", "https:%2F%2Fevil.com"]
    }
    
    results = {}
    
    for family in ['sqli', 'xss', 'redirect']:
        print(f"\n🔍 Testing {family.upper()} Model")
        print("-" * 40)
        
        try:
            # Test prediction
            endpoint = test_cases[family]['endpoint']
            param = test_cases[family]['param']
            
            result = engine.predict_with_confidence(endpoint, param, family)
            
            print(f"✅ Prediction successful!")
            print(f"   Prediction: {result['prediction']}")
            print(f"   Raw Probability: {result['raw_probability']:.4f}")
            print(f"   Calibrated Probability: {result['calibrated_probability']:.4f}")
            print(f"   Confidence: {result['confidence']:.4f}")
            print(f"   Uncertainty: {result['uncertainty']:.4f}")
            print(f"   Model Type: {result['model_type']}")
            print(f"   Features Used: {result['features_used']}")
            
            # Test payload ranking
            payloads = test_payloads[family]
            ranked = engine.rank_payloads(endpoint, param, family, payloads, top_k=2)
            
            print(f"✅ Payload ranking successful!")
            print(f"   Top 2 payloads:")
            for i, payload_info in enumerate(ranked):
                print(f"     {i+1}. {payload_info['payload']} (Score: {payload_info['score']:.4f})")
            
            results[family] = {
                'prediction': 'SUCCESS',
                'payload_ranking': 'SUCCESS',
                'model_type': result['model_type'],
                'confidence': result['confidence']
            }
            
        except Exception as e:
            print(f"❌ {family.upper()} test failed: {e}")
            results[family] = {
                'prediction': 'FAILED',
                'payload_ranking': 'FAILED',
                'error': str(e)
            }
    
    # Print summary
    print("\n" + "=" * 60)
    print("📊 TEST SUMMARY")
    print("=" * 60)
    
    for family, result in results.items():
        status = "✅" if result['prediction'] == 'SUCCESS' else "❌"
        print(f"{status} {family.upper()}: {result['prediction']}")
        if 'model_type' in result:
            print(f"   Model: {result['model_type']}")
            print(f"   Confidence: {result['confidence']:.4f}")
    
    # Test model info
    print(f"\n🔧 System Information")
    print("-" * 40)
    model_info = engine.get_model_info()
    print(f"Models Loaded: {model_info['models_loaded']}")
    print(f"Total Models: {model_info['total_models']}")
    
    for family in model_info['models_loaded']:
        model_type = model_info.get(f"{family}_model_type", "unknown")
        features = model_info.get(f"{family}_features", 0)
        cv_score = model_info.get(f"{family}_cv_score", 0.0)
        print(f"  {family.upper()}: {model_type} model, {features} features, CV score: {cv_score:.4f}")
    
    return results

if __name__ == "__main__":
    test_all_models()
