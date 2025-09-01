#!/usr/bin/env python3
"""
Simple test script for the enhanced ML system
"""

import numpy as np

def test_enhanced_features():
    """Test enhanced feature extraction."""
    print("Testing Enhanced Feature Extraction...")
    
    try:
        from enhanced_features import EnhancedFeatureExtractor
        
        extractor = EnhancedFeatureExtractor()
        endpoint = {'url': 'https://example.com/api/users', 'method': 'GET'}
        param = {'name': 'user_id', 'value': '123', 'loc': 'query'}
        
        features = extractor.extract_enhanced_features(endpoint, param, 'sqli')
        print(f"✅ Enhanced feature extraction successful! Extracted {len(features)} features")
        print(f"First few features: {dict(list(features.items())[:3])}")
        return True
        
    except Exception as e:
        print(f"❌ Enhanced feature extraction failed: {e}")
        return False

def test_confidence_calibration():
    """Test confidence calibration."""
    print("\nTesting Confidence Calibration...")
    
    try:
        from confidence_calibration import ConfidenceCalibrator
        
        calibrator = ConfidenceCalibrator(method='isotonic')
        y_true = np.array([1, 0, 1, 0, 1])
        y_pred_proba = np.array([0.8, 0.3, 0.9, 0.2, 0.7])
        
        calibrator.fit(y_true, y_pred_proba)
        calibrated_probs = calibrator.calibrate(y_pred_proba)
        uncertainty = calibrator.estimate_uncertainty(calibrated_probs, method='entropy')
        
        print("✅ Confidence calibration successful!")
        print(f"Original probs: {y_pred_proba}")
        print(f"Calibrated probs: {calibrated_probs}")
        print(f"Uncertainty: {uncertainty}")
        return True
        
    except Exception as e:
        print(f"❌ Confidence calibration failed: {e}")
        return False

def test_enhanced_inference():
    """Test enhanced inference engine."""
    print("\nTesting Enhanced Inference Engine...")
    
    try:
        from enhanced_inference import EnhancedInferenceEngine
        
        engine = EnhancedInferenceEngine()
        endpoint = {'url': 'https://example.com/api/users', 'method': 'GET'}
        param = {'name': 'user_id', 'value': '123', 'loc': 'query'}
        
        # This will use fallback since no enhanced models are trained yet
        result = engine.predict_with_confidence(endpoint, param, 'sqli')
        
        print("✅ Enhanced inference successful!")
        print(f"Prediction: {result['prediction']}")
        print(f"Confidence: {result['confidence']:.4f}")
        print(f"Uncertainty: {result['uncertainty']:.4f}")
        print(f"Model Type: {result['model_type']}")
        return True
        
    except Exception as e:
        print(f"❌ Enhanced inference failed: {e}")
        return False

def test_enhanced_trainer():
    """Test enhanced trainer."""
    print("\nTesting Enhanced Trainer...")
    
    try:
        from enhanced_trainer import EnhancedModelTrainer, ModelConfig
        
        config = ModelConfig(
            family="sqli",
            model_type="xgboost",
            use_cross_validation=False,
            hyperparameter_tuning=False,
            feature_selection=False
        )
        
        trainer = EnhancedModelTrainer(config)
        print("✅ Enhanced trainer initialization successful!")
        return True
        
    except Exception as e:
        print(f"❌ Enhanced trainer failed: {e}")
        return False

def main():
    """Run all tests."""
    print("🧪 Testing Enhanced ML System Components")
    print("=" * 50)
    
    tests = [
        test_enhanced_features,
        test_confidence_calibration,
        test_enhanced_inference,
        test_enhanced_trainer
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
    
    print("\n" + "=" * 50)
    print(f"Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Enhanced ML system is ready to use.")
    else:
        print("⚠️  Some tests failed. Check the errors above.")
    
    return passed == total

if __name__ == "__main__":
    main()
