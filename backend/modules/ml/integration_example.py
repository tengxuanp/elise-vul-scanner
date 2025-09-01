#!/usr/bin/env python3
"""
Integration Example: Enhanced ML System

This script demonstrates how to integrate the enhanced ML system with your existing codebase.
It shows how to:
1. Use enhanced feature extraction
2. Make predictions with confidence
3. Rank payloads with uncertainty
4. Integrate with existing fuzzer and recommender
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any, List

# Import enhanced components
try:
    from enhanced_features import EnhancedFeatureExtractor
    from enhanced_inference import EnhancedInferenceEngine
    from confidence_calibration import ConfidenceCalibrator
except ImportError:
    from .enhanced_features import EnhancedFeatureExtractor
    from .enhanced_inference import EnhancedInferenceEngine
    from .confidence_calibration import ConfidenceCalibrator

# Configure logging
logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

def example_enhanced_prediction():
    """Example of using enhanced prediction with confidence."""
    print("="*60)
    print("ENHANCED PREDICTION EXAMPLE")
    print("="*60)
    
    # Initialize enhanced inference engine
    engine = EnhancedInferenceEngine()
    
    # Example endpoint and parameter
    endpoint = {
        "url": "https://example.com/api/users/search",
        "method": "GET",
        "content_type": "application/json"
    }
    
    param = {
        "name": "user_id",
        "value": "123",
        "loc": "query"
    }
    
    # Make prediction for SQL injection
    result = engine.predict_with_confidence(endpoint, param, "sqli")
    
    print(f"Endpoint: {endpoint['url']}")
    print(f"Parameter: {param['name']} = {param['value']}")
    print(f"Family: SQL Injection")
    print(f"Prediction: {result['prediction']}")
    print(f"Raw Probability: {result['raw_probability']:.4f}")
    print(f"Calibrated Probability: {result['calibrated_probability']:.4f}")
    print(f"Confidence: {result['confidence']:.4f}")
    print(f"Uncertainty: {result['uncertainty']:.4f}")
    print(f"Model Type: {result['model_type']}")
    print(f"Features Used: {result['features_used']}")
    
    # Show top contributing features if available
    if 'top_features' in result:
        print("\nTop Contributing Features:")
        for feat in result['top_features'][:3]:
            print(f"  {feat['name']}: {feat['value']:.4f} (importance: {feat['importance']:.4f})")

def example_payload_ranking():
    """Example of enhanced payload ranking."""
    print("\n" + "="*60)
    print("ENHANCED PAYLOAD RANKING EXAMPLE")
    print("="*60)
    
    # Initialize engine
    engine = EnhancedInferenceEngine()
    
    # Example endpoint and parameter
    endpoint = {
        "url": "https://example.com/api/comments/add",
        "method": "POST",
        "content_type": "application/json"
    }
    
    param = {
        "name": "comment_text",
        "value": "Hello world",
        "loc": "json"
    }
    
    # Example XSS payloads
    xss_payloads = [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg/onload=alert(1)>',
        '<a href=javascript:alert(1)>x</a>',
        '<details open ontoggle=alert(1)>'
    ]
    
    # Rank payloads
    ranked = engine.rank_payloads(endpoint, param, "xss", xss_payloads, top_k=3)
    
    print(f"Endpoint: {endpoint['url']}")
    print(f"Parameter: {param['name']}")
    print(f"Family: XSS")
    print(f"Top {len(ranked)} Payloads:")
    
    for i, payload_info in enumerate(ranked):
        print(f"\n{i+1}. {payload_info['payload']}")
        print(f"   Score: {payload_info['score']:.4f}")
        print(f"   Confidence: {payload_info['confidence']:.4f}")
        print(f"   Base Prediction: {payload_info['base_prediction']:.4f}")
        print(f"   Payload Score: {payload_info['payload_score']:.4f}")

def example_feature_extraction():
    """Example of enhanced feature extraction."""
    print("\n" + "="*60)
    print("ENHANCED FEATURE EXTRACTION EXAMPLE")
    print("="*60)
    
    # Initialize feature extractor
    extractor = EnhancedFeatureExtractor()
    
    # Example endpoint and parameter
    endpoint = {
        "url": "https://banking.example.com/api/transfer",
        "method": "POST",
        "content_type": "application/json",
        "headers": {
            "Authorization": "Bearer token123",
            "Content-Type": "application/json"
        }
    }
    
    param = {
        "name": "amount",
        "value": "1000.00",
        "loc": "json"
    }
    
    # Extract features with context
    context = {
        "prev_responses": [
            {"status": 200, "time": 150},
            {"status": 200, "time": 145}
        ],
        "param_history": [
            {"value": "500.00", "timestamp": "2024-01-01T10:00:00Z"},
            {"value": "750.00", "timestamp": "2024-01-01T11:00:00Z"}
        ]
    }
    
    features = extractor.extract_enhanced_features(endpoint, param, "sqli", context)
    
    print(f"Endpoint: {endpoint['url']}")
    print(f"Parameter: {param['name']}")
    print(f"Features extracted: {len(features)}")
    
    # Group features by category
    feature_categories = {
        "Endpoint": [k for k in features.keys() if k.startswith(('url_', 'path_', 'method_'))],
        "Parameter": [k for k in features.keys() if k.startswith(('param_', 'location_'))],
        "Security": [k for k in features.keys() if k.startswith('security_')],
        "Business": [k for k in features.keys() if k.startswith('business_')],
        "Context": [k for k in features.keys() if k.startswith(('avg_', 'prev_', 'param_'))]
    }
    
    for category, feature_names in feature_categories.items():
        if feature_names:
            print(f"\n{category} Features:")
            for name in feature_names[:5]:  # Show first 5
                value = features[name]
                print(f"  {name}: {value:.4f}")

def example_confidence_calibration():
    """Example of confidence calibration."""
    print("\n" + "="*60)
    print("CONFIDENCE CALIBRATION EXAMPLE")
    print("="*60)
    
    # Initialize calibrator
    calibrator = ConfidenceCalibrator(method="isotonic")
    
    # Simulate some training data
    import numpy as np
    
    # Generate synthetic data
    np.random.seed(42)
    n_samples = 1000
    
    # True probabilities (ground truth)
    true_probs = np.random.beta(2, 5, n_samples)
    
    # Raw model predictions (uncalibrated)
    raw_probs = true_probs + np.random.normal(0, 0.2, n_samples)
    raw_probs = np.clip(raw_probs, 0.01, 0.99)
    
    # Binary labels
    y_true = (true_probs > 0.5).astype(int)
    
    # Fit calibrator
    calibrator.fit(y_true, raw_probs)
    
    # Calibrate predictions
    calibrated_probs = calibrator.calibrate(raw_probs)
    
    # Evaluate calibration
    metrics = calibrator.evaluate_calibration(y_true, raw_probs)
    
    print(f"Calibration Method: {calibrator.method}")
    print(f"Brier Score (lower is better): {metrics['brier_score']:.4f}")
    print(f"Expected Calibration Error: {metrics['ece']:.4f}")
    
    if 'reliability_stats' in metrics:
        reliability = metrics['reliability_stats']
        print(f"Reliability Correlation: {reliability['correlation']:.4f}")
        print(f"Mean Absolute Difference: {reliability['mean_absolute_difference']:.4f}")
    
    # Show some examples
    print(f"\nCalibration Examples:")
    for i in range(5):
        print(f"  Sample {i+1}: Raw={raw_probs[i]:.3f} → Calibrated={calibrated_probs[i]:.3f} (True={true_probs[i]:.3f})")
    
    # Estimate uncertainty
    uncertainty = calibrator.estimate_uncertainty(calibrated_probs, method="entropy")
    print(f"\nUncertainty Statistics:")
    print(f"  Mean Uncertainty: {np.mean(uncertainty):.4f}")
    print(f"  Std Uncertainty: {np.std(uncertainty):.4f}")
    print(f"  Min Uncertainty: {np.min(uncertainty):.4f}")
    print(f"  Max Uncertainty: {np.max(uncertainty):.4f}")

def example_integration_with_existing():
    """Example of how to integrate with existing fuzzer/recommender."""
    print("\n" + "="*60)
    print("INTEGRATION WITH EXISTING SYSTEM")
    print("="*60)
    
    # Initialize enhanced engine
    engine = EnhancedInferenceEngine()
    
    # Get model information
    model_info = engine.get_model_info()
    
    print("Enhanced ML System Status:")
    print(f"  Models Loaded: {model_info['models_loaded']}")
    print(f"  Scalers Loaded: {model_info['scalers_loaded']}")
    print(f"  Total Models: {model_info['total_models']}")
    
    # Show per-family details
    for family in model_info['models_loaded']:
        model_type = model_info.get(f"{family}_model_type", "unknown")
        features = model_info.get(f"{family}_features", 0)
        cv_score = model_info.get(f"{family}_cv_score", 0.0)
        
        print(f"  {family.upper()}: {model_type} model, {features} features, CV score: {cv_score:.4f}")
    
    print("\nIntegration Points:")
    print("1. Replace existing ml_ranker.predict_proba() calls with engine.predict_with_confidence()")
    print("2. Use engine.rank_payloads() for better payload ranking")
    print("3. Access enhanced features via EnhancedFeatureExtractor")
    print("4. Use confidence scores for adaptive fuzzing strategies")
    print("5. Leverage uncertainty estimates for risk assessment")

def main():
    """Run all examples."""
    print("ELISE ENHANCED ML SYSTEM - INTEGRATION EXAMPLES")
    print("="*80)
    
    try:
        # Run examples
        example_enhanced_prediction()
        example_payload_ranking()
        example_feature_extraction()
        example_confidence_calibration()
        example_integration_with_existing()
        
        print("\n" + "="*80)
        print("All examples completed successfully!")
        print("\nNext Steps:")
        print("1. Train enhanced models using train_enhanced_models.py")
        print("2. Integrate EnhancedInferenceEngine into your existing code")
        print("3. Replace basic predictions with confidence-aware predictions")
        print("4. Use enhanced features for better model performance")
        print("5. Implement adaptive fuzzing based on confidence scores")
        
    except Exception as e:
        log.error(f"Example failed: {e}")
        print(f"\nError running examples: {e}")
        print("Make sure all dependencies are installed and models are trained.")

if __name__ == "__main__":
    main()
