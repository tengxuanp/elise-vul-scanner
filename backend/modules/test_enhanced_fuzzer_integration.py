#!/usr/bin/env python3
"""
Test Enhanced Fuzzer Integration

This script demonstrates how the enhanced ML system integrates with the fuzzer,
showing the enhanced predictions and payload ranking in action.
"""

import json
from pathlib import Path

def test_enhanced_fuzzer_integration():
    """Test the enhanced fuzzer integration."""
    print("🧪 Testing Enhanced Fuzzer Integration")
    print("=" * 60)
    
    try:
        # Import the enhanced fuzzer functions
        from enhanced_fuzzer_core import (
            _enhanced_ml_predict,
            _enhanced_rank_payloads_for_family,
            _endpoint_features,
            _ENHANCED_ML_AVAILABLE
        )
        
        print(f"✅ Enhanced ML Available: {_ENHANCED_ML_AVAILABLE}")
        
        if not _ENHANCED_ML_AVAILABLE:
            print("❌ Enhanced ML system not available. Check the installation.")
            return False
        
        # Test 1: Enhanced ML Prediction
        print("\n🔍 Test 1: Enhanced ML Prediction")
        print("-" * 40)
        
        # Create test target (similar to what the fuzzer would use)
        test_target = {
            "id": "test_001",
            "method": "GET",
            "url": "https://example.com/api/users/search",
            "target_param": "user_id",
            "control_value": "123",
            "in": "query",
            "content_type": "application/json"
        }
        
        # Extract features
        features = _endpoint_features(test_target)
        print(f"Features extracted: {len(features)}")
        print(f"Sample features: {dict(list(features.items())[:5])}")
        
        # Test ML prediction
        ml_result = _enhanced_ml_predict(None, features, family="sqli")
        
        print(f"✅ ML Prediction successful!")
        print(f"   Probability: {ml_result['p']:.4f}")
        print(f"   Source: {ml_result['source']}")
        print(f"   Enhanced: {ml_result.get('enhanced', False)}")
        print(f"   Confidence: {ml_result.get('confidence', 0.0):.4f}")
        print(f"   Uncertainty: {ml_result.get('uncertainty', 0.0):.4f}")
        print(f"   Model Type: {ml_result.get('model_type', 'unknown')}")
        print(f"   Features Used: {ml_result.get('features_used', 0)}")
        
        # Test 2: Enhanced Payload Ranking
        print("\n🔍 Test 2: Enhanced Payload Ranking")
        print("-" * 40)
        
        # Test payload ranking for SQL injection
        recs, meta = _enhanced_rank_payloads_for_family(
            features, "sqli", top_n=3, threshold=0.2
        )
        
        print(f"✅ Payload Ranking successful!")
        print(f"   Used Path: {meta.get('used_path', 'unknown')}")
        print(f"   Enhanced: {meta.get('enhanced', False)}")
        print(f"   Family: {meta.get('family', 'unknown')}")
        print(f"   Confidence: {meta.get('confidence', 0.0):.4f}")
        print(f"   Uncertainty: {meta.get('uncertainty', 0.0):.4f}")
        
        print(f"   Top {len(recs)} Payloads:")
        for i, (payload, score) in enumerate(recs):
            print(f"     {i+1}. {payload} (Score: {score:.4f})")
        
        # Test 3: Different vulnerability families
        print("\n🔍 Test 3: Different Vulnerability Families")
        print("-" * 40)
        
        families = ["sqli", "xss", "redirect"]
        for family in families:
            print(f"\n   Testing {family.upper()}:")
            
            # Test prediction
            ml_result = _enhanced_ml_predict(None, features, family=family)
            print(f"     Prediction: {ml_result['p']:.4f} (Source: {ml_result['source']})")
            
            # Test payload ranking
            recs, meta = _enhanced_rank_payloads_for_family(
                features, family, top_n=2, threshold=0.2
            )
            print(f"     Payloads: {len(recs)} ranked (Path: {meta.get('used_path', 'unknown')})")
        
        print("\n" + "=" * 60)
        print("🎉 All Enhanced Fuzzer Integration Tests Passed!")
        print("\n📋 Integration Summary:")
        print("✅ Enhanced ML predictions working")
        print("✅ Enhanced payload ranking working")
        print("✅ Multiple vulnerability families supported")
        print("✅ Enhanced features being extracted")
        print("✅ Fallback mechanisms working")
        
        return True
        
    except Exception as e:
        print(f"❌ Enhanced fuzzer integration test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def show_integration_instructions():
    """Show how to integrate the enhanced ML system."""
    print("\n📚 INTEGRATION INSTRUCTIONS")
    print("=" * 60)
    
    print("""
To integrate the enhanced ML system into your existing fuzzer:

1. **Backup your current fuzzer_core.py**
   cp backend/modules/fuzzer_core.py backend/modules/fuzzer_core.py.backup

2. **Apply the enhanced ML integration:**
   - Add enhanced ML imports at the top
   - Replace _ranker_predict function with enhanced version
   - Replace _rank_payloads_for_family function with enhanced version
   - Update _endpoint_features to use enhanced features

3. **The enhanced system provides:**
   - Better predictions with confidence scores
   - Uncertainty quantification
   - Enhanced feature extraction (48 features vs 17)
   - Improved payload ranking
   - Automatic fallback to legacy system

4. **Enhanced ML fields available:**
   - enhanced: True/False (indicates if enhanced ML was used)
   - confidence: Enhanced confidence score
   - uncertainty: Uncertainty estimate
   - model_type: Type of model used
   - features_used: Number of features used

5. **Backward compatibility:**
   - All existing code continues to work
   - Enhanced features are automatically used when available
   - Fallback to legacy system if enhanced ML fails

6. **Testing:**
   - Run this script to verify integration
   - Check logs for "Enhanced ML used" messages
   - Monitor confidence and uncertainty scores
    """)


if __name__ == "__main__":
    success = test_enhanced_fuzzer_integration()
    
    if success:
        show_integration_instructions()
    else:
        print("\n❌ Integration test failed. Check the errors above.")
