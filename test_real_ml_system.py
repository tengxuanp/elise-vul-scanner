#!/usr/bin/env python3
"""
Test the new real ML-based fuzzing system
Demonstrates the flow: Crawl → ML Predict → User Choose → Real Fuzz
"""

import sys
import os
import asyncio
import json
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'backend'))

async def test_real_ml_system():
    """Test the complete real ML fuzzing system"""
    print("🚀 Testing Real ML-Based Fuzzing System")
    print("=" * 50)
    
    try:
        # Step 1: Test dynamic crawling
        print("\n📡 Step 1: Dynamic Crawling")
        from routes.enhanced_crawl_routes import discover_endpoints_dynamically
        
        base_url = "http://localhost:8082"
        print(f"🔍 Crawling: {base_url}")
        
        endpoints = discover_endpoints_dynamically(base_url)
        print(f"✅ Found {len(endpoints)} endpoints")
        
        for i, endpoint in enumerate(endpoints[:3]):  # Show first 3
            print(f"  {i+1}. {endpoint['url']} ({endpoint.get('type', 'unknown')})")
        
        if len(endpoints) > 3:
            print(f"  ... and {len(endpoints) - 3} more endpoints")
        
        # Step 2: Test ML prediction
        print("\n🧠 Step 2: ML Vulnerability Prediction")
        from modules.ml.vulnerability_predictor import VulnerabilityPredictor
        from modules.ml.payload_recommender import PayloadRecommender
        
        # Initialize ML components
        predictor = VulnerabilityPredictor()
        recommender = PayloadRecommender()
        
        # Make predictions
        predictions = predictor.predict(endpoints)
        print(f"✅ ML predictions completed for {len(predictions)} endpoints")
        
        # Show predictions
        for i, prediction in enumerate(predictions[:3]):
            endpoint = prediction["endpoint"]
            pred_type = prediction["predicted_type"]
            confidence = prediction["confidence"]
            print(f"  {i+1}. {endpoint['url']} → {pred_type} (confidence: {confidence:.2f})")
        
        # Step 3: Test payload recommendations
        print("\n🎯 Step 3: ML Payload Recommendations")
        
        recommendations = []
        for prediction in predictions:
            if prediction["predicted_type"] != "none":
                endpoint = prediction["endpoint"]
                vuln_type = prediction["predicted_type"]
                
                payloads = recommender.recommend_payloads(endpoint, vuln_type, top_k=3)
                if payloads:
                    recommendations.append({
                        "endpoint": endpoint,
                        "vulnerability_type": vuln_type,
                        "payloads": payloads
                    })
        
        print(f"✅ Generated payload recommendations for {len(recommendations)} endpoints")
        
        # Show recommendations
        for i, rec in enumerate(recommendations[:2]):
            endpoint = rec["endpoint"]
            vuln_type = rec["vulnerability_type"]
            payloads = rec["payloads"]
            print(f"  {i+1}. {endpoint['url']} ({vuln_type})")
            for j, payload in enumerate(payloads[:2]):
                print(f"     - {payload['payload']} (score: {payload['score']:.2f})")
        
        # Step 4: Test real fuzzing
        print("\n🔥 Step 4: Real HTTP Fuzzing")
        from modules.real_fuzzer import RealHTTPFuzzer
        
        fuzzer = RealHTTPFuzzer()
        
        # Test a few endpoint-payload combinations
        fuzz_results = []
        for rec in recommendations[:2]:  # Test first 2 recommendations
            endpoint = rec["endpoint"]
            payload = rec["payloads"][0]  # Use top payload
            
            print(f"🎯 Fuzzing: {endpoint['url']} with {payload['payload'][:30]}...")
            
            result = fuzzer.fuzz_endpoint(endpoint, payload["payload"])
            fuzz_results.append(result)
            
            status = "VULNERABLE" if result.vulnerability_detected else "SAFE"
            print(f"   Result: {result.response_status} - {status} (confidence: {result.confidence_score:.2f})")
        
        # Summary
        print("\n📊 Summary")
        print("=" * 30)
        print(f"✅ Endpoints discovered: {len(endpoints)}")
        print(f"✅ ML predictions made: {len(predictions)}")
        print(f"✅ Payload recommendations: {len(recommendations)}")
        print(f"✅ Real fuzzing tests: {len(fuzz_results)}")
        
        vulnerabilities_found = sum(1 for r in fuzz_results if r.vulnerability_detected)
        print(f"🎯 Vulnerabilities detected: {vulnerabilities_found}")
        
        print("\n🎉 Real ML System Test Complete!")
        return True
        
    except Exception as e:
        print(f"❌ Error testing ML system: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = asyncio.run(test_real_ml_system())
    if success:
        print("\n✅ All tests passed! The real ML system is working.")
    else:
        print("\n❌ Some tests failed. Check the errors above.")
