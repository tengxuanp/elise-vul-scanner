#!/usr/bin/env python3
"""
Test the complete ML-based vulnerability scanning flow:
1. Dynamic Crawling
2. ML Prediction & Payload Recommendation  
3. Real Fuzzing
"""

import requests
import json
import time

def test_complete_flow():
    print("🚀 Testing Complete ML-Based Vulnerability Scanning Flow")
    print("=" * 60)
    
    base_url = "http://localhost:8000/api"
    target_url = "http://localhost:8082/"
    
    # Step 1: Dynamic Crawling
    print("\n📡 Step 1: Dynamic Crawling")
    print("-" * 30)
    
    crawl_response = requests.post(f"{base_url}/crawl", json={
        "target_url": target_url,
        "max_endpoints": 10
    })
    
    if crawl_response.status_code != 200:
        print(f"❌ Crawling failed: {crawl_response.status_code}")
        return
    
    crawl_data = crawl_response.json()
    endpoints = crawl_data.get("endpoints", [])
    print(f"✅ Discovered {len(endpoints)} endpoints")
    
    if not endpoints:
        print("❌ No endpoints discovered. Cannot proceed.")
        return
    
    # Show first few endpoints
    for i, endpoint in enumerate(endpoints[:3]):
        print(f"  {i+1}. {endpoint['url']} ({endpoint['method']}) param={endpoint['param']}")
    
    # Step 2: ML Prediction
    print("\n🧠 Step 2: ML Prediction & Payload Recommendation")
    print("-" * 50)
    
    # First train models
    print("Training ML models...")
    train_response = requests.post(f"{base_url}/train-models", json={})
    if train_response.status_code != 200:
        print(f"❌ Model training failed: {train_response.status_code}")
        return
    
    train_data = train_response.json()
    print(f"✅ Models trained: {train_data['message']}")
    
    # Now predict vulnerabilities
    predict_response = requests.post(f"{base_url}/ml-predict", json={
        "endpoints": endpoints[:3]  # Test first 3 endpoints
    })
    
    if predict_response.status_code != 200:
        print(f"❌ ML prediction failed: {predict_response.status_code}")
        return
    
    predict_data = predict_response.json()
    recommendations = predict_data.get("recommendations", [])
    print(f"✅ ML found {len(recommendations)} potentially vulnerable endpoints")
    
    for i, rec in enumerate(recommendations):
        endpoint = rec["endpoint"]
        vuln_type = rec["predicted_vulnerability"]
        confidence = rec["confidence"]
        payload_count = len(rec["recommended_payloads"])
        
        print(f"  {i+1}. {endpoint['url']}")
        print(f"     → {vuln_type.upper()} ({confidence:.1%} confidence)")
        print(f"     → {payload_count} recommended payloads")
        
        # Show top payload
        if rec["recommended_payloads"]:
            top_payload = rec["recommended_payloads"][0]
            print(f"     → Top payload: '{top_payload['payload'][:50]}...' (score: {top_payload['score']:.2f})")
    
    # Step 3: Real Fuzzing
    print("\n🎯 Step 3: Real Fuzzing")
    print("-" * 25)
    
    if not recommendations:
        print("❌ No recommendations to fuzz")
        return
    
    # Create fuzz requests from top recommendations
    fuzz_requests = []
    for rec in recommendations[:2]:  # Test first 2 recommendations
        endpoint = rec["endpoint"]
        top_payload = rec["recommended_payloads"][0]
        
        fuzz_requests.append({
            "endpoint": endpoint,
            "payload": top_payload["payload"]
        })
    
    print(f"Testing {len(fuzz_requests)} endpoint-payload combinations...")
    
    fuzz_response = requests.post(f"{base_url}/ml-fuzz", json={
        "fuzz_requests": fuzz_requests
    })
    
    if fuzz_response.status_code != 200:
        print(f"❌ Fuzzing failed: {fuzz_response.status_code}")
        return
    
    fuzz_data = fuzz_response.json()
    results = fuzz_data.get("results", [])
    vulnerabilities_found = fuzz_data.get("vulnerabilities_found", 0)
    
    print(f"✅ Real fuzzing completed: {vulnerabilities_found} vulnerabilities found")
    
    for i, result in enumerate(results):
        endpoint = result["endpoint"]
        payload = result["payload"]
        status = result["response_status"]
        vuln_detected = result["vulnerability_detected"]
        response_time = result["response_time"]
        
        status_icon = "🔴" if vuln_detected else "🟢"
        print(f"  {i+1}. {status_icon} {endpoint['url']}")
        print(f"     → Payload: '{payload[:50]}...'")
        print(f"     → Response: {status} ({response_time:.3f}s)")
        print(f"     → Vulnerable: {'YES' if vuln_detected else 'NO'}")
        
        if vuln_detected and result.get("evidence"):
            print(f"     → Evidence: {result['evidence'][0]}")
    
    # Summary
    print("\n📊 Summary")
    print("-" * 15)
    print(f"Endpoints discovered: {len(endpoints)}")
    print(f"Vulnerabilities predicted: {len(recommendations)}")
    print(f"Real tests performed: {len(fuzz_requests)}")
    print(f"Vulnerabilities found: {vulnerabilities_found}")
    
    if vulnerabilities_found > 0:
        print("🎉 SUCCESS: Real vulnerabilities detected!")
    else:
        print("ℹ️  No vulnerabilities detected in this test")

if __name__ == "__main__":
    test_complete_flow()
