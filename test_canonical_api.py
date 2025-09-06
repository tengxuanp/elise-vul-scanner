#!/usr/bin/env python3
"""
Test script for the canonicalized API endpoints
"""

import requests
import json
import time

def test_healthz():
    """Test the healthz endpoint"""
    print("🏥 Testing /api/healthz...")
    try:
        response = requests.get("http://localhost:8000/api/healthz")
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Health check: ok={data['ok']}, browser={data['browser_pool_ready']}, ml={data['ml_ready']}")
            print(f"📋 Routes: {len(data['routes'])} endpoints")
            return True
        else:
            print(f"❌ Health check failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Health check error: {e}")
        return False

def test_crawl():
    """Test the crawl endpoint"""
    print("\n🕷️ Testing /api/crawl...")
    try:
        payload = {
            "target_url": "http://httpbin.org/get",
            "max_endpoints": 3
        }
        response = requests.post("http://localhost:8000/api/crawl", json=payload)
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Crawl: {len(data['endpoints'])} endpoints found")
            print(f"📊 Meta: pages={data['meta']['pagesVisited']}, emitted={data['meta']['emitted']}")
            return data['endpoints']
        else:
            print(f"❌ Crawl failed: {response.status_code} - {response.text}")
            return []
    except Exception as e:
        print(f"❌ Crawl error: {e}")
        return []

def test_ml_predict(endpoints):
    """Test the ML predict endpoint"""
    print("\n🧠 Testing /api/ml-predict...")
    if not endpoints:
        print("⚠️ No endpoints to predict")
        return []
    
    try:
        payload = {"endpoints": endpoints}
        response = requests.post("http://localhost:8000/api/ml-predict", json=payload)
        if response.status_code == 200:
            predictions = response.json()
            print(f"✅ ML Predict: {len(predictions)} predictions")
            for pred in predictions:
                print(f"  📍 {pred['family']} (confidence: {pred['confidence']:.2f})")
            return predictions
        else:
            print(f"❌ ML Predict failed: {response.status_code} - {response.text}")
            return []
    except Exception as e:
        print(f"❌ ML Predict error: {e}")
        return []

def test_fuzz(predictions):
    """Test the fuzz endpoint"""
    print("\n🧪 Testing /api/fuzz...")
    if not predictions:
        print("⚠️ No predictions to fuzz")
        return []
    
    try:
        payload = {"predictions": predictions}
        response = requests.post("http://localhost:8000/api/fuzz", json=payload)
        if response.status_code == 200:
            results = response.json()
            print(f"✅ Fuzz: {len(results)} results")
            for result in results:
                print(f"  🎯 {result['family']} - CVSS: {result['cvss']['base']} ({result['cvss']['severity']})")
            return results
        else:
            print(f"❌ Fuzz failed: {response.status_code} - {response.text}")
            return []
    except Exception as e:
        print(f"❌ Fuzz error: {e}")
        return []

def test_exploit(fuzz_result):
    """Test the exploit endpoint"""
    print("\n💥 Testing /api/exploit...")
    if not fuzz_result:
        print("⚠️ No fuzz result to exploit")
        return None
    
    try:
        response = requests.post("http://localhost:8000/api/exploit", json=fuzz_result)
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Exploit: confirmed={result.get('confirmed', False)}")
            return result
        else:
            print(f"❌ Exploit failed: {response.status_code} - {response.text}")
            return None
    except Exception as e:
        print(f"❌ Exploit error: {e}")
        return None

def main():
    """Run all tests"""
    print("🚀 Testing Canonical API Endpoints")
    print("=" * 50)
    
    # Test healthz
    if not test_healthz():
        print("❌ Health check failed, stopping tests")
        return
    
    # Test crawl
    endpoints = test_crawl()
    
    # Test ML predict
    predictions = test_ml_predict(endpoints)
    
    # Test fuzz
    fuzz_results = test_fuzz(predictions)
    
    # Test exploit (with first result if available)
    if fuzz_results:
        test_exploit(fuzz_results[0])
    
    print("\n" + "=" * 50)
    print("🎉 Canonical API testing complete!")

if __name__ == "__main__":
    main()

