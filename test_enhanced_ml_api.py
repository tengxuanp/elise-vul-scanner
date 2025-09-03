#!/usr/bin/env python3
"""
Test script to verify the enhanced ML API is working with the metadata fix
"""
import requests
import json
import sys

def test_backend_health():
    """Test if backend is responding"""
    try:
        response = requests.get("http://localhost:8000/api/evidence")
        print(f"Backend status: {response.status_code}")
        return response.status_code == 200
    except Exception as e:
        print(f"Backend not responding: {e}")
        return False

def test_enhanced_ml_scoring():
    """Test enhanced ML scoring directly"""
    try:
        # Test data that should trigger enhanced ML
        test_payload = {
            "url": "http://testphp.vulnweb.com/artists.php?artist=1",
            "method": "GET",
            "params": {"artist": "1"},
            "vulnerability_type": "sqli"
        }
        
        response = requests.post("http://localhost:8000/api/ml/enhanced-score", json=test_payload)
        print(f"Enhanced ML API status: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            print("Enhanced ML API Response:")
            print(json.dumps(result, indent=2))
            
            # Check for family_probs in the response
            if 'family_probs' in result:
                print(f"✅ family_probs found: {result['family_probs']}")
                if result['family_probs']:  # Check if not empty
                    print("✅ family_probs is properly populated!")
                    return True
                else:
                    print("❌ family_probs is empty")
                    return False
            else:
                print("❌ family_probs not found in response")
                return False
        else:
            print(f"API error: {response.text}")
            return False
            
    except Exception as e:
        print(f"Enhanced ML test failed: {e}")
        return False

def test_fuzz_endpoint():
    """Test the fuzz endpoint to see if enhanced ML is being used"""
    try:
        # Test fuzzing request
        fuzz_payload = {
            "target_url": "http://testphp.vulnweb.com/artists.php?artist=1",
            "method": "GET",
            "max_payloads": 5,
            "use_enhanced_ml": True
        }
        
        response = requests.post("http://localhost:8000/api/fuzz", json=fuzz_payload)
        print(f"Fuzz API status: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            print("Fuzz API Response (first result):")
            if result and len(result) > 0:
                first_result = result[0]
                print(json.dumps(first_result, indent=2))
                
                # Check metadata for enhanced ML indicators
                meta = first_result.get('metadata', {})
                if 'family_probs' in meta:
                    print(f"✅ family_probs in fuzz result: {meta['family_probs']}")
                    return True
                else:
                    print("❌ family_probs not found in fuzz result")
                    return False
            else:
                print("No fuzz results returned")
                return False
        else:
            print(f"Fuzz API error: {response.text}")
            return False
            
    except Exception as e:
        print(f"Fuzz test failed: {e}")
        return False

if __name__ == "__main__":
    print("=== Testing Enhanced ML API Fix ===")
    
    # Test backend connectivity
    if not test_backend_health():
        print("❌ Backend is not responding. Please start the backend first.")
        sys.exit(1)
    
    print("✅ Backend is responding")
    
    # Test enhanced ML scoring
    print("\n--- Testing Enhanced ML Scoring ---")
    ml_success = test_enhanced_ml_scoring()
    
    # Test fuzz endpoint
    print("\n--- Testing Fuzz Endpoint ---")
    fuzz_success = test_fuzz_endpoint()
    
    # Summary
    print("\n=== Test Summary ===")
    print(f"Enhanced ML API: {'✅ PASS' if ml_success else '❌ FAIL'}")
    print(f"Fuzz Endpoint: {'✅ PASS' if fuzz_success else '❌ FAIL'}")
    
    if ml_success or fuzz_success:
        print("\n🎉 Enhanced ML fix is working! family_probs should now be populated.")
    else:
        print("\n❌ Enhanced ML fix needs more investigation.")
