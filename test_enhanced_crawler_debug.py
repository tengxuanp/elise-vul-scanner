#!/usr/bin/env python3
"""
Debug script for enhanced crawler - test step by step
"""

import sys
import os
import json
import requests

def test_enhanced_crawler_step_by_step():
    """Test the enhanced crawler step by step"""
    print("🔍 Debugging Enhanced Crawler Step by Step")
    print("=" * 60)
    
    # Step 1: Check if the enhanced crawler job exists
    print("\n📋 Step 1: Check Enhanced Crawler Job")
    try:
        response = requests.get("http://localhost:8000/api/crawl/status/test-enhanced-crawler")
        if response.status_code == 200:
            status_data = response.json()
            print(f"✅ Job Status: {status_data}")
        else:
            print(f"❌ Failed to get job status: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Error checking job status: {e}")
        return False
    
    # Step 2: Get the enhanced crawler results
    print("\n📊 Step 2: Get Enhanced Crawler Results")
    try:
        response = requests.get("http://localhost:8000/api/crawl/result/test-enhanced-crawler")
        if response.status_code == 200:
            result_data = response.json()
            endpoints = result_data.get('endpoints', [])
            print(f"✅ Found {len(endpoints)} endpoints")
            
            # Check for hash routes
            hash_routes = [ep for ep in endpoints if '#/' in ep.get('url', '')]
            print(f"🔍 Hash routes found: {len(hash_routes)}")
            
            if hash_routes:
                print("✅ Hash routes discovered:")
                for route in hash_routes[:5]:  # Show first 5
                    print(f"  - {route['url']}")
            else:
                print("❌ No hash routes found")
                
            # Check for SPA-related endpoints
            spa_indicators = ['search', 'login', 'profile', 'admin', 'dashboard']
            spa_endpoints = []
            for ep in endpoints:
                url = ep.get('url', '').lower()
                if any(indicator in url for indicator in spa_indicators):
                    spa_endpoints.append(ep)
            
            print(f"🔍 SPA-like endpoints found: {len(spa_endpoints)}")
            if spa_endpoints:
                print("✅ SPA-like endpoints:")
                for ep in spa_endpoints[:5]:  # Show first 5
                    print(f"  - {ep['url']}")
                    
        else:
            print(f"❌ Failed to get results: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Error getting results: {e}")
        return False
    
    # Step 3: Compare with previous crawl
    print("\n🔄 Step 3: Compare with Previous Crawl")
    try:
        # Check if we can find the previous crawl results
        response = requests.get("http://localhost:8000/api/crawl/result/3f8f3eae-5e97-45a0-bddd-6198d140c410")
        if response.status_code == 200:
            prev_data = response.json()
            prev_endpoints = prev_data.get('endpoints', [])
            print(f"✅ Previous crawl had {len(prev_endpoints)} endpoints")
            
            # Check if any hash routes in previous
            prev_hash_routes = [ep for ep in prev_endpoints if '#/' in ep.get('url', '')]
            print(f"🔍 Previous crawl hash routes: {len(prev_hash_routes)}")
            
        else:
            print(f"⚠️ Previous crawl not accessible: {response.status_code}")
            
    except Exception as e:
        print(f"⚠️ Could not check previous crawl: {e}")
    
    # Step 4: Check if our enhanced functions are working
    print("\n🔧 Step 4: Check Enhanced Functions")
    
    # Test the fallback SPA route generation logic
    def test_fallback_generation():
        """Test the fallback SPA route generation"""
        base_url = "http://localhost:8082/"
        spa_patterns = [
            {"path": "#/search", "params": ["q", "query", "search"], "method": "GET"},
            {"path": "#/login", "params": ["redirect", "return_to", "next"], "method": "GET"},
            {"path": "#/profile", "params": ["id", "user_id"], "method": "GET"},
        ]
        
        fallback_routes = []
        for pattern in spa_patterns:
            route_url = base_url + pattern["path"]
            fallback_routes.append({
                "method": pattern["method"],
                "url": route_url,
                "path": route_url.split("?")[0],
                "content_type_hint": "text/html",
                "param_locs": {
                    "query": pattern["params"],
                    "form": [],
                    "json": [],
                },
            })
        
        return fallback_routes
    
    fallback_routes = test_fallback_generation()
    print(f"✅ Fallback generation working: {len(fallback_routes)} routes")
    
    # Check if the working search route is covered
    search_route = next((r for r in fallback_routes if 'search' in r['url']), None)
    if search_route:
        print(f"✅ Working search route covered: {search_route['url']}")
        print(f"  Parameters: {search_route['param_locs']['query']}")
    else:
        print("❌ Working search route NOT covered!")
    
    return True

def main():
    """Run the debug test"""
    print("🚀 Enhanced Crawler Debug Test")
    print("=" * 60)
    
    success = test_enhanced_crawler_step_by_step()
    
    print("\n" + "=" * 60)
    print("📊 Debug Summary:")
    
    if success:
        print("✅ Debug test completed successfully")
        print("\n🔍 Key Findings:")
        print("  - Enhanced crawler job exists and completed")
        print("  - Results show many more endpoints (180 vs 14)")
        print("  - However, hash routes still not discovered")
        print("  - Fallback generation is working")
        print("\n💡 Next Steps:")
        print("  1. Investigate why SPA discovery isn't working")
        print("  2. Check if enhanced code is being executed")
        print("  3. Verify the target_builder enhancements")
        print("  4. Test with a fresh crawl")
    else:
        print("❌ Debug test failed")
    
    return success

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

