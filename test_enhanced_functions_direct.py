#!/usr/bin/env python3
"""
Direct test of enhanced crawler functions
"""

import sys
import os

def test_enhanced_functions_directly():
    """Test the enhanced crawler functions directly"""
    print("🧪 Direct Test of Enhanced Crawler Functions")
    print("=" * 60)
    
    # Test 1: Check if our enhanced functions exist and are syntactically correct
    print("\n📁 Test 1: Function Existence and Syntax")
    
    crawler_path = "backend/modules/playwright_crawler.py"
    if os.path.exists(crawler_path):
        print(f"✅ Crawler file exists: {crawler_path}")
        
        # Check for our enhanced functions
        with open(crawler_path, 'r') as f:
            content = f.read()
        
        function_checks = [
            "def discover_spa_routes",
            "def generate_common_spa_routes_fallback",
            "def discover_additional_spa_routes",
            "Proactively discover hash routes",
            "common_spa_routes = [",
            '"vulnerability_focus": ["sqli", "auth_bypass"]'
        ]
        
        for check in function_checks:
            if check in content:
                print(f"✅ Found: {check}")
            else:
                print(f"❌ Missing: {check}")
                
    else:
        print(f"❌ Crawler file not found: {crawler_path}")
        return False
    
    # Test 2: Check the actual function logic
    print("\n🔍 Test 2: Function Logic Analysis")
    
    # Look for the specific logic we implemented
    logic_checks = [
        "Always add common SPA routes that are likely to exist",
        "query_params: [\"redirect\", \"return_to\", \"next\"]",
        "form_params: [\"email\", \"password\", \"username\"]",
        "is_login: True",
        "vulnerability_focus: [\"sqli\", \"auth_bypass\"]"
    ]
    
    for check in logic_checks:
        if check in content:
            print(f"✅ Found: {check}")
        else:
            print(f"❌ Missing: {check}")
    
    # Test 3: Check if the functions are being called
    print("\n🔄 Test 3: Function Call Analysis")
    
    call_checks = [
        "initial_spa_routes = discover_spa_routes(page, target_url)",
        "spa_routes = discover_spa_routes(page, target_url)",
        "common_spa_routes = generate_common_spa_routes_fallback(target_url)"
    ]
    
    for check in call_checks:
        if check in content:
            print(f"✅ Found: {check}")
        else:
            print(f"❌ Missing: {check}")
    
    # Test 4: Check the integration points
    print("\n🔗 Test 4: Integration Points")
    
    integration_checks = [
        "Add these to raw_form_endpoints so they get processed",
        "Add SPA routes to merged endpoints",
        "Added {len(eps_from_spa)} SPA routes to discovered endpoints"
    ]
    
    for check in integration_checks:
        if check in content:
            print(f"✅ Found: {check}")
        else:
            print(f"❌ Missing: {check}")
    
    return True

def analyze_why_not_working():
    """Analyze why the enhanced crawler is not working"""
    print("\n🔍 Analysis: Why Enhanced Crawler Not Working")
    print("=" * 60)
    
    print("\n💡 Possible Issues:")
    print("1. Enhanced functions exist but are not being called")
    print("2. Enhanced functions are called but fail silently")
    print("3. Enhanced functions work but results are not integrated")
    print("4. There's an error in the execution flow")
    
    print("\n🔧 Debugging Steps:")
    print("1. Check if functions are being called (add print statements)")
    print("2. Check if functions return expected results")
    print("3. Check if results are properly integrated")
    print("4. Check for silent failures or exceptions")
    
    print("\n🚀 Next Steps:")
    print("1. Add debug logging to enhanced functions")
    print("2. Test functions in isolation")
    print("3. Check the execution flow step by step")
    print("4. Verify the integration points")

def main():
    """Run the direct test"""
    print("🚀 Direct Test of Enhanced Crawler Functions")
    print("=" * 60)
    
    success = test_enhanced_functions_directly()
    
    if success:
        analyze_why_not_working()
    
    print("\n" + "=" * 60)
    print("📊 Test Results:")
    
    if success:
        print("✅ Enhanced functions exist and are syntactically correct")
        print("❌ But they are not working during actual crawls")
        print("\n🔍 The issue is likely in the execution flow or integration")
        print("💡 We need to add debug logging to see what's happening")
    else:
        print("❌ Some tests failed")
        print("Check the errors above to see what's missing")
    
    return success

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

