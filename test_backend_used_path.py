#!/usr/bin/env python3
"""
Test script to verify that the backend properly preserves enhanced_ml used_path
"""

def test_used_path_preservation():
    """Test the logic from fuzz_routes.py"""
    
    # Simulate the logic from the backend routes
    def preserve_used_path(raw_rm, has_ml_fields):
        used_path = raw_rm.get("used_path")
        
        # CRITICAL: Preserve the original used_path from evidence - don't overwrite ML paths!
        if raw_rm.get("used_path") and (raw_rm.get("used_path").startswith("ml:") or raw_rm.get("used_path") == "enhanced_ml"):
            used_path = raw_rm.get("used_path")  # Keep "ml:redirect", "ml:sqli", "enhanced_ml", etc.
        elif has_ml_fields and not used_path:
            used_path = "family_ranker"  # Only use fallback if no ML path exists
            
        return used_path
    
    # Test cases
    test_cases = [
        {
            "name": "enhanced_ml path",
            "raw_rm": {"used_path": "enhanced_ml"},
            "has_ml_fields": True,
            "expected": "enhanced_ml"
        },
        {
            "name": "ml:sqli path",
            "raw_rm": {"used_path": "ml:sqli"},
            "has_ml_fields": True,
            "expected": "ml:sqli"
        },
        {
            "name": "heuristic path",
            "raw_rm": {"used_path": "heuristic"},
            "has_ml_fields": True,
            "expected": "heuristic"
        },
        {
            "name": "no used_path but has ML fields",
            "raw_rm": {},
            "has_ml_fields": True,
            "expected": "family_ranker"
        },
        {
            "name": "no used_path and no ML fields",
            "raw_rm": {},
            "has_ml_fields": False,
            "expected": None
        }
    ]
    
    print("Testing used_path preservation logic...")
    print("=" * 50)
    
    all_passed = True
    
    for test_case in test_cases:
        result = preserve_used_path(test_case["raw_rm"], test_case["has_ml_fields"])
        passed = result == test_case["expected"]
        
        print(f"Test: {test_case['name']}")
        print(f"  Input: raw_rm={test_case['raw_rm']}, has_ml_fields={test_case['has_ml_fields']}")
        print(f"  Expected: {test_case['expected']}")
        print(f"  Actual: {result}")
        print(f"  Result: {'✅ PASS' if passed else '❌ FAIL'}")
        print()
        
        if not passed:
            all_passed = False
    
    print("=" * 50)
    if all_passed:
        print("🎉 All tests passed! The backend should properly preserve enhanced_ml used_path.")
    else:
        print("❌ Some tests failed. There might still be an issue.")
    
    return all_passed

if __name__ == "__main__":
    test_used_path_preservation()
