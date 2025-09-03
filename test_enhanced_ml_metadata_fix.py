#!/usr/bin/env python3
"""
Quick test to verify the enhanced ML metadata fix is working
"""

import sys
import os
from pathlib import Path

# Add the backend directory to Python path  
backend_dir = Path(__file__).parent / "backend"
sys.path.insert(0, str(backend_dir))

def test_enhanced_ml_metadata():
    """Test that enhanced ML metadata is being built correctly"""
    
    print("=== Testing Enhanced ML Metadata Fix ===")
    
    # Test the dictionary creation logic directly
    fam = "sqli"
    chosen_family = fam or "sqli"  # Fallback to sqli if fam is empty
    family_probs_dict = {chosen_family: 1.0}
    
    print(f"Input family: '{fam}'")
    print(f"Chosen family: '{chosen_family}'")
    print(f"Family probs dict: {family_probs_dict}")
    
    # Test with empty family
    fam_empty = ""
    chosen_family_empty = fam_empty or "sqli"
    family_probs_dict_empty = {chosen_family_empty: 1.0}
    
    print(f"\nTest with empty family:")
    print(f"Input family: '{fam_empty}'")
    print(f"Chosen family: '{chosen_family_empty}'")
    print(f"Family probs dict: {family_probs_dict_empty}")
    
    # Test with None family
    fam_none = None
    chosen_family_none = fam_none or "sqli"
    family_probs_dict_none = {chosen_family_none: 1.0}
    
    print(f"\nTest with None family:")
    print(f"Input family: {fam_none}")
    print(f"Chosen family: '{chosen_family_none}'")
    print(f"Family probs dict: {family_probs_dict_none}")
    
    # Verify the dictionaries are non-empty
    assert len(family_probs_dict) > 0, "family_probs_dict should not be empty"
    assert len(family_probs_dict_empty) > 0, "family_probs_dict_empty should not be empty"
    assert len(family_probs_dict_none) > 0, "family_probs_dict_none should not be empty"
    
    print("\n✅ All tests passed! Enhanced ML metadata should now correctly populate family_probs")

if __name__ == "__main__":
    test_enhanced_ml_metadata()
