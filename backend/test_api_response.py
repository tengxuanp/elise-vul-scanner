#!/usr/bin/env python3
"""
Test to see what the API is actually returning to the frontend
"""

import sys
import os
import json
import requests
from pathlib import Path

# Add the backend directory to Python path
backend_dir = Path(__file__).parent
sys.path.insert(0, str(backend_dir))

def test_fuzz_api_response():
    """Test what the fuzz API is actually returning"""
    
    print("=== Testing Fuzz API Response ===")
    
    # Try to get the most recent fuzz results
    try:
        # First, get available jobs
        response = requests.get("http://localhost:8000/api/jobs")
        if response.status_code == 200:
            jobs = response.json()
            if jobs:
                latest_job = jobs[-1] if isinstance(jobs, list) else jobs
                job_id = latest_job.get('id') if isinstance(latest_job, dict) else latest_job
                print(f"Latest job ID: {job_id}")
                
                # Get fuzz results for this job
                fuzz_response = requests.get(f"http://localhost:8000/api/fuzz/by_job/{job_id}")
                if fuzz_response.status_code == 200:
                    results = fuzz_response.json()
                    print(f"Got {len(results) if isinstance(results, list) else 1} results")
                    
                    # Examine the first few results for ranker_meta
                    for i, result in enumerate(results[:3] if isinstance(results, list) else [results]):
                        print(f"\n--- Result {i+1} ---")
                        print(f"URL: {result.get('url', 'N/A')}")
                        print(f"Param: {result.get('param', 'N/A')}")
                        print(f"Family: {result.get('family', 'N/A')}")
                        
                        # Check ranker_meta structure
                        ranker_meta = result.get('ranker_meta', {})
                        print(f"Ranker Meta Keys: {list(ranker_meta.keys())}")
                        print(f"  ranker_score: {ranker_meta.get('ranker_score')}")
                        print(f"  family_probs: {ranker_meta.get('family_probs')}")
                        print(f"  family_chosen: {ranker_meta.get('family_chosen')}")
                        print(f"  model_ids: {ranker_meta.get('model_ids')}")
                        print(f"  used_path: {ranker_meta.get('used_path')}")
                        print(f"  enhanced_ml: {ranker_meta.get('enhanced_ml')}")
                        print(f"  is_ml_prediction: {ranker_meta.get('is_ml_prediction')}")
                        
                        # Check if there are ML indicators at the top level
                        print(f"Top-level ml field: {result.get('ml')}")
                        print(f"Top-level ranker field: {result.get('ranker')}")
                        
                else:
                    print(f"Fuzz API returned {fuzz_response.status_code}: {fuzz_response.text}")
            else:
                print("No jobs found")
        else:
            print(f"Jobs API returned {response.status_code}: {response.text}")
            
    except Exception as e:
        print(f"Error testing API: {e}")

if __name__ == "__main__":
    test_fuzz_api_response()
