#!/usr/bin/env python3
"""
Debug script to examine evidence data structure
"""

import os
import json
from pathlib import Path

# Set environment variables for ML
os.environ["ELISE_USE_ML"] = "1"
os.environ["ELISE_ML_DEBUG"] = "1"
os.environ["ELISE_ML_MODEL_DIR"] = "/Users/raphaelpang/code/elise/backend/modules/ml"

def examine_evidence_files():
    """Examine evidence files to see the data structure"""
    
    # Look for evidence files
    data_dir = Path("/Users/raphaelpang/code/elise/data")
    jobs_dir = data_dir / "jobs"
    
    if not jobs_dir.exists():
        print(f"Jobs directory not found: {jobs_dir}")
        return
    
    print("Found jobs directory, looking for evidence files...")
    
    # Find the most recent job
    job_dirs = [d for d in jobs_dir.iterdir() if d.is_dir()]
    if not job_dirs:
        print("No job directories found")
        return
    
    # Sort by modification time, newest first
    job_dirs.sort(key=lambda x: x.stat().st_mtime, reverse=True)
    latest_job = job_dirs[0]
    
    print(f"Latest job directory: {latest_job.name}")
    
    # Look for evidence files
    evidence_files = list(latest_job.rglob("*.jsonl"))
    if not evidence_files:
        print("No evidence files found")
        return
    
    print(f"Found {len(evidence_files)} evidence files")
    
    # Examine the first few lines of each evidence file
    for evidence_file in evidence_files[:3]:  # Look at first 3 files
        print(f"\n--- Examining {evidence_file.name} ---")
        
        try:
            with open(evidence_file, 'r') as f:
                lines = f.readlines()[:5]  # First 5 lines
                
            for i, line in enumerate(lines):
                try:
                    data = json.loads(line.strip())
                    
                    # Look for ranker-related fields
                    ranker_fields = {}
                    for key in ['ranker_used_path', 'ranker_meta', 'used_path']:
                        if key in data:
                            ranker_fields[key] = data[key]
                    
                    if ranker_fields:
                        print(f"  Line {i+1}: {ranker_fields}")
                    else:
                        print(f"  Line {i+1}: No ranker fields found")
                        
                except json.JSONDecodeError:
                    print(f"  Line {i+1}: Invalid JSON")
                    
        except Exception as e:
            print(f"  Error reading file: {e}")

if __name__ == "__main__":
    examine_evidence_files()
