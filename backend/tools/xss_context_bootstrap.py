#!/usr/bin/env python3
"""
XSS Context Auto-label Bootstrap Tool

Reads NDJSON events from XSS probes and produces labeled CSV for ML training.
Uses heuristics to automatically label context and escaping types.
"""

import json
import csv
import re
import html
import urllib.parse
from pathlib import Path
from typing import List, Dict, Any, Tuple
from backend.app_state import DATA_DIR

CANARY = "EliseXSSCanary123"

def extract_context_features(text_window: str, canary_pos: int) -> Dict[str, Any]:
    """Extract features for context classification."""
    features = {
        "has_script_tag": False,
        "has_style_tag": False,
        "has_quotes": False,
        "has_equals": False,
        "has_angle_brackets": False,
        "has_url_attrs": False,
        "has_style_attr": False,
        "quote_type": "",
        "attr_name": "",
        "before_canary": "",
        "after_canary": ""
    }
    
    # Check for script tags
    if '<script' in text_window.lower():
        features["has_script_tag"] = True
    
    # Check for style tags
    if '<style' in text_window.lower() or 'style=' in text_window.lower():
        features["has_style_tag"] = True
    
    # Check for quotes
    if '"' in text_window or "'" in text_window:
        features["has_quotes"] = True
        if '"' in text_window:
            features["quote_type"] = "double"
        elif "'" in text_window:
            features["quote_type"] = "single"
    
    # Check for equals (attribute indicator)
    if '=' in text_window:
        features["has_equals"] = True
    
    # Check for angle brackets (HTML indicator)
    if '<' in text_window and '>' in text_window:
        features["has_angle_brackets"] = True
    
    # Check for URL attributes
    url_attrs = ['href=', 'src=', 'action=', 'formaction=']
    for attr in url_attrs:
        if attr in text_window.lower():
            features["has_url_attrs"] = True
            break
    
    # Check for style attribute
    if 'style=' in text_window.lower():
        features["has_style_attr"] = True
    
    # Extract attribute name if present
    attr_match = re.search(r'(\w+)=["\']([^"\']*' + re.escape(CANARY) + r'[^"\']*)["\']', text_window)
    if attr_match:
        features["attr_name"] = attr_match.group(1)
    
    # Extract context around canary
    if canary_pos >= 0:
        features["before_canary"] = text_window[max(0, canary_pos - 20):canary_pos]
        features["after_canary"] = text_window[canary_pos + len(CANARY):canary_pos + len(CANARY) + 20]
    
    return features

def label_context_heuristic(features: Dict[str, Any], text_window: str, canary_pos: int) -> str:
    """Label context using heuristics."""
    
    # JavaScript string context
    if features["has_script_tag"] and features["has_quotes"]:
        # Check if canary is inside quotes within script
        script_start = text_window.rfind('<script', 0, canary_pos)
        script_end = text_window.find('</script>', canary_pos)
        if script_start != -1 and script_end != -1:
            script_content = text_window[script_start:script_end]
            canary_in_script = script_content.find(CANARY)
            if canary_in_script != -1:
                before_canary = script_content[max(0, canary_in_script - 10):canary_in_script]
                after_canary = script_content[canary_in_script + len(CANARY):canary_in_script + len(CANARY) + 10]
                if ('"' in before_canary and '"' in after_canary) or ("'" in before_canary and "'" in after_canary):
                    return "js_string"
    
    # CSS context
    if features["has_style_tag"] or features["has_style_attr"]:
        return "css"
    
    # URL context
    if features["has_url_attrs"]:
        return "url"
    
    # HTML attribute context
    if features["has_quotes"] and features["has_equals"] and features["attr_name"]:
        return "attr"
    
    # HTML body context
    if features["has_angle_brackets"]:
        return "html_body"
    
    return "unknown"

def label_escaping_heuristic(raw_reflection: str) -> str:
    """Label escaping using heuristics."""
    
    # Check for raw reflection first
    if raw_reflection == CANARY:
        return "raw"
    
    # Check for HTML escaping
    html_escaped = html.escape(CANARY)
    if raw_reflection == html_escaped:
        return "html"
    
    # Check for URL encoding
    url_encoded = urllib.parse.quote(CANARY)
    if raw_reflection == url_encoded:
        return "url"
    
    # Check for JavaScript string escaping
    js_escaped = CANARY.replace('\\', '\\\\').replace('"', '\\"').replace("'", "\\'")
    if raw_reflection == js_escaped:
        return "js"
    
    return "unknown"

def process_ndjson_file(ndjson_path: Path) -> List[Dict[str, Any]]:
    """Process NDJSON file and return labeled data."""
    labeled_data = []
    
    if not ndjson_path.exists():
        print(f"NDJSON file not found: {ndjson_path}")
        return labeled_data
    
    with open(ndjson_path, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            try:
                event = json.loads(line.strip())
                
                # Extract text window
                text_window = event["fragment_left_64"] + CANARY + event["fragment_right_64"]
                canary_pos = len(event["fragment_left_64"])
                
                # Extract features
                features = extract_context_features(text_window, canary_pos)
                
                # Label using heuristics
                label_context = label_context_heuristic(features, text_window, canary_pos)
                label_escaping = label_escaping_heuristic(event["raw_reflection"])
                
                # Create labeled row
                labeled_row = {
                    "label_context": label_context,
                    "label_escaping": label_escaping,
                    "text_window": text_window,
                    "canary_pos": canary_pos,
                    "raw_reflection": event["raw_reflection"],
                    "in_script_tag": event.get("in_script_tag", False),
                    "in_attr": event.get("in_attr", False),
                    "attr_name": event.get("attr_name", ""),
                    "in_style": event.get("in_style", False),
                    "attr_quote": event.get("attr_quote", ""),
                    "content_type": event.get("content_type", ""),
                    "url": event.get("url", ""),
                    "method": event.get("method", ""),
                    "param_in": event.get("param_in", ""),
                    "param": event.get("param", ""),
                    "rule_context": event.get("rule_context", ""),
                    "rule_escaping": event.get("rule_escaping", ""),
                    "rule_conf": event.get("rule_conf", 0.0),
                    # Feature flags
                    "has_script_tag": features["has_script_tag"],
                    "has_style_tag": features["has_style_tag"],
                    "has_quotes": features["has_quotes"],
                    "has_equals": features["has_equals"],
                    "has_angle_brackets": features["has_angle_brackets"],
                    "has_url_attrs": features["has_url_attrs"],
                    "has_style_attr": features["has_style_attr"],
                    "quote_type": features["quote_type"],
                    "attr_name_feature": features["attr_name"],
                    "before_canary": features["before_canary"],
                    "after_canary": features["after_canary"]
                }
                
                labeled_data.append(labeled_row)
                
            except json.JSONDecodeError as e:
                print(f"Error parsing line {line_num}: {e}")
                continue
            except KeyError as e:
                print(f"Missing key in line {line_num}: {e}")
                continue
    
    return labeled_data

def save_labeled_csv(labeled_data: List[Dict[str, Any]], output_path: Path) -> None:
    """Save labeled data to CSV file."""
    if not labeled_data:
        print("No labeled data to save")
        return
    
    fieldnames = labeled_data[0].keys()
    
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(labeled_data)
    
    print(f"Saved {len(labeled_data)} labeled examples to {output_path}")

def main():
    """Main function to process all job directories."""
    jobs_dir = DATA_DIR / "jobs"
    
    if not jobs_dir.exists():
        print(f"Jobs directory not found: {jobs_dir}")
        return
    
    all_labeled_data = []
    
    # Process all job directories
    for job_dir in jobs_dir.iterdir():
        if job_dir.is_dir():
            ndjson_path = job_dir / "xss_context_events.ndjson"
            if ndjson_path.exists():
                print(f"Processing {job_dir.name}...")
                labeled_data = process_ndjson_file(ndjson_path)
                all_labeled_data.extend(labeled_data)
                print(f"  Found {len(labeled_data)} events")
    
    if all_labeled_data:
        # Save combined labeled data
        output_path = DATA_DIR / "xss_context_labeled.csv"
        save_labeled_csv(all_labeled_data, output_path)
        
        # Print statistics
        context_counts = {}
        escaping_counts = {}
        
        for row in all_labeled_data:
            context = row["label_context"]
            escaping = row["label_escaping"]
            
            context_counts[context] = context_counts.get(context, 0) + 1
            escaping_counts[escaping] = escaping_counts.get(escaping, 0) + 1
        
        print("\nContext distribution:")
        for context, count in sorted(context_counts.items()):
            print(f"  {context}: {count}")
        
        print("\nEscaping distribution:")
        for escaping, count in sorted(escaping_counts.items()):
            print(f"  {escaping}: {count}")
    else:
        print("No XSS context events found to process")

if __name__ == "__main__":
    main()
