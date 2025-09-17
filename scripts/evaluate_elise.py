#!/usr/bin/env python3
"""
Elise Evaluation CLI Script

Runs comprehensive evaluation of Elise against baseline tools and generates reports.

Usage:
    python scripts/evaluate_elise.py --target https://example.com --ground-truth ground_truth.json
    python scripts/evaluate_elise.py --target https://example.com --lab-mode
    python scripts/evaluate_elise.py --target https://example.com --compare-all
"""

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Optional

# Add backend to path
sys.path.append(str(Path(__file__).parent.parent))

from backend.evaluation import (
    EvaluationConfig,
    ComparativeEvaluator,
    generate_evaluation_report,
    ReportConfig
)
from backend.evaluation.metrics import GroundTruth


def create_lab_ground_truth() -> GroundTruth:
    """Create ground truth data for the lab environment."""
    ground_truth = GroundTruth()
    
    # XSS vulnerabilities from lab
    xss_vulns = [
        ("https://localhost:5001/search", "q", "xss", "<script>alert('XSS')</script>"),
        ("https://localhost:5001/profile", "name", "xss", "\"><script>alert('XSS')</script>"),
        ("https://localhost:5001/script", "msg", "xss", "\";alert('XSS');//"),
        ("https://localhost:5001/notes", "content", "xss", "<script>alert('Stored')</script>"),
    ]
    
    for endpoint, param, vuln_type, payload in xss_vulns:
        ground_truth.add_vulnerability(endpoint, param, vuln_type, payload)
    
    # SQL injection vulnerabilities from lab
    sqli_vulns = [
        ("https://localhost:5001/product", "id", "sqli", "1 OR 1=1"),
        ("https://localhost:5001/login", "username", "sqli", "alice' OR '1'='1"),
        ("https://localhost:5001/api/search-json", "q", "sqli", "a' OR 1=1--"),
    ]
    
    for endpoint, param, vuln_type, payload in sqli_vulns:
        ground_truth.add_vulnerability(endpoint, param, vuln_type, payload)
    
    # Open redirect vulnerability
    ground_truth.add_vulnerability(
        "https://localhost:5001/go", "url", "redirect", "https://evil.com"
    )
    
    # Safe endpoints (no vulnerabilities)
    safe_endpoints = [
        ("https://localhost:5001/", "index"),
        ("https://localhost:5001/about", "page"),
        ("https://localhost:5001/contact", "form"),
    ]
    
    for endpoint, param in safe_endpoints:
        ground_truth.add_safe_endpoint(endpoint, param)
    
    return ground_truth


def save_ground_truth(ground_truth: GroundTruth, output_path: Path):
    """Save ground truth to JSON file."""
    data = {
        'vulnerabilities': [],
        'safe_endpoints': []
    }
    
    for vuln in ground_truth.vulnerabilities:
        data['vulnerabilities'].append({
            'endpoint': vuln.endpoint,
            'parameter': vuln.parameter,
            'vulnerability_type': vuln.vulnerability_type,
            'payload': vuln.payload,
            'context': vuln.context
        })
    
    for endpoint, param in ground_truth.safe_endpoints:
        data['safe_endpoints'].append({
            'endpoint': endpoint,
            'parameter': param
        })
    
    with open(output_path, 'w') as f:
        json.dump(data, f, indent=2)
    
    print(f"Saved ground truth to {output_path}")


def main():
    parser = argparse.ArgumentParser(description="Evaluate Elise vulnerability scanner")
    parser.add_argument("--target", required=True, help="Target URL to evaluate")
    parser.add_argument("--ground-truth", help="Path to ground truth JSON file")
    parser.add_argument("--output-dir", default="evaluation_results", help="Output directory for results")
    parser.add_argument("--lab-mode", action="store_true", help="Use lab environment ground truth")
    parser.add_argument("--compare-all", action="store_true", help="Compare against all baseline tools")
    parser.add_argument("--tools", nargs="+", choices=["xsser", "sqlmap", "ffuf"], 
                       help="Specific baseline tools to run")
    parser.add_argument("--format", choices=["html", "markdown", "json"], default="html",
                       help="Report output format")
    parser.add_argument("--timeout", type=int, default=1800, help="Evaluation timeout in seconds")
    parser.add_argument("--save-ground-truth", help="Save generated ground truth to file")
    
    args = parser.parse_args()
    
    # Create output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Setup ground truth
    ground_truth_file = None
    if args.lab_mode:
        print("Using lab environment ground truth...")
        ground_truth = create_lab_ground_truth()
        ground_truth_file = output_dir / "lab_ground_truth.json"
        save_ground_truth(ground_truth, ground_truth_file)
    elif args.ground_truth:
        ground_truth_file = Path(args.ground_truth)
        if not ground_truth_file.exists():
            print(f"Error: Ground truth file not found: {ground_truth_file}")
            sys.exit(1)
    else:
        print("Warning: No ground truth provided. Evaluation will be limited.")
    
    # Setup evaluation configuration
    config = EvaluationConfig(
        target_url=args.target,
        ground_truth_file=ground_truth_file,
        output_dir=output_dir,
        include_baseline_tools=args.compare_all or args.tools is not None,
        tools_to_run=args.tools or (["xsser", "sqlmap", "ffuf"] if args.compare_all else []),
        evaluation_timeout=args.timeout
    )
    
    # Setup report configuration
    report_config = ReportConfig(
        output_format=args.format,
        include_charts=True,
        include_detailed_metrics=True,
        include_baseline_comparison=args.compare_all or args.tools is not None
    )
    
    print(f"Starting evaluation of {args.target}")
    print(f"Output directory: {output_dir}")
    print(f"Ground truth: {ground_truth_file or 'None'}")
    print(f"Baseline tools: {config.tools_to_run if config.include_baseline_tools else 'None'}")
    print()
    
    # Run evaluation
    evaluator = ComparativeEvaluator()
    
    try:
        start_time = time.time()
        results = evaluator.run_comparative_evaluation(config)
        evaluation_time = time.time() - start_time
        
        print(f"Evaluation completed in {evaluation_time:.2f} seconds")
        
        # Generate report
        report_path = output_dir / f"evaluation_report.{args.format}"
        generate_evaluation_report(results, report_path, report_config)
        
        print(f"Report generated: {report_path}")
        
        # Print summary
        print("\n" + "="*60)
        print("EVALUATION SUMMARY")
        print("="*60)
        
        elise_data = results.get('elise', {})
        if 'metrics' in elise_data:
            metrics = elise_data['metrics']
            
            # Handle both dict and EvaluationResult object
            if hasattr(metrics, 'total_vulnerabilities_found'):
                total_vulns = metrics.total_vulnerabilities_found
                total_fp = metrics.total_false_positives
                eval_time = metrics.total_evaluation_time
                recall_scores = metrics.recall_at_param
                precision_scores = metrics.precision_at_5
                fpr = metrics.false_positive_rate
            else:
                total_vulns = metrics.get('total_vulnerabilities_found', 0)
                total_fp = metrics.get('total_false_positives', 0)
                eval_time = metrics.get('total_evaluation_time', 0)
                recall_scores = metrics.get('recall_at_param', {})
                precision_scores = metrics.get('precision_at_5', {})
                fpr = metrics.get('false_positive_rate', 0)
            
            print(f"Vulnerabilities Found: {total_vulns}")
            print(f"False Positives: {total_fp}")
            print(f"Evaluation Time: {eval_time:.1f}s")
            
            if recall_scores:
                avg_recall = sum(recall_scores.values()) / len(recall_scores)
                print(f"Average Recall: {avg_recall:.3f}")
            
            if precision_scores:
                avg_precision = sum(precision_scores.values()) / len(precision_scores)
                print(f"Average Precision@5: {avg_precision:.3f}")
            
            print(f"False Positive Rate: {fpr:.3f}")
        
        # Show baseline tool comparison
        baseline_tools = results.get('baseline_tools', {})
        if baseline_tools:
            print(f"\nBaseline Tools Comparison:")
            for tool_name, tool_data in baseline_tools.items():
                if 'metrics' in tool_data:
                    tool_metrics = tool_data['metrics']
                    tool_time = tool_data.get('execution_time', 0)
                    tool_vulns = tool_metrics.get('total_vulnerabilities_found', 0)
                    print(f"  {tool_name.upper()}: {tool_vulns} vulns in {tool_time:.1f}s")
        
        print("="*60)
        
    except Exception as e:
        print(f"Evaluation failed: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    
    finally:
        evaluator.cleanup()


if __name__ == "__main__":
    main()
