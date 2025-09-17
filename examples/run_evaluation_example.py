#!/usr/bin/env python3
"""
Example script demonstrating the Elise evaluation framework.

This script shows how to:
1. Set up ground truth data
2. Run Elise evaluation
3. Compare against baseline tools
4. Generate reports
"""

import sys
import time
from pathlib import Path

# Add backend to path
sys.path.append(str(Path(__file__).parent.parent))

from backend.evaluation import (
    EvaluationConfig,
    ComparativeEvaluator,
    generate_evaluation_report,
    ReportConfig,
    GroundTruth
)
from backend.evaluation.metrics import VulnerabilityInstance


def create_example_ground_truth():
    """Create example ground truth data."""
    ground_truth = GroundTruth()
    
    # Add some XSS vulnerabilities
    ground_truth.add_vulnerability(
        endpoint="https://example.com/search",
        param="q",
        vuln_type="xss",
        payload="<script>alert('XSS')</script>"
    )
    
    ground_truth.add_vulnerability(
        endpoint="https://example.com/profile",
        param="name", 
        vuln_type="xss",
        payload="\"><script>alert('XSS')</script>"
    )
    
    # Add some SQL injection vulnerabilities
    ground_truth.add_vulnerability(
        endpoint="https://example.com/product",
        param="id",
        vuln_type="sqli",
        payload="1 OR 1=1"
    )
    
    ground_truth.add_vulnerability(
        endpoint="https://example.com/login",
        param="username",
        vuln_type="sqli", 
        payload="admin' OR '1'='1"
    )
    
    # Add safe endpoints
    ground_truth.add_safe_endpoint("https://example.com/", "index")
    ground_truth.add_safe_endpoint("https://example.com/about", "page")
    
    return ground_truth


def simulate_elise_results(ground_truth: GroundTruth):
    """Simulate Elise detection results for demonstration."""
    detected_vulns = []
    
    # Simulate finding some vulnerabilities
    vuln_data = [
        ("https://example.com/search", "q", "xss", "<script>alert('XSS')</script>", 0.95, 2),
        ("https://example.com/product", "id", "sqli", "1 OR 1=1", 0.88, 1),
        ("https://example.com/login", "username", "sqli", "admin' OR '1'='1", 0.92, 3),
    ]
    
    for endpoint, param, vuln_type, payload, confidence, attempt_count in vuln_data:
        vuln = VulnerabilityInstance(
            endpoint=endpoint,
            parameter=param,
            vulnerability_type=vuln_type,
            payload=payload,
            confirmed=True,
            confidence=confidence,
            detection_time=time.time() + len(detected_vulns) * 10,  # Simulate timing
            attempt_count=attempt_count,
            rank_position=1  # Simulate good ranking
        )
        detected_vulns.append(vuln)
    
    return detected_vulns


def main():
    print("🔍 Elise Evaluation Framework Demo")
    print("=" * 50)
    
    # Create example ground truth
    print("1. Creating example ground truth...")
    ground_truth = create_example_ground_truth()
    print(f"   - {len(ground_truth.vulnerabilities)} vulnerabilities")
    print(f"   - {len(ground_truth.safe_endpoints)} safe endpoints")
    
    # Simulate Elise results
    print("\n2. Simulating Elise detection results...")
    detected_vulns = simulate_elise_results(ground_truth)
    print(f"   - {len(detected_vulns)} vulnerabilities detected")
    
    # Create evaluation configuration
    print("\n3. Setting up evaluation...")
    config = EvaluationConfig(
        target_url="https://example.com",
        output_dir=Path("demo_results"),
        include_baseline_tools=False,  # Skip baseline tools for demo
        evaluation_timeout=300
    )
    
    # Run evaluation
    print("\n4. Running evaluation...")
    evaluator = ComparativeEvaluator(initialize_baseline_tools=False)
    
    # Manually set ground truth for demo
    evaluator.elise_evaluator._load_ground_truth = lambda cfg: ground_truth
    
    # Simulate the evaluation results
    results = {
        'elise': {
            'metrics': evaluator.metrics_calculator.evaluate(
                ground_truth=ground_truth,
                detected_vulns=detected_vulns,
                evaluation_time=30.0
            ),
            'vulnerabilities': detected_vulns
        },
        'baseline_tools': {},
        'comparison': {},
        'config': {
            'target_url': 'https://example.com',
            'evaluation_timestamp': time.time()
        }
    }
    
    # Generate report
    print("\n5. Generating report...")
    report_config = ReportConfig(
        output_format="html",
        include_charts=True,
        include_detailed_metrics=True,
        include_baseline_comparison=False
    )
    
    # Ensure output directory exists
    output_dir = Path("demo_results")
    output_dir.mkdir(exist_ok=True)
    
    report_path = generate_evaluation_report(
        results, 
        output_dir / "evaluation_report.html",
        report_config
    )
    
    print(f"   - Report saved to: {report_path}")
    
    # Display summary
    print("\n6. Evaluation Summary")
    print("-" * 30)
    
    elise_metrics = results['elise']['metrics']
    
    print(f"Vulnerabilities Found: {elise_metrics.total_vulnerabilities_found}")
    print(f"False Positives: {elise_metrics.total_false_positives}")
    print(f"Evaluation Time: {elise_metrics.total_evaluation_time:.1f}s")
    
    # Show recall by type
    recall_scores = elise_metrics.recall_at_param
    if recall_scores:
        print("\nRecall by Vulnerability Type:")
        for vuln_type, score in recall_scores.items():
            print(f"  {vuln_type.upper()}: {score:.3f}")
    
    # Show precision by type
    precision_scores = elise_metrics.precision_at_5
    if precision_scores:
        print("\nPrecision@5 by Vulnerability Type:")
        for vuln_type, score in precision_scores.items():
            print(f"  {vuln_type.upper()}: {score:.3f}")
    
    # Show efficiency metrics
    probes_metrics = elise_metrics.median_probes_per_confirm
    if probes_metrics:
        print("\nMedian Probes per Confirm:")
        for vuln_type, probes in probes_metrics.items():
            print(f"  {vuln_type.upper()}: {probes:.1f}")
    
    # Show timing metrics
    ttfc_metrics = elise_metrics.time_to_first_confirm
    if ttfc_metrics:
        print("\nTime to First Confirm:")
        for vuln_type, times in ttfc_metrics.items():
            print(f"  {vuln_type.upper()}: {times['median']:.1f}s (median), {times['p90']:.1f}s (p90)")
    
    print(f"\nFalse Positive Rate: {elise_metrics.false_positive_rate:.3f}")
    
    print("\n✅ Demo completed! Check the generated report for detailed analysis.")
    print(f"📊 Open {report_path} in your browser to view the full report.")


if __name__ == "__main__":
    main()
