"""
Integration helpers for incorporating evaluation metrics into Elise workflow.

Provides hooks and utilities for real-time evaluation during scanning.
"""

import time
import json
from typing import Dict, List, Any, Optional
from pathlib import Path
from dataclasses import dataclass

from .metrics import VulnerabilityInstance, EvaluationMetrics, GroundTruth
from .evaluator import EliseEvaluator


@dataclass
class RealTimeMetrics:
    """Real-time metrics tracking during scanning."""
    start_time: float
    vulnerabilities_found: List[VulnerabilityInstance] = None
    attempts_made: int = 0
    false_positives: int = 0
    current_phase: str = "initializing"
    
    def __post_init__(self):
        if self.vulnerabilities_found is None:
            self.vulnerabilities_found = []


class EliseMetricsCollector:
    """Collects metrics during Elise scanning for real-time evaluation."""
    
    def __init__(self, ground_truth: Optional[GroundTruth] = None):
        self.ground_truth = ground_truth or GroundTruth()
        self.metrics = RealTimeMetrics(start_time=time.time())
        self.evaluation_metrics = EvaluationMetrics()
    
    def record_vulnerability_found(self, endpoint: str, param: str, vuln_type: str, 
                                 payload: str, confidence: float, attempt_count: int,
                                 rank_position: Optional[int] = None, context: Dict = None):
        """Record a vulnerability found during scanning."""
        vuln = VulnerabilityInstance(
            endpoint=endpoint,
            parameter=param,
            vulnerability_type=vuln_type,
            payload=payload,
            confirmed=True,
            confidence=confidence,
            detection_time=time.time() - self.metrics.start_time,
            attempt_count=attempt_count,
            rank_position=rank_position,
            context=context
        )
        self.metrics.vulnerabilities_found.append(vuln)
    
    def record_attempt(self):
        """Record a scanning attempt."""
        self.metrics.attempts_made += 1
    
    def record_false_positive(self, endpoint: str, param: str):
        """Record a false positive detection."""
        self.metrics.false_positives += 1
        
        # Mark the corresponding vulnerability as false positive
        for vuln in self.metrics.vulnerabilities_found:
            if vuln.endpoint == endpoint and vuln.parameter == param:
                vuln.false_positive = True
                break
    
    def set_phase(self, phase: str):
        """Set current scanning phase."""
        self.metrics.current_phase = phase
    
    def get_current_metrics(self) -> Dict[str, Any]:
        """Get current real-time metrics."""
        current_time = time.time()
        elapsed = current_time - self.metrics.start_time
        
        # Calculate basic metrics
        total_vulns = len(self.metrics.vulnerabilities_found)
        confirmed_vulns = len([v for v in self.metrics.vulnerabilities_found if v.confirmed])
        false_positives = len([v for v in self.metrics.vulnerabilities_found if v.false_positive])
        
        # Calculate efficiency metrics
        avg_attempts_per_vuln = (
            sum(v.attempt_count for v in self.metrics.vulnerabilities_found) / total_vulns
            if total_vulns > 0 else 0
        )
        
        # Calculate detection rate
        detection_rate = confirmed_vulns / elapsed if elapsed > 0 else 0
        
        return {
            'elapsed_time': elapsed,
            'current_phase': self.metrics.current_phase,
            'total_vulnerabilities': total_vulns,
            'confirmed_vulnerabilities': confirmed_vulns,
            'false_positives': false_positives,
            'total_attempts': self.metrics.attempts_made,
            'avg_attempts_per_vuln': avg_attempts_per_vuln,
            'detection_rate': detection_rate,
            'vulnerabilities_by_type': self._group_by_type(),
            'recent_vulnerabilities': self._get_recent_vulnerabilities(5)
        }
    
    def _group_by_type(self) -> Dict[str, int]:
        """Group vulnerabilities by type."""
        by_type = {}
        for vuln in self.metrics.vulnerabilities_found:
            vuln_type = vuln.vulnerability_type
            by_type[vuln_type] = by_type.get(vuln_type, 0) + 1
        return by_type
    
    def _get_recent_vulnerabilities(self, count: int) -> List[Dict[str, Any]]:
        """Get recent vulnerabilities."""
        recent = sorted(
            self.metrics.vulnerabilities_found,
            key=lambda v: v.detection_time,
            reverse=True
        )[:count]
        
        return [
            {
                'endpoint': v.endpoint,
                'parameter': v.parameter,
                'type': v.vulnerability_type,
                'confidence': v.confidence,
                'time': v.detection_time
            }
            for v in recent
        ]
    
    def get_evaluation_summary(self) -> Dict[str, Any]:
        """Get comprehensive evaluation summary."""
        if not self.ground_truth.vulnerabilities:
            return {
                'message': 'No ground truth available for evaluation',
                'metrics': self.get_current_metrics()
            }
        
        # Run full evaluation
        result = self.evaluation_metrics.evaluate(
            ground_truth=self.ground_truth,
            detected_vulns=self.metrics.vulnerabilities_found,
            evaluation_time=time.time() - self.metrics.start_time
        )
        
        return {
            'evaluation_result': result,
            'real_time_metrics': self.get_current_metrics(),
            'performance_summary': self._generate_performance_summary(result)
        }
    
    def _generate_performance_summary(self, result) -> Dict[str, Any]:
        """Generate human-readable performance summary."""
        summary = {
            'overall_score': 'Unknown',
            'strengths': [],
            'weaknesses': [],
            'recommendations': []
        }
        
        # Calculate overall score
        recall_scores = result.recall_at_param
        precision_scores = result.precision_at_5
        fpr = result.false_positive_rate
        
        if recall_scores and precision_scores:
            avg_recall = sum(recall_scores.values()) / len(recall_scores)
            avg_precision = sum(precision_scores.values()) / len(precision_scores)
            
            # Simple scoring algorithm
            score = (avg_recall * 0.4 + avg_precision * 0.3 + (1 - fpr) * 0.3)
            
            if score >= 0.8:
                summary['overall_score'] = 'Excellent'
            elif score >= 0.6:
                summary['overall_score'] = 'Good'
            elif score >= 0.4:
                summary['overall_score'] = 'Fair'
            else:
                summary['overall_score'] = 'Needs Improvement'
        
        # Identify strengths and weaknesses
        if recall_scores:
            for vuln_type, recall in recall_scores.items():
                if recall >= 0.9:
                    summary['strengths'].append(f"Excellent {vuln_type.upper()} detection (recall: {recall:.3f})")
                elif recall < 0.5:
                    summary['weaknesses'].append(f"Poor {vuln_type.upper()} detection (recall: {recall:.3f})")
        
        if fpr <= 0.05:
            summary['strengths'].append(f"Low false positive rate ({fpr:.3f})")
        elif fpr > 0.15:
            summary['weaknesses'].append(f"High false positive rate ({fpr:.3f})")
        
        # Generate recommendations
        if summary['weaknesses']:
            summary['recommendations'].append("Review payload selection and ranking algorithms")
            summary['recommendations'].append("Consider adjusting confidence thresholds")
        
        if result.median_probes_per_confirm:
            for vuln_type, probes in result.median_probes_per_confirm.items():
                if probes > 5:
                    summary['recommendations'].append(f"Improve {vuln_type.upper()} payload efficiency (current: {probes:.1f} probes)")
        
        return summary


def create_metrics_collector_for_lab() -> EliseMetricsCollector:
    """Create a metrics collector with lab environment ground truth."""
    ground_truth = GroundTruth()
    
    # Add lab vulnerabilities
    lab_vulns = [
        ("https://localhost:5001/search", "q", "xss", "<script>alert('XSS')</script>"),
        ("https://localhost:5001/profile", "name", "xss", "\"><script>alert('XSS')</script>"),
        ("https://localhost:5001/script", "msg", "xss", "\";alert('XSS');//"),
        ("https://localhost:5001/product", "id", "sqli", "1 OR 1=1"),
        ("https://localhost:5001/login", "username", "sqli", "alice' OR '1'='1"),
        ("https://localhost:5001/go", "url", "redirect", "https://evil.com"),
    ]
    
    for endpoint, param, vuln_type, payload in lab_vulns:
        ground_truth.add_vulnerability(endpoint, param, vuln_type, payload)
    
    # Add safe endpoints
    safe_endpoints = [
        ("https://localhost:5001/", "index"),
        ("https://localhost:5001/about", "page"),
    ]
    
    for endpoint, param in safe_endpoints:
        ground_truth.add_safe_endpoint(endpoint, param)
    
    return EliseMetricsCollector(ground_truth)


def integrate_with_elise_workflow():
    """
    Example of how to integrate metrics collection with Elise workflow.
    
    This shows how to add real-time metrics collection to existing Elise code.
    """
    # Create metrics collector
    collector = create_metrics_collector_for_lab()
    
    # Example: During vulnerability detection
    def on_vulnerability_found(endpoint, param, vuln_type, payload, confidence, attempt_count):
        collector.record_vulnerability_found(
            endpoint=endpoint,
            param=param,
            vuln_type=vuln_type,
            payload=payload,
            confidence=confidence,
            attempt_count=attempt_count
        )
        
        # Get real-time metrics
        metrics = collector.get_current_metrics()
        print(f"Vulnerability found! Current metrics: {metrics}")
    
    # Example: During scanning attempts
    def on_scan_attempt():
        collector.record_attempt()
    
    # Example: At the end of scanning
    def on_scan_complete():
        summary = collector.get_evaluation_summary()
        print(f"Scan complete! Evaluation summary: {summary}")
        
        # Save results
        with open("real_time_evaluation.json", "w") as f:
            json.dump(summary, f, indent=2, default=str)
    
    return collector
