"""
Core evaluation metrics for vulnerability detection systems.

Implements the 5 key metrics requested:
1. Recall@Param (↑) — "How many real vulns did we actually catch?"
2. Median Probes per Confirm (↓) — "How many shots until the first hit?"
3. TTFC (median / p90) (↓) — Time-to-First-Confirm
4. P@5 (↑) for payload ranking — "Is the ML ranking actually helpful?"
5. FPR on safe cases (↓) — False-Positive Rate "Do the system hallucinate vulns?"
"""

import time
import statistics
from typing import Dict, List, Any, Optional, Tuple, Union
from dataclasses import dataclass, field
from collections import defaultdict
import json
from pathlib import Path


@dataclass
class VulnerabilityInstance:
    """Represents a single vulnerability instance for evaluation."""
    endpoint: str
    parameter: str
    vulnerability_type: str  # 'xss', 'sqli', 'redirect'
    payload: str
    confirmed: bool
    confidence: float
    detection_time: float  # seconds from start
    attempt_count: int  # number of attempts before confirmation
    rank_position: Optional[int] = None  # position in ML ranking (1-indexed)
    false_positive: bool = False
    context: Optional[Dict[str, Any]] = None


@dataclass
class GroundTruth:
    """Ground truth data for evaluation."""
    vulnerabilities: List[VulnerabilityInstance] = field(default_factory=list)
    safe_endpoints: List[Tuple[str, str]] = field(default_factory=list)  # (endpoint, param)
    
    def add_vulnerability(self, endpoint: str, param: str, vuln_type: str, 
                         payload: str, context: Optional[Dict] = None):
        """Add a known vulnerability to ground truth."""
        self.vulnerabilities.append(VulnerabilityInstance(
            endpoint=endpoint,
            parameter=param,
            vulnerability_type=vuln_type,
            payload=payload,
            confirmed=True,
            confidence=1.0,
            detection_time=0.0,
            attempt_count=0,
            context=context
        ))
    
    def add_safe_endpoint(self, endpoint: str, param: str):
        """Add a known safe endpoint to ground truth."""
        self.safe_endpoints.append((endpoint, param))


@dataclass
class EvaluationResult:
    """Results of evaluation metrics computation."""
    recall_at_param: Dict[str, float] = field(default_factory=dict)  # by vuln type
    median_probes_per_confirm: Dict[str, float] = field(default_factory=dict)
    time_to_first_confirm: Dict[str, Dict[str, float]] = field(default_factory=dict)  # by vuln type, then median/p90
    precision_at_5: Dict[str, float] = field(default_factory=dict)  # by vuln type
    false_positive_rate: float = 0.0
    total_evaluation_time: float = 0.0
    total_vulnerabilities_found: int = 0
    total_false_positives: int = 0
    total_safe_cases_tested: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


class RecallAtParam:
    """Recall@Param metric: How many real vulnerabilities did we catch?"""
    
    @staticmethod
    def compute(ground_truth: GroundTruth, detected_vulns: List[VulnerabilityInstance]) -> Dict[str, float]:
        """
        Compute recall@param for each vulnerability type.
        
        Args:
            ground_truth: Known vulnerabilities
            detected_vulns: Vulnerabilities found by the system
            
        Returns:
            Dict mapping vulnerability type to recall score (0.0-1.0)
        """
        recall_scores = {}
        
        # Group ground truth by vulnerability type
        gt_by_type = defaultdict(list)
        for vuln in ground_truth.vulnerabilities:
            gt_by_type[vuln.vulnerability_type].append(vuln)
        
        # Group detected vulnerabilities by type
        detected_by_type = defaultdict(list)
        for vuln in detected_vulns:
            if vuln.confirmed:
                detected_by_type[vuln.vulnerability_type].append(vuln)
        
        # Compute recall for each type
        for vuln_type in gt_by_type:
            gt_vulns = gt_by_type[vuln_type]
            detected_vulns_type = detected_by_type.get(vuln_type, [])
            
            # Match detected vulnerabilities to ground truth by endpoint+param
            matched = 0
            for gt_vuln in gt_vulns:
                for detected in detected_vulns_type:
                    if (detected.endpoint == gt_vuln.endpoint and 
                        detected.parameter == gt_vuln.parameter):
                        matched += 1
                        break
            
            recall = matched / len(gt_vulns) if gt_vulns else 0.0
            recall_scores[vuln_type] = recall
        
        return recall_scores


class MedianProbesPerConfirm:
    """Median Probes per Confirm metric: How many attempts until first hit?"""
    
    @staticmethod
    def compute(detected_vulns: List[VulnerabilityInstance]) -> Dict[str, float]:
        """
        Compute median probes per confirmation for each vulnerability type.
        
        Args:
            detected_vulns: Vulnerabilities found by the system
            
        Returns:
            Dict mapping vulnerability type to median attempt count
        """
        attempts_by_type = defaultdict(list)
        
        for vuln in detected_vulns:
            if vuln.confirmed and vuln.attempt_count > 0:
                attempts_by_type[vuln.vulnerability_type].append(vuln.attempt_count)
        
        median_attempts = {}
        for vuln_type, attempts in attempts_by_type.items():
            if attempts:
                median_attempts[vuln_type] = statistics.median(attempts)
            else:
                median_attempts[vuln_type] = 0.0
        
        return median_attempts


class TimeToFirstConfirm:
    """Time-to-First-Confirm metric: How long until first detection?"""
    
    @staticmethod
    def compute(detected_vulns: List[VulnerabilityInstance]) -> Dict[str, Dict[str, float]]:
        """
        Compute TTFC metrics (median and p90) for each vulnerability type.
        
        Args:
            detected_vulns: Vulnerabilities found by the system
            
        Returns:
            Dict mapping vuln_type -> {'median': float, 'p90': float}
        """
        ttfc_by_type = defaultdict(list)
        
        for vuln in detected_vulns:
            if vuln.confirmed and vuln.detection_time > 0:
                ttfc_by_type[vuln.vulnerability_type].append(vuln.detection_time)
        
        results = {}
        for vuln_type, times in ttfc_by_type.items():
            if times:
                times_sorted = sorted(times)
                median_time = statistics.median(times_sorted)
                p90_idx = int(0.9 * len(times_sorted))
                p90_time = times_sorted[p90_idx] if p90_idx < len(times_sorted) else times_sorted[-1]
                
                results[vuln_type] = {
                    'median': median_time,
                    'p90': p90_time
                }
            else:
                results[vuln_type] = {'median': 0.0, 'p90': 0.0}
        
        return results


class PrecisionAtK:
    """Precision@K metric: Is the ML ranking actually helpful?"""
    
    @staticmethod
    def compute(ground_truth: GroundTruth, detected_vulns: List[VulnerabilityInstance], k: int = 5) -> Dict[str, float]:
        """
        Compute Precision@K for payload ranking effectiveness.
        
        Args:
            ground_truth: Known vulnerabilities
            detected_vulns: Vulnerabilities found by the system
            k: Number of top-ranked items to consider (default 5)
            
        Returns:
            Dict mapping vulnerability type to P@K score
        """
        precision_scores = {}
        
        # Group by vulnerability type
        gt_by_type = defaultdict(list)
        for vuln in ground_truth.vulnerabilities:
            gt_by_type[vuln.vulnerability_type].append(vuln)
        
        detected_by_type = defaultdict(list)
        for vuln in detected_vulns:
            if vuln.confirmed and vuln.rank_position is not None:
                detected_by_type[vuln.vulnerability_type].append(vuln)
        
        for vuln_type in gt_by_type:
            gt_vulns = gt_by_type[vuln_type]
            detected_vulns_type = detected_by_type.get(vuln_type, [])
            
            if not detected_vulns_type:
                precision_scores[vuln_type] = 0.0
                continue
            
            # Sort by rank position and take top K
            top_k_vulns = sorted(detected_vulns_type, key=lambda x: x.rank_position)[:k]
            
            # Count how many of top K are actually in ground truth
            relevant_in_top_k = 0
            for detected in top_k_vulns:
                for gt_vuln in gt_vulns:
                    if (detected.endpoint == gt_vuln.endpoint and 
                        detected.parameter == gt_vuln.parameter):
                        relevant_in_top_k += 1
                        break
            
            precision = relevant_in_top_k / min(k, len(detected_vulns_type))
            precision_scores[vuln_type] = precision
        
        return precision_scores


class FalsePositiveRate:
    """False-Positive Rate metric: Does the system hallucinate vulnerabilities?"""
    
    @staticmethod
    def compute(ground_truth: GroundTruth, detected_vulns: List[VulnerabilityInstance]) -> float:
        """
        Compute false positive rate on safe cases.
        
        Args:
            ground_truth: Known safe endpoints
            detected_vulns: All detections (including false positives)
            
        Returns:
            False positive rate (0.0-1.0)
        """
        if not ground_truth.safe_endpoints:
            return 0.0
        
        # Create set of safe endpoint+param combinations
        safe_combinations = set(ground_truth.safe_endpoints)
        
        # Count false positives
        false_positives = 0
        for vuln in detected_vulns:
            if vuln.confirmed:
                endpoint_param = (vuln.endpoint, vuln.parameter)
                if endpoint_param in safe_combinations:
                    false_positives += 1
        
        return false_positives / len(safe_combinations)


class EvaluationMetrics:
    """Main evaluation metrics calculator."""
    
    def __init__(self):
        self.recall_calculator = RecallAtParam()
        self.probes_calculator = MedianProbesPerConfirm()
        self.ttfc_calculator = TimeToFirstConfirm()
        self.precision_calculator = PrecisionAtK()
        self.fpr_calculator = FalsePositiveRate()
    
    def evaluate(self, ground_truth: GroundTruth, detected_vulns: List[VulnerabilityInstance], 
                evaluation_time: float = 0.0) -> EvaluationResult:
        """
        Compute all evaluation metrics.
        
        Args:
            ground_truth: Ground truth data
            detected_vulns: Detected vulnerabilities
            evaluation_time: Total time taken for evaluation
            
        Returns:
            Complete evaluation results
        """
        # Compute individual metrics
        recall_scores = self.recall_calculator.compute(ground_truth, detected_vulns)
        median_probes = self.probes_calculator.compute(detected_vulns)
        ttfc_metrics = self.ttfc_calculator.compute(detected_vulns)
        precision_at_5 = self.precision_calculator.compute(ground_truth, detected_vulns, k=5)
        fpr = self.fpr_calculator.compute(ground_truth, detected_vulns)
        
        # Count totals
        total_found = len([v for v in detected_vulns if v.confirmed])
        total_fp = len([v for v in detected_vulns if v.confirmed and v.false_positive])
        total_safe = len(ground_truth.safe_endpoints)
        
        return EvaluationResult(
            recall_at_param=recall_scores,
            median_probes_per_confirm=median_probes,
            time_to_first_confirm=ttfc_metrics,
            precision_at_5=precision_at_5,
            false_positive_rate=fpr,
            total_evaluation_time=evaluation_time,
            total_vulnerabilities_found=total_found,
            total_false_positives=total_fp,
            total_safe_cases_tested=total_safe,
            metadata={
                'evaluation_timestamp': time.time(),
                'ground_truth_vulns': len(ground_truth.vulnerabilities),
                'ground_truth_safe': len(ground_truth.safe_endpoints),
                'detected_vulns': len(detected_vulns)
            }
        )
    
    def save_results(self, result: EvaluationResult, output_path: Path):
        """Save evaluation results to JSON file."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Convert dataclass to dict for JSON serialization
        result_dict = {
            'recall_at_param': result.recall_at_param,
            'median_probes_per_confirm': result.median_probes_per_confirm,
            'time_to_first_confirm': result.time_to_first_confirm,
            'precision_at_5': result.precision_at_5,
            'false_positive_rate': result.false_positive_rate,
            'total_evaluation_time': result.total_evaluation_time,
            'total_vulnerabilities_found': result.total_vulnerabilities_found,
            'total_false_positives': result.total_false_positives,
            'total_safe_cases_tested': result.total_safe_cases_tested,
            'metadata': result.metadata
        }
        
        with open(output_path, 'w') as f:
            json.dump(result_dict, f, indent=2)
    
    def load_results(self, input_path: Path) -> EvaluationResult:
        """Load evaluation results from JSON file."""
        with open(input_path, 'r') as f:
            result_dict = json.load(f)
        
        return EvaluationResult(
            recall_at_param=result_dict.get('recall_at_param', {}),
            median_probes_per_confirm=result_dict.get('median_probes_per_confirm', {}),
            time_to_first_confirm=result_dict.get('time_to_first_confirm', {}),
            precision_at_5=result_dict.get('precision_at_5', {}),
            false_positive_rate=result_dict.get('false_positive_rate', 0.0),
            total_evaluation_time=result_dict.get('total_evaluation_time', 0.0),
            total_vulnerabilities_found=result_dict.get('total_vulnerabilities_found', 0),
            total_false_positives=result_dict.get('total_false_positives', 0),
            total_safe_cases_tested=result_dict.get('total_safe_cases_tested', 0),
            metadata=result_dict.get('metadata', {})
        )
