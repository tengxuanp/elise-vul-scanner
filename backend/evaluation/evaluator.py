"""
Main evaluator classes for running comprehensive evaluations.

Integrates Elise system with baseline tools and ground truth data.
"""

import time
import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass

from .metrics import (
    EvaluationMetrics, 
    GroundTruth, 
    VulnerabilityInstance, 
    EvaluationResult
)
from .baseline_tools import BaselineToolManager, ToolResult

logger = logging.getLogger(__name__)


@dataclass
class EvaluationConfig:
    """Configuration for evaluation runs."""
    target_url: str
    ground_truth_file: Optional[Path] = None
    output_dir: Path = Path("evaluation_results")
    include_baseline_tools: bool = True
    tools_to_run: List[str] = None  # None means run all
    evaluation_timeout: int = 1800  # 30 minutes
    save_detailed_results: bool = True
    
    def __post_init__(self):
        if self.tools_to_run is None:
            self.tools_to_run = ['xsser', 'sqlmap', 'ffuf']


class EliseEvaluator:
    """Evaluator for Elise system performance."""
    
    def __init__(self, elise_runner=None):
        """
        Initialize Elise evaluator.
        
        Args:
            elise_runner: Function to run Elise assessment. Should accept
                         (target_url, **kwargs) and return results dict.
        """
        self.elise_runner = elise_runner or self._default_elise_runner
        self.metrics_calculator = EvaluationMetrics()
    
    def _default_elise_runner(self, target_url: str, **kwargs) -> Dict[str, Any]:
        """Default Elise runner - imports and runs the assessment workflow."""
        try:
            from backend.pipeline.workflow import assess_endpoints
            from backend.modules.playwright_crawler import crawl_site
            
            # Crawl the target
            crawl_result = crawl_site(
                target_url=target_url,
                max_depth=kwargs.get('max_depth', 2),
                max_endpoints=kwargs.get('max_endpoints', 50),
                max_seconds=kwargs.get('max_seconds', 300)
            )
            
            endpoints = crawl_result.get('endpoints', [])
            if not endpoints:
                logger.warning(f"No endpoints found for {target_url}")
                return {'summary': {}, 'rows': []}
            
            # Assess endpoints
            assessment_result = assess_endpoints(
                endpoints=endpoints,
                job_id=f"eval_{int(time.time())}",
                top_k=kwargs.get('top_k', 5),
                strategy=kwargs.get('strategy', 'auto'),
                ctx_mode=kwargs.get('ctx_mode', 'auto'),
                sqli_ml_mode=kwargs.get('sqli_ml_mode', 'never')
            )
            
            return assessment_result
            
        except Exception as e:
            logger.error(f"Failed to run Elise: {str(e)}")
            return {'summary': {}, 'rows': []}
    
    def run_elise_evaluation(self, config: EvaluationConfig) -> Tuple[EvaluationResult, List[VulnerabilityInstance]]:
        """
        Run Elise evaluation against target.
        
        Args:
            config: Evaluation configuration
            
        Returns:
            Tuple of (evaluation_result, detected_vulnerabilities)
        """
        logger.info(f"Starting Elise evaluation for {config.target_url}")
        start_time = time.time()
        
        # Run Elise assessment
        elise_results = self.elise_runner(
            target_url=config.target_url,
            max_depth=2,
            max_endpoints=50,
            top_k=5,
            strategy='auto',
            ctx_mode='auto'
        )
        
        # Convert Elise results to VulnerabilityInstance objects
        detected_vulns = self._convert_elise_results(elise_results, config.target_url)
        
        # Load ground truth
        ground_truth = self._load_ground_truth(config)
        
        # Compute evaluation metrics
        evaluation_time = time.time() - start_time
        result = self.metrics_calculator.evaluate(
            ground_truth=ground_truth,
            detected_vulns=detected_vulns,
            evaluation_time=evaluation_time
        )
        
        # Save results if requested
        if config.save_detailed_results:
            self._save_evaluation_results(result, detected_vulns, config)
        
        logger.info(f"Elise evaluation completed in {evaluation_time:.2f}s")
        return result, detected_vulns
    
    def _convert_elise_results(self, elise_results: Dict[str, Any], target_url: str) -> List[VulnerabilityInstance]:
        """Convert Elise results to VulnerabilityInstance objects."""
        vulnerabilities = []
        rows = elise_results.get('rows', [])
        
        for row in rows:
            if row.get('decision') == 'positive':
                vuln = VulnerabilityInstance(
                    endpoint=row.get('target', {}).get('url', target_url),
                    parameter=row.get('target', {}).get('param', 'unknown'),
                    vulnerability_type=row.get('family', 'unknown'),
                    payload=row.get('payload', ''),
                    confirmed=True,
                    confidence=row.get('ml', {}).get('p', 0.8),
                    detection_time=row.get('timestamp', 0.0),
                    attempt_count=row.get('attempt_idx', 1),
                    rank_position=row.get('rank_position'),
                    context=row.get('context', {})
                )
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _load_ground_truth(self, config: EvaluationConfig) -> GroundTruth:
        """Load ground truth data."""
        ground_truth = GroundTruth()
        
        if config.ground_truth_file and config.ground_truth_file.exists():
            try:
                with open(config.ground_truth_file, 'r') as f:
                    data = json.load(f)
                
                # Load vulnerabilities
                for vuln_data in data.get('vulnerabilities', []):
                    ground_truth.add_vulnerability(
                        endpoint=vuln_data['endpoint'],
                        param=vuln_data['parameter'],
                        vuln_type=vuln_data['vulnerability_type'],
                        payload=vuln_data.get('payload', ''),
                        context=vuln_data.get('context')
                    )
                
                # Load safe endpoints
                for safe_data in data.get('safe_endpoints', []):
                    ground_truth.add_safe_endpoint(
                        endpoint=safe_data['endpoint'],
                        param=safe_data['parameter']
                    )
                
                logger.info(f"Loaded ground truth: {len(ground_truth.vulnerabilities)} vulns, {len(ground_truth.safe_endpoints)} safe")
                
            except Exception as e:
                logger.error(f"Failed to load ground truth: {str(e)}")
        else:
            logger.warning("No ground truth file provided - evaluation will be limited")
        
        return ground_truth
    
    def _save_evaluation_results(self, result: EvaluationResult, vulns: List[VulnerabilityInstance], config: EvaluationConfig):
        """Save detailed evaluation results."""
        config.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Save metrics
        metrics_file = config.output_dir / f"elise_metrics_{int(time.time())}.json"
        self.metrics_calculator.save_results(result, metrics_file)
        
        # Save detected vulnerabilities
        vulns_file = config.output_dir / f"elise_vulns_{int(time.time())}.json"
        vulns_data = []
        for vuln in vulns:
            vulns_data.append({
                'endpoint': vuln.endpoint,
                'parameter': vuln.parameter,
                'vulnerability_type': vuln.vulnerability_type,
                'payload': vuln.payload,
                'confirmed': vuln.confirmed,
                'confidence': vuln.confidence,
                'detection_time': vuln.detection_time,
                'attempt_count': vuln.attempt_count,
                'rank_position': vuln.rank_position,
                'context': vuln.context
            })
        
        with open(vulns_file, 'w') as f:
            json.dump(vulns_data, f, indent=2)
        
        logger.info(f"Saved evaluation results to {config.output_dir}")


class ComparativeEvaluator:
    """Evaluator for comparing Elise against baseline tools."""
    
    def __init__(self, elise_runner=None, initialize_baseline_tools: bool = True):
        self.elise_evaluator = EliseEvaluator(elise_runner)
        self.baseline_manager = BaselineToolManager(initialize_tools=initialize_baseline_tools)
        self.metrics_calculator = EvaluationMetrics()
    
    def run_comparative_evaluation(self, config: EvaluationConfig) -> Dict[str, Any]:
        """
        Run comparative evaluation between Elise and baseline tools.
        
        Args:
            config: Evaluation configuration
            
        Returns:
            Dictionary with results from all tools
        """
        logger.info(f"Starting comparative evaluation for {config.target_url}")
        results = {
            'elise': None,
            'baseline_tools': {},
            'comparison': {},
            'config': {
                'target_url': config.target_url,
                'evaluation_timestamp': time.time()
            }
        }
        
        # Run Elise evaluation
        try:
            elise_result, elise_vulns = self.elise_evaluator.run_elise_evaluation(config)
            results['elise'] = {
                'metrics': elise_result,
                'vulnerabilities': elise_vulns
            }
        except Exception as e:
            logger.error(f"Elise evaluation failed: {str(e)}")
            results['elise'] = {'error': str(e)}
        
        # Run baseline tools
        if config.include_baseline_tools:
            try:
                baseline_results = self.baseline_manager.run_all_tools(
                    config.target_url,
                    crawl=config.get('crawl', False),
                    forms=config.get('forms', True)
                )
                
                # Convert baseline results to evaluation format
                for tool_name, tool_result in baseline_results.items():
                    if tool_name in config.tools_to_run:
                        # Convert to VulnerabilityInstance format
                        vulns = tool_result.vulnerabilities
                        
                        # Load ground truth for baseline evaluation
                        ground_truth = self.elise_evaluator._load_ground_truth(config)
                        
                        # Compute metrics for baseline tool
                        baseline_metrics = self.metrics_calculator.evaluate(
                            ground_truth=ground_truth,
                            detected_vulns=vulns,
                            evaluation_time=tool_result.execution_time
                        )
                        
                        results['baseline_tools'][tool_name] = {
                            'metrics': baseline_metrics,
                            'vulnerabilities': vulns,
                            'execution_time': tool_result.execution_time,
                            'command_used': tool_result.command_used,
                            'errors': tool_result.errors
                        }
                
            except Exception as e:
                logger.error(f"Baseline tools evaluation failed: {str(e)}")
                results['baseline_tools'] = {'error': str(e)}
        
        # Compute comparison metrics
        results['comparison'] = self._compute_comparison_metrics(results)
        
        # Save comprehensive results
        if config.save_detailed_results:
            self._save_comparative_results(results, config)
        
        logger.info("Comparative evaluation completed")
        return results
    
    def _compute_comparison_metrics(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Compute comparison metrics between tools."""
        comparison = {}
        
        if 'elise' in results and 'metrics' in results['elise']:
            elise_metrics = results['elise']['metrics']
            
            # Compare against each baseline tool
            for tool_name, tool_data in results.get('baseline_tools', {}).items():
                if 'metrics' in tool_data:
                    tool_metrics = tool_data['metrics']
                    
                    comparison[tool_name] = {
                        'recall_comparison': self._compare_recall(elise_metrics, tool_metrics),
                        'speed_comparison': self._compare_speed(elise_metrics, tool_metrics),
                        'precision_comparison': self._compare_precision(elise_metrics, tool_metrics),
                        'fpr_comparison': self._compare_fpr(elise_metrics, tool_metrics)
                    }
        
        return comparison
    
    def _compare_recall(self, elise_metrics: EvaluationResult, tool_metrics: EvaluationResult) -> Dict[str, Any]:
        """Compare recall scores."""
        comparison = {}
        
        for vuln_type in elise_metrics.recall_at_param:
            elise_recall = elise_metrics.recall_at_param.get(vuln_type, 0.0)
            tool_recall = tool_metrics.recall_at_param.get(vuln_type, 0.0)
            
            comparison[vuln_type] = {
                'elise': elise_recall,
                'tool': tool_recall,
                'difference': elise_recall - tool_recall,
                'improvement': ((elise_recall - tool_recall) / tool_recall * 100) if tool_recall > 0 else 0
            }
        
        return comparison
    
    def _compare_speed(self, elise_metrics: EvaluationResult, tool_metrics: EvaluationResult) -> Dict[str, Any]:
        """Compare execution speed."""
        return {
            'elise_time': elise_metrics.total_evaluation_time,
            'tool_time': tool_metrics.total_evaluation_time,
            'speedup': tool_metrics.total_evaluation_time / elise_metrics.total_evaluation_time if elise_metrics.total_evaluation_time > 0 else 0
        }
    
    def _compare_precision(self, elise_metrics: EvaluationResult, tool_metrics: EvaluationResult) -> Dict[str, Any]:
        """Compare precision scores."""
        comparison = {}
        
        for vuln_type in elise_metrics.precision_at_5:
            elise_precision = elise_metrics.precision_at_5.get(vuln_type, 0.0)
            tool_precision = tool_metrics.precision_at_5.get(vuln_type, 0.0)
            
            comparison[vuln_type] = {
                'elise': elise_precision,
                'tool': tool_precision,
                'difference': elise_precision - tool_precision
            }
        
        return comparison
    
    def _compare_fpr(self, elise_metrics: EvaluationResult, tool_metrics: EvaluationResult) -> Dict[str, Any]:
        """Compare false positive rates."""
        return {
            'elise_fpr': elise_metrics.false_positive_rate,
            'tool_fpr': tool_metrics.false_positive_rate,
            'difference': elise_metrics.false_positive_rate - tool_metrics.false_positive_rate
        }
    
    def _save_comparative_results(self, results: Dict[str, Any], config: EvaluationConfig):
        """Save comprehensive comparative results."""
        config.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Save full results
        results_file = config.output_dir / f"comparative_evaluation_{int(time.time())}.json"
        
        # Convert EvaluationResult objects to dicts for JSON serialization
        serializable_results = self._make_serializable(results)
        
        with open(results_file, 'w') as f:
            json.dump(serializable_results, f, indent=2)
        
        logger.info(f"Saved comparative results to {results_file}")
    
    def _make_serializable(self, obj):
        """Convert objects to JSON-serializable format."""
        if hasattr(obj, '__dict__'):
            return {k: self._make_serializable(v) for k, v in obj.__dict__.items()}
        elif isinstance(obj, list):
            return [self._make_serializable(item) for item in obj]
        elif isinstance(obj, dict):
            return {k: self._make_serializable(v) for k, v in obj.items()}
        else:
            return obj
    
    def cleanup(self):
        """Clean up resources."""
        self.baseline_manager.cleanup()
