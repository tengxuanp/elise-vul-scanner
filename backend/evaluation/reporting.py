"""
Reporting and visualization for evaluation results.

Generates comprehensive reports comparing Elise against baseline tools.
"""

import json
import time
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import logging

from .metrics import EvaluationResult

logger = logging.getLogger(__name__)


@dataclass
class ReportConfig:
    """Configuration for report generation."""
    output_format: str = "html"  # html, json, markdown
    include_charts: bool = True
    include_detailed_metrics: bool = True
    include_baseline_comparison: bool = True
    template_file: Optional[Path] = None


class EvaluationReporter:
    """Generates evaluation reports."""
    
    def __init__(self, config: ReportConfig = None):
        self.config = config or ReportConfig()
    
    def _get_metric_value(self, metrics_obj, key: str, default=None):
        """Get metric value from either dict or EvaluationResult object."""
        if hasattr(metrics_obj, key):
            return getattr(metrics_obj, key)
        elif isinstance(metrics_obj, dict):
            return metrics_obj.get(key, default)
        else:
            return default
    
    def generate_report(self, results: Dict[str, Any], output_path: Path) -> Path:
        """
        Generate evaluation report.
        
        Args:
            results: Evaluation results from ComparativeEvaluator
            output_path: Path to save the report
            
        Returns:
            Path to generated report
        """
        if self.config.output_format == "html":
            return self._generate_html_report(results, output_path)
        elif self.config.output_format == "markdown":
            return self._generate_markdown_report(results, output_path)
        elif self.config.output_format == "json":
            return self._generate_json_report(results, output_path)
        else:
            raise ValueError(f"Unsupported output format: {self.config.output_format}")
    
    def _generate_html_report(self, results: Dict[str, Any], output_path: Path) -> Path:
        """Generate HTML report."""
        html_content = self._build_html_content(results)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"Generated HTML report: {output_path}")
        return output_path
    
    def _generate_markdown_report(self, results: Dict[str, Any], output_path: Path) -> Path:
        """Generate Markdown report."""
        md_content = self._build_markdown_content(results)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(md_content)
        
        logger.info(f"Generated Markdown report: {output_path}")
        return output_path
    
    def _generate_json_report(self, results: Dict[str, Any], output_path: Path) -> Path:
        """Generate JSON report."""
        # Convert EvaluationResult objects to dicts for JSON serialization
        serializable_results = self._make_serializable(results)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(serializable_results, f, indent=2)
        
        logger.info(f"Generated JSON report: {output_path}")
        return output_path
    
    def _build_html_content(self, results: Dict[str, Any]) -> str:
        """Build HTML report content."""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
        target_url = results.get('config', {}).get('target_url', 'Unknown')
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Elise Evaluation Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }}
        .header {{ background: #f4f4f4; padding: 20px; border-radius: 5px; margin-bottom: 30px; }}
        .metric-card {{ background: #fff; border: 1px solid #ddd; border-radius: 5px; padding: 20px; margin: 10px 0; }}
        .metric-title {{ font-size: 1.2em; font-weight: bold; color: #333; margin-bottom: 10px; }}
        .metric-value {{ font-size: 1.5em; font-weight: bold; color: #2c5aa0; }}
        .comparison-table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        .comparison-table th, .comparison-table td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        .comparison-table th {{ background-color: #f2f2f2; }}
        .positive {{ color: #28a745; }}
        .negative {{ color: #dc3545; }}
        .neutral {{ color: #6c757d; }}
        .chart-container {{ margin: 20px 0; }}
        .summary-stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 Elise Vulnerability Scanner Evaluation Report</h1>
        <p><strong>Target:</strong> {target_url}</p>
        <p><strong>Generated:</strong> {timestamp}</p>
    </div>
"""
        
        # Add summary statistics
        html += self._build_summary_section(results)
        
        # Add detailed metrics
        if self.config.include_detailed_metrics:
            html += self._build_detailed_metrics_section(results)
        
        # Add baseline comparison
        if self.config.include_baseline_comparison:
            html += self._build_comparison_section(results)
        
        # Add charts if enabled
        if self.config.include_charts:
            html += self._build_charts_section(results)
        
        html += """
</body>
</html>
"""
        return html
    
    def _build_summary_section(self, results: Dict[str, Any]) -> str:
        """Build summary statistics section."""
        elise_data = results.get('elise', {})
        elise_metrics = elise_data.get('metrics', {})
        
        # Get metric values using helper
        total_vulns = self._get_metric_value(elise_metrics, 'total_vulnerabilities_found', 0)
        total_fp = self._get_metric_value(elise_metrics, 'total_false_positives', 0)
        eval_time = self._get_metric_value(elise_metrics, 'total_evaluation_time', 0)
        recall_scores = self._get_metric_value(elise_metrics, 'recall_at_param', {})
        precision_scores = self._get_metric_value(elise_metrics, 'precision_at_5', {})
        fpr = self._get_metric_value(elise_metrics, 'false_positive_rate', 0)
        
        # Calculate overall recall
        avg_recall = sum(recall_scores.values()) / len(recall_scores) if recall_scores else 0
        
        # Calculate overall precision
        avg_precision = sum(precision_scores.values()) / len(precision_scores) if precision_scores else 0
        
        return f"""
    <div class="summary-stats">
        <div class="metric-card">
            <div class="metric-title">Vulnerabilities Found</div>
            <div class="metric-value">{total_vulns}</div>
        </div>
        <div class="metric-card">
            <div class="metric-title">Average Recall</div>
            <div class="metric-value">{avg_recall:.3f}</div>
        </div>
        <div class="metric-card">
            <div class="metric-title">Average Precision@5</div>
            <div class="metric-value">{avg_precision:.3f}</div>
        </div>
        <div class="metric-card">
            <div class="metric-title">False Positive Rate</div>
            <div class="metric-value">{fpr:.3f}</div>
        </div>
        <div class="metric-card">
            <div class="metric-title">Evaluation Time</div>
            <div class="metric-value">{eval_time:.1f}s</div>
        </div>
        <div class="metric-card">
            <div class="metric-title">False Positives</div>
            <div class="metric-value">{total_fp}</div>
        </div>
    </div>
"""
    
    def _build_detailed_metrics_section(self, results: Dict[str, Any]) -> str:
        """Build detailed metrics section."""
        elise_data = results.get('elise', {})
        elise_metrics = elise_data.get('metrics', {})
        
        html = """
    <h2>📊 Detailed Metrics</h2>
"""
        
        # Recall by vulnerability type
        recall_scores = self._get_metric_value(elise_metrics, 'recall_at_param', {})
        if recall_scores:
            html += """
    <h3>Recall by Vulnerability Type</h3>
    <table class="comparison-table">
        <tr><th>Vulnerability Type</th><th>Recall Score</th><th>Performance</th></tr>
"""
            for vuln_type, score in recall_scores.items():
                performance = "🟢 Excellent" if score >= 0.9 else "🟡 Good" if score >= 0.7 else "🔴 Needs Improvement"
                html += f"        <tr><td>{vuln_type.upper()}</td><td>{score:.3f}</td><td>{performance}</td></tr>\n"
            html += "    </table>\n"
        
        # Precision by vulnerability type
        precision_scores = self._get_metric_value(elise_metrics, 'precision_at_5', {})
        if precision_scores:
            html += """
    <h3>Precision@5 by Vulnerability Type</h3>
    <table class="comparison-table">
        <tr><th>Vulnerability Type</th><th>Precision@5</th><th>Performance</th></tr>
"""
            for vuln_type, score in precision_scores.items():
                performance = "🟢 Excellent" if score >= 0.8 else "🟡 Good" if score >= 0.6 else "🔴 Needs Improvement"
                html += f"        <tr><td>{vuln_type.upper()}</td><td>{score:.3f}</td><td>{performance}</td></tr>\n"
            html += "    </table>\n"
        
        # Time to First Confirm
        ttfc_metrics = self._get_metric_value(elise_metrics, 'time_to_first_confirm', {})
        if ttfc_metrics:
            html += """
    <h3>Time to First Confirm (TTFC)</h3>
    <table class="comparison-table">
        <tr><th>Vulnerability Type</th><th>Median (s)</th><th>P90 (s)</th></tr>
"""
            for vuln_type, times in ttfc_metrics.items():
                median = times.get('median', 0)
                p90 = times.get('p90', 0)
                html += f"        <tr><td>{vuln_type.upper()}</td><td>{median:.2f}</td><td>{p90:.2f}</td></tr>\n"
            html += "    </table>\n"
        
        # Median Probes per Confirm
        probes_metrics = self._get_metric_value(elise_metrics, 'median_probes_per_confirm', {})
        if probes_metrics:
            html += """
    <h3>Median Probes per Confirm</h3>
    <table class="comparison-table">
        <tr><th>Vulnerability Type</th><th>Median Probes</th><th>Efficiency</th></tr>
"""
            for vuln_type, probes in probes_metrics.items():
                efficiency = "🟢 Excellent" if probes <= 2 else "🟡 Good" if probes <= 5 else "🔴 Needs Improvement"
                html += f"        <tr><td>{vuln_type.upper()}</td><td>{probes:.1f}</td><td>{efficiency}</td></tr>\n"
            html += "    </table>\n"
        
        return html
    
    def _build_comparison_section(self, results: Dict[str, Any]) -> str:
        """Build baseline tools comparison section."""
        comparison = results.get('comparison', {})
        baseline_tools = results.get('baseline_tools', {})
        
        if not comparison or not baseline_tools:
            return ""
        
        html = """
    <h2>⚖️ Baseline Tools Comparison</h2>
"""
        
        for tool_name, tool_comparison in comparison.items():
            if tool_name in baseline_tools:
                tool_data = baseline_tools[tool_name]
                tool_time = tool_data.get('execution_time', 0)
                
                html += f"""
    <h3>{tool_name.upper()}</h3>
    <table class="comparison-table">
        <tr><th>Metric</th><th>Elise</th><th>{tool_name.upper()}</th><th>Difference</th><th>Winner</th></tr>
"""
                
                # Speed comparison
                speed_comp = tool_comparison.get('speed_comparison', {})
                elise_time = speed_comp.get('elise_time', 0)
                tool_time = speed_comp.get('tool_time', 0)
                speedup = speed_comp.get('speedup', 1)
                
                winner = "Elise" if speedup > 1 else tool_name.upper()
                html += f"        <tr><td>Execution Time</td><td>{elise_time:.1f}s</td><td>{tool_time:.1f}s</td><td>{speedup:.1f}x</td><td>{winner}</td></tr>\n"
                
                # FPR comparison
                fpr_comp = tool_comparison.get('fpr_comparison', {})
                elise_fpr = fpr_comp.get('elise_fpr', 0)
                tool_fpr = fpr_comp.get('tool_fpr', 0)
                fpr_diff = fpr_comp.get('difference', 0)
                
                winner = "Elise" if fpr_diff < 0 else tool_name.upper()
                html += f"        <tr><td>False Positive Rate</td><td>{elise_fpr:.3f}</td><td>{tool_fpr:.3f}</td><td>{fpr_diff:+.3f}</td><td>{winner}</td></tr>\n"
                
                # Recall comparison by type
                recall_comp = tool_comparison.get('recall_comparison', {})
                for vuln_type, recall_data in recall_comp.items():
                    elise_recall = recall_data.get('elise', 0)
                    tool_recall = recall_data.get('tool', 0)
                    improvement = recall_data.get('improvement', 0)
                    
                    winner = "Elise" if improvement > 0 else tool_name.upper()
                    html += f"        <tr><td>Recall ({vuln_type.upper()})</td><td>{elise_recall:.3f}</td><td>{tool_recall:.3f}</td><td>{improvement:+.1f}%</td><td>{winner}</td></tr>\n"
                
                html += "    </table>\n"
        
        return html
    
    def _build_charts_section(self, results: Dict[str, Any]) -> str:
        """Build charts section (placeholder for future chart implementation)."""
        return """
    <h2>📈 Performance Charts</h2>
    <div class="chart-container">
        <p><em>Chart visualization will be implemented in future versions.</em></p>
        <p>For now, refer to the detailed metrics tables above for performance analysis.</p>
    </div>
"""
    
    def _build_markdown_content(self, results: Dict[str, Any]) -> str:
        """Build Markdown report content."""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
        target_url = results.get('config', {}).get('target_url', 'Unknown')
        
        md = f"""# 🔍 Elise Vulnerability Scanner Evaluation Report

**Target:** {target_url}  
**Generated:** {timestamp}

## 📊 Summary Statistics

"""
        
        # Add summary stats
        elise_data = results.get('elise', {})
        elise_metrics = elise_data.get('metrics', {})
        
        total_vulns = elise_metrics.get('total_vulnerabilities_found', 0)
        total_fp = elise_metrics.get('total_false_positives', 0)
        eval_time = elise_metrics.get('total_evaluation_time', 0)
        
        recall_scores = elise_metrics.get('recall_at_param', {})
        avg_recall = sum(recall_scores.values()) / len(recall_scores) if recall_scores else 0
        
        precision_scores = elise_metrics.get('precision_at_5', {})
        avg_precision = sum(precision_scores.values()) / len(precision_scores) if precision_scores else 0
        
        fpr = elise_metrics.get('false_positive_rate', 0)
        
        md += f"""| Metric | Value |
|--------|-------|
| Vulnerabilities Found | {total_vulns} |
| Average Recall | {avg_recall:.3f} |
| Average Precision@5 | {avg_precision:.3f} |
| False Positive Rate | {fpr:.3f} |
| Evaluation Time | {eval_time:.1f}s |
| False Positives | {total_fp} |

"""
        
        # Add detailed metrics
        if self.config.include_detailed_metrics:
            md += self._build_markdown_detailed_metrics(results)
        
        # Add comparison
        if self.config.include_baseline_comparison:
            md += self._build_markdown_comparison(results)
        
        return md
    
    def _build_markdown_detailed_metrics(self, results: Dict[str, Any]) -> str:
        """Build detailed metrics in Markdown format."""
        elise_data = results.get('elise', {})
        elise_metrics = elise_data.get('metrics', {})
        
        md = "## 📊 Detailed Metrics\n\n"
        
        # Recall by vulnerability type
        recall_scores = elise_metrics.get('recall_at_param', {})
        if recall_scores:
            md += "### Recall by Vulnerability Type\n\n"
            md += "| Vulnerability Type | Recall Score | Performance |\n"
            md += "|-------------------|--------------|-------------|\n"
            for vuln_type, score in recall_scores.items():
                performance = "🟢 Excellent" if score >= 0.9 else "🟡 Good" if score >= 0.7 else "🔴 Needs Improvement"
                md += f"| {vuln_type.upper()} | {score:.3f} | {performance} |\n"
            md += "\n"
        
        return md
    
    def _build_markdown_comparison(self, results: Dict[str, Any]) -> str:
        """Build comparison section in Markdown format."""
        comparison = results.get('comparison', {})
        baseline_tools = results.get('baseline_tools', {})
        
        if not comparison or not baseline_tools:
            return ""
        
        md = "## ⚖️ Baseline Tools Comparison\n\n"
        
        for tool_name, tool_comparison in comparison.items():
            if tool_name in baseline_tools:
                md += f"### {tool_name.upper()}\n\n"
                md += "| Metric | Elise | Tool | Difference | Winner |\n"
                md += "|--------|-------|------|------------|--------|\n"
                
                # Add comparison rows
                speed_comp = tool_comparison.get('speed_comparison', {})
                elise_time = speed_comp.get('elise_time', 0)
                tool_time = speed_comp.get('tool_time', 0)
                speedup = speed_comp.get('speedup', 1)
                winner = "Elise" if speedup > 1 else tool_name.upper()
                md += f"| Execution Time | {elise_time:.1f}s | {tool_time:.1f}s | {speedup:.1f}x | {winner} |\n"
                
                md += "\n"
        
        return md


def generate_evaluation_report(results: Dict[str, Any], output_path: Path, 
                             config: ReportConfig = None) -> Path:
    """
    Convenience function to generate evaluation report.
    
    Args:
        results: Evaluation results
        output_path: Path to save report
        config: Report configuration
        
    Returns:
        Path to generated report
    """
    reporter = EvaluationReporter(config)
    return reporter.generate_report(results, output_path)
