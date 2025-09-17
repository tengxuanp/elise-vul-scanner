"""
Elise Evaluation Metrics Framework

Comprehensive evaluation system for vulnerability detection performance
including comparison against conventional tools.
"""

from .metrics import (
    EvaluationMetrics,
    RecallAtParam,
    MedianProbesPerConfirm,
    TimeToFirstConfirm,
    PrecisionAtK,
    FalsePositiveRate,
    EvaluationResult,
    GroundTruth,
    VulnerabilityInstance
)

from .baseline_tools import (
    BaselineToolRunner,
    XSStrikeRunner,
    SQLmapRunner,
    FFUFRunner
)

from .evaluator import (
    EliseEvaluator,
    ComparativeEvaluator,
    EvaluationConfig
)

from .reporting import (
    EvaluationReporter,
    generate_evaluation_report,
    ReportConfig
)

__all__ = [
    'EvaluationMetrics',
    'RecallAtParam', 
    'MedianProbesPerConfirm',
    'TimeToFirstConfirm',
    'PrecisionAtK',
    'FalsePositiveRate',
    'EvaluationResult',
    'GroundTruth',
    'VulnerabilityInstance',
    'BaselineToolRunner',
    'XSStrikeRunner',
    'SQLmapRunner', 
    'FFUFRunner',
    'EliseEvaluator',
    'ComparativeEvaluator',
    'EvaluationConfig',
    'EvaluationReporter',
    'generate_evaluation_report',
    'ReportConfig'
]
