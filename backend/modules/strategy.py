"""
Scan strategy module for Elise.

Defines and manages different scanning strategies.
"""

import os
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, Set
from backend.app_state import REQUIRE_RANKER

class ScanStrategy(str, Enum):
    """Available scan strategies."""
    AUTO = "auto"
    PROBE_ONLY = "probe_only"
    ML_ONLY = "ml_only"
    ML_WITH_CONTEXT = "ml_with_context"  # ML-only but with XSS context classification
    HYBRID = "hybrid"

@dataclass
class Plan:
    """Strategy execution plan with clear behavior rules."""
    name: ScanStrategy
    probes_disabled: Set[str] = field(default_factory=set)  # families: {"xss","redirect","sqli"}
    allow_injections: bool = True
    force_ctx_inject_on_probe: bool = False  # for hybrid only

# Default strategy from environment
DEFAULT_STRATEGY = os.getenv("ELISE_DEFAULT_STRATEGY", "auto")

def make_plan(name: str, env: Optional[Dict[str, Any]] = None) -> Plan:
    """
    Create a strategy execution plan based on strategy name and environment.
    
    Args:
        name: Strategy name
        env: Environment variables (optional)
        
    Returns:
        Plan object with clear behavior rules
    """
    if env is None:
        env = {}
    
    s = ScanStrategy(name.lower())
    
    if s == ScanStrategy.ML_ONLY:
        return Plan(s, probes_disabled={"xss", "redirect", "sqli"}, allow_injections=True)
    elif s == ScanStrategy.PROBE_ONLY:
        return Plan(s, probes_disabled=set(), allow_injections=False)
    elif s == ScanStrategy.ML_WITH_CONTEXT:
        # Full-Smart: XSS canary + SQLi probes allowed (as signals), Redirect disabled
        return Plan(s, probes_disabled={"redirect"}, allow_injections=True, force_ctx_inject_on_probe=True)
    elif s == ScanStrategy.HYBRID:
        return Plan(s, probes_disabled=set(), allow_injections=True, force_ctx_inject_on_probe=True)
    else:  # AUTO
        return Plan(s)

def probe_enabled(plan: Plan, family: str) -> bool:
    """Check if probes are enabled for a specific family."""
    return family not in plan.probes_disabled

def injections_enabled(plan: Plan) -> bool:
    """Check if injections are enabled for the plan."""
    return plan.allow_injections

def parse_strategy(value: Optional[str]) -> ScanStrategy:
    """
    Parse strategy string to ScanStrategy enum.
    
    Args:
        value: Strategy string (can be None)
        
    Returns:
        ScanStrategy enum value
        
    Raises:
        ValueError: If strategy is invalid
    """
    if not value:
        value = DEFAULT_STRATEGY
    
    try:
        return ScanStrategy(value.lower().strip())
    except ValueError:
        raise ValueError(f"Invalid strategy '{value}'. Must be one of: {[s.value for s in ScanStrategy]}")

def validate_strategy_requirements(strategy: ScanStrategy, ml_available: bool) -> Dict[str, Any]:
    """
    Validate strategy requirements against available capabilities.
    
    Args:
        strategy: Scan strategy
        ml_available: Whether ML models are available
        
    Returns:
        Validation result with success flag and metadata
        
    Raises:
        ValueError: If strategy requirements not met
    """
    result = {
        "strategy": strategy.value,
        "ml_required": strategy in {ScanStrategy.ML_ONLY, ScanStrategy.AUTO, ScanStrategy.HYBRID},
        "ml_available": ml_available,
        "fallback": None,
        "flags": []
    }
    
    # Check ML requirements
    if result["ml_required"] and not ml_available:
        if REQUIRE_RANKER:
            raise ValueError("Strategy requires ML models but none are available. Set ELISE_REQUIRE_RANKER=0 to allow fallback.")
        else:
            # Fallback to probe_only
            result["fallback"] = "probe_only"
            result["flags"].append("ml_fallback")
    
    return result

def get_strategy_behavior(strategy: ScanStrategy) -> Dict[str, Any]:
    """
    Get behavior configuration for a strategy.
    
    Args:
        strategy: Scan strategy
        
    Returns:
        Behavior configuration dictionary
    """
    behaviors = {
        ScanStrategy.AUTO: {
            "run_probes": True,
            "run_injections": True,
            "probe_first": True,
            "stop_on_probe_positive": True,
            "use_ml_ranking": True,
            "use_context_pool": False,
            "max_context_injections": 0,
            "description": "Run probes first; if probe-positive, stop for that family. If probe-negative, run ML-ranked injections."
        },
        ScanStrategy.PROBE_ONLY: {
            "run_probes": True,
            "run_injections": False,
            "probe_first": True,
            "stop_on_probe_positive": True,
            "use_ml_ranking": False,
            "use_context_pool": False,
            "max_context_injections": 0,
            "description": "Run oracles only; never run injections."
        },
        ScanStrategy.ML_ONLY: {
            "run_probes": False,
            "run_injections": True,
            "probe_first": False,
            "stop_on_probe_positive": False,
            "use_ml_ranking": True,
            "use_context_pool": False,
            "max_context_injections": 0,
            "description": "Skip probes and go straight to ML-ranked injections."
        },
        ScanStrategy.HYBRID: {
            "run_probes": True,
            "run_injections": True,
            "probe_first": True,
            "stop_on_probe_positive": False,  # Continue to context injection
            "use_ml_ranking": True,
            "use_context_pool": True,
            "max_context_injections": 1,  # One context-guided injection per XSS hit
            "description": "Run probes; even if probe-positive for XSS, execute one context-guided payload."
        }
    }
    
    return behaviors.get(strategy, behaviors[ScanStrategy.AUTO])

def get_strategy_hint(strategy: ScanStrategy) -> str:
    """
    Get user-friendly hint for a strategy.
    
    Args:
        strategy: Scan strategy
        
    Returns:
        Hint string
    """
    hints = {
        ScanStrategy.AUTO: "Recommended: probes first, then ML injections if needed",
        ScanStrategy.PROBE_ONLY: "Probes only; injections disabled",
        ScanStrategy.ML_ONLY: "Probes disabled; Top-K injections only",
        ScanStrategy.HYBRID: "Probe + one context-guided injection per XSS hit (demo)"
    }
    
    return hints.get(strategy, hints[ScanStrategy.AUTO])

def should_run_probes(strategy: ScanStrategy, family: str = None) -> bool:
    """
    Check if probes should run for a strategy and family.
    
    Args:
        strategy: Scan strategy
        family: Vulnerability family (optional)
        
    Returns:
        True if probes should run
    """
    behavior = get_strategy_behavior(strategy)
    
    if not behavior["run_probes"]:
        return False
    
    # Check for disabled probes via environment
    disabled_probes = os.getenv("DISABLE_PROBES", "").lower().split(",")
    if family and family.lower() in disabled_probes:
        return False
    
    return True

def should_run_injections(strategy: ScanStrategy) -> bool:
    """
    Check if injections should run for a strategy.
    
    Args:
        strategy: Scan strategy
        
    Returns:
        True if injections should run
    """
    behavior = get_strategy_behavior(strategy)
    return behavior["run_injections"]

def should_use_context_pool(strategy: ScanStrategy) -> bool:
    """
    Check if context pool should be used for a strategy.
    
    Args:
        strategy: Scan strategy
        
    Returns:
        True if context pool should be used
    """
    behavior = get_strategy_behavior(strategy)
    return behavior["use_context_pool"]

def get_max_context_injections(strategy: ScanStrategy) -> int:
    """
    Get maximum context injections for a strategy.
    
    Args:
        strategy: Scan strategy
        
    Returns:
        Maximum number of context injections
    """
    behavior = get_strategy_behavior(strategy)
    return behavior["max_context_injections"]
