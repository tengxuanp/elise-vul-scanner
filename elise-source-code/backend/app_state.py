#!/usr/bin/env python3
"""
Application state and configuration management
"""

from dataclasses import dataclass
from typing import Optional
import os

# Configuration from environment variables
P_MIN = float(os.getenv("P_MIN", "0.6"))
ENTROPY_MAX = float(os.getenv("ENTROPY_MAX", "0.9"))
MODEL_DIR = os.getenv("MODEL_DIR", "backend/modules/ml/models")
DATA_DIR = os.getenv("DATA_DIR", "data")

@dataclass
class MLState:
    """Machine Learning state management"""
    ready: bool = False
    error: Optional[str] = None
    engine: Optional[object] = None  # EnhancedInferenceEngineStrict

@dataclass
class BrowserState:
    """Browser pool state management"""
    ready: bool = False
    error: Optional[str] = None

# Global application state
ml_state = MLState()
browser_state = BrowserState()

# Convenience functions for checking state
def is_ml_ready() -> bool:
    """Check if ML engine is ready"""
    return ml_state.ready and ml_state.engine is not None

def get_ml_engine():
    """Get the ML engine instance"""
    if not is_ml_ready():
        raise RuntimeError("ML engine is not ready")
    return ml_state.engine

def get_ml_engine_error() -> Optional[str]:
    """Get ML engine error if any"""
    return ml_state.error

def is_browser_ready() -> bool:
    """Check if browser pool is ready"""
    return browser_state.ready

def get_browser_error() -> Optional[str]:
    """Get browser error if any"""
    return browser_state.error