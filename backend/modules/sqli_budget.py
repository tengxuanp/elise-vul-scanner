"""
SQLi Short-Circuit Budget Management

Tracks site-wide SQLi outcomes and implements short-circuiting to reduce unnecessary probes.
"""

import os
from collections import deque
from typing import Optional

# Configuration from environment
M = int(os.getenv("ELISE_SQLI_SHORTCIRCUIT_M", 12))  # consecutive null attempts to trigger pause
K = int(os.getenv("ELISE_SQLI_SHORTCIRCUIT_K", 20))  # endpoints to skip once paused
WHITELIST = {"id", "q", "query", "search", "user", "product", "item", "token", "param", "value"}

class SQLiBudget:
    """Manages SQLi short-circuit budget across a site."""
    
    def __init__(self):
        self.null_streak = 0
        self.paused_until = 0  # endpoints processed count
        self.processed = 0
        self.total_attempts = 0
        self.total_signals = 0
        self.recent_outcomes = deque(maxlen=50)  # Keep last 50 outcomes for analysis
    
    def note_result(self, had_signal: bool, param_name: Optional[str] = None):
        """
        Record a SQLi attempt result.
        
        Args:
            had_signal: Whether the attempt produced any SQLi signals
            param_name: Parameter name (for whitelist checking)
        """
        self.processed += 1
        self.total_attempts += 1
        
        if had_signal:
            self.total_signals += 1
            self.null_streak = 0
            self.paused_until = 0
        else:
            self.null_streak += 1
            if self.null_streak >= M and self.paused_until == 0:
                self.paused_until = self.processed + K
        
        # Track recent outcomes for analysis
        self.recent_outcomes.append({
            "had_signal": had_signal,
            "param_name": param_name,
            "processed": self.processed
        })
    
    def is_paused(self, param_name: Optional[str] = None) -> bool:
        """
        Check if SQLi should be paused for this parameter.
        
        Args:
            param_name: Parameter name to check against whitelist
            
        Returns:
            True if SQLi should be paused, False otherwise
        """
        # Whitelist parameters always bypass pause
        if param_name and param_name.lower() in WHITELIST:
            return False
        
        # Check if we're in the pause period
        return self.paused_until != 0 and self.processed < self.paused_until
    
    def get_status(self) -> dict:
        """
        Get current budget status.
        
        Returns:
            Dictionary with budget status information
        """
        return {
            "null_streak": self.null_streak,
            "paused_until": self.paused_until,
            "processed": self.processed,
            "total_attempts": self.total_attempts,
            "total_signals": self.total_signals,
            "is_paused": self.is_paused(),
            "success_rate": self.total_signals / max(self.total_attempts, 1),
            "recent_outcomes_count": len(self.recent_outcomes)
        }
    
    def reset(self):
        """Reset the budget (useful for testing)."""
        self.null_streak = 0
        self.paused_until = 0
        self.processed = 0
        self.total_attempts = 0
        self.total_signals = 0
        self.recent_outcomes.clear()

# Global budget instance
_sqli_budget = None

def get_sqli_budget() -> SQLiBudget:
    """Get the global SQLi budget instance."""
    global _sqli_budget
    if _sqli_budget is None:
        _sqli_budget = SQLiBudget()
    return _sqli_budget

def reset_sqli_budget():
    """Reset the global SQLi budget (useful for testing)."""
    global _sqli_budget
    if _sqli_budget is not None:
        _sqli_budget.reset()
