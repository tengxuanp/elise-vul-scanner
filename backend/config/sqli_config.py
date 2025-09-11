"""
SQLi Configuration Toggles

Environment variables for configuring strict SQLi decision policies.
All variables have sane defaults and can be overridden via environment.
"""

import os

# Boolean-based SQLi thresholds
SQLI_BOOLEAN_THRESHOLD_POS = float(os.getenv("ELISE_SQLI_BOOLEAN_THRESHOLD_POS", "0.30"))
SQLI_BOOLEAN_THRESHOLD_SUSPECT = float(os.getenv("ELISE_SQLI_BOOLEAN_THRESHOLD_SUSPECT", "0.15"))

# Timing-based SQLi thresholds
SQLI_TIMING_SLOWDOWN_POS = float(os.getenv("ELISE_SQLI_TIMING_SLOWDOWN_POS", "1.5"))

# Confirmation trial settings
SQLI_CONFIRM_TRIALS = int(os.getenv("ELISE_SQLI_CONFIRM_TRIALS", "3"))

# URL parameter suppression
SQLI_SUPPRESS_URL_PARAMS = os.getenv("ELISE_SQLI_SUPPRESS_URL_PARAMS", "1") == "1"

# Debug logging
SQLI_DEBUG_DECISIONS = os.getenv("ELISE_SQLI_DEBUG_DECISIONS", "0") == "1"

# Configuration summary
CONFIG = {
    "boolean_threshold_positive": SQLI_BOOLEAN_THRESHOLD_POS,
    "boolean_threshold_suspect": SQLI_BOOLEAN_THRESHOLD_SUSPECT,
    "timing_slowdown_positive": SQLI_TIMING_SLOWDOWN_POS,
    "confirm_trials": SQLI_CONFIRM_TRIALS,
    "suppress_url_params": SQLI_SUPPRESS_URL_PARAMS,
    "debug_decisions": SQLI_DEBUG_DECISIONS
}

def get_config_summary():
    """Get a summary of current SQLi configuration"""
    return {
        "sqli_config": CONFIG
    }