"""
Strict SQLi Decision Logic

Implements non-negotiable SQLi decision policy:
- SQLi positives only when reason ∈ {error_signature, boolean_confirmed, time_based_confirmed}
- Reflection never contributes to SQLi
- Boolean/timing require confirm trials with control payloads
- URL-like params are skipped/de-weighted for SQLi unless hard SQL evidence exists
"""

import os
import time
import logging
from typing import Dict, Any, Tuple, Optional, List
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Configuration toggles with sane defaults
SQLI_BOOLEAN_THRESHOLD_POS = float(os.getenv("ELISE_SQLI_BOOLEAN_THRESHOLD_POS", "0.30"))
SQLI_BOOLEAN_THRESHOLD_SUSPECT = float(os.getenv("ELISE_SQLI_BOOLEAN_THRESHOLD_SUSPECT", "0.15"))
SQLI_TIMING_SLOWDOWN_POS = float(os.getenv("ELISE_SQLI_TIMING_SLOWDOWN_POS", "1.5"))
SQLI_CONFIRM_TRIALS = int(os.getenv("ELISE_SQLI_CONFIRM_TRIALS", "3"))

# URL-like parameter keys that should be suppressed for SQLi
LIKELY_URL_KEYS = {
    'url', 'next', 'redirect', 'return', 'continue', 'to', 'target', 'link',
    'callback', 'return_url', 'redirect_url', 'forward', 'goto', 'destination'
}

@dataclass
class ConfirmStats:
    """Statistics from confirmation trials"""
    trials: List[Dict[str, Any]]
    attack_avg_latency: float
    control_avg_latency: float
    attack_avg_length: int
    control_avg_length: int
    delta_latency: float
    delta_length: float
    consistent: bool

def is_url_like_param(param_name: str, param_value: str) -> bool:
    """
    Check if a parameter is likely URL-related and should be suppressed for SQLi
    unless hard SQL evidence exists.
    """
    param_lower = param_name.lower()
    
    # Check if param name is URL-like
    if param_lower in LIKELY_URL_KEYS:
        return True
    
    # Check if value looks like a URL
    if param_value:
        value_lower = param_value.lower()
        if (value_lower.startswith(('http://', 'https://', 'www.')) or 
            value_lower.startswith('/') or
            '://' in value_lower or
            '.' in value_lower and ('/' in value_lower or value_lower.endswith('.com'))):
            return True
    
    return False

def confirm_helper(kind: str, target, payload_used: str, min_trials: int = 3, 
                  min_delta: float = 0.30, min_slowdown: float = 1.5, 
                  stable_status: bool = True) -> Tuple[bool, Optional[ConfirmStats]]:
    """
    Run A/B confirmation trials: candidate payload vs neutral control payload.
    
    Args:
        kind: 'boolean' or 'timing'
        target: Target object for injection
        payload_used: The attack payload that triggered the signal
        min_trials: Minimum trials per condition
        min_delta: Minimum response length delta for boolean
        min_slowdown: Minimum timing slowdown for timing
        stable_status: Whether status codes should be stable
    
    Returns:
        (confirmed, confirm_stats)
    """
    from backend.modules.injector import inject_once
    
    logger.info(f"CONFIRM_HELPER starting {kind} confirmation for payload: {payload_used}")
    
    # Define control payloads
    if kind == 'boolean':
        control_payloads = ["1", "0", "true", "false"]
    elif kind == 'timing':
        control_payloads = ["1", "2", "3", "4"]
    else:
        logger.error(f"Unknown confirmation kind: {kind}")
        return False, None
    
    trials = []
    attack_results = []
    control_results = []
    
    # Run attack trials
    for i in range(min_trials):
        try:
            result = inject_once(
                target.url, target.method, target.param_in, target.param,
                payload_used, target.headers
            )
            attack_results.append({
                'type': 'attack',
                'latency_ms': getattr(result, 'latency_ms', 0),
                'status': getattr(result, 'status', 0),
                'length': len(getattr(result, 'response_body', '')),
                'trial': i + 1
            })
            trials.append(attack_results[-1])
            time.sleep(0.1)  # Small delay between trials
        except Exception as e:
            logger.error(f"Attack trial {i+1} failed: {e}")
            return False, None
    
    # Run control trials
    for i in range(min_trials):
        control_payload = control_payloads[i % len(control_payloads)]
        try:
            result = inject_once(
                target.url, target.method, target.param_in, target.param,
                control_payload, target.headers
            )
            control_results.append({
                'type': 'control',
                'latency_ms': getattr(result, 'latency_ms', 0),
                'status': getattr(result, 'status', 0),
                'length': len(getattr(result, 'response_body', '')),
                'trial': i + 1
            })
            trials.append(control_results[-1])
            time.sleep(0.1)  # Small delay between trials
        except Exception as e:
            logger.error(f"Control trial {i+1} failed: {e}")
            return False, None
    
    # Calculate statistics
    attack_avg_latency = sum(r['latency_ms'] for r in attack_results) / len(attack_results)
    control_avg_latency = sum(r['latency_ms'] for r in control_results) / len(control_results)
    attack_avg_length = sum(r['length'] for r in attack_results) // len(attack_results)
    control_avg_length = sum(r['length'] for r in control_results) // len(control_results)
    
    delta_latency = attack_avg_latency - control_avg_latency
    delta_length = attack_avg_length - control_avg_length
    
    # Check consistency
    attack_statuses = [r['status'] for r in attack_results]
    control_statuses = [r['status'] for r in control_results]
    consistent = (len(set(attack_statuses)) <= 2 and len(set(control_statuses)) <= 2) if stable_status else True
    
    confirm_stats = ConfirmStats(
        trials=trials,
        attack_avg_latency=attack_avg_latency,
        control_avg_latency=control_avg_latency,
        attack_avg_length=attack_avg_length,
        control_avg_length=control_avg_length,
        delta_latency=delta_latency,
        delta_length=delta_length,
        consistent=consistent
    )
    
    # Determine if confirmed based on kind
    if kind == 'boolean':
        confirmed = (abs(delta_length) >= min_delta and consistent)
        logger.info(f"BOOLEAN_CONFIRM delta_length={delta_length:.2f} min_delta={min_delta} consistent={consistent} confirmed={confirmed}")
    elif kind == 'timing':
        slowdown = attack_avg_latency / control_avg_latency if control_avg_latency > 0 else 1.0
        confirmed = (slowdown >= min_slowdown and consistent)
        logger.info(f"TIMING_CONFIRM slowdown={slowdown:.2f} min_slowdown={min_slowdown} consistent={consistent} confirmed={confirmed}")
    else:
        confirmed = False
    
    return confirmed, confirm_stats

def decide_sqli(signals: Dict[str, Any], payload_used: str, target, 
                confirm_helper_func=None) -> Tuple[str, str, Dict[str, Any]]:
    """
    Strict SQLi decision logic with non-negotiable acceptance criteria.
    
    Allowed positive reasons: error_signature, boolean_confirmed, time_based_confirmed
    Suspected: weak_boolean_delta (below positive threshold but ≥ suspect)
    Clean: no_sql_evidence
    Reflection/XSS signals must not appear on SQLi decisions.
    
    Args:
        signals: Probe signals (only sqli.* signals should influence)
        payload_used: The payload that was used
        target: Target object for confirmation trials
        confirm_helper_func: Function to run confirmation trials
    
    Returns:
        (decision, reason, extras)
        - decision: 'positive', 'suspected', 'clean'
        - reason: specific reason code
        - extras: additional metadata
    """
    logger.info(f"SQLI_DECIDER signals={signals} payload={payload_used}")
    
    # Extract SQLi-specific signals only - NO XSS/REFLECTION SIGNALS
    sqli_error_based = signals.get('sqli.error_based', False)
    sqli_boolean_delta = signals.get('sqli.boolean_delta', 0.0)
    sqli_timing_based = signals.get('sqli.timing_based', False)
    
    # STRICT: Never use reflection/XSS signals for SQLi decisions
    xss_reflected = signals.get('xss.reflected', False)
    if xss_reflected:
        logger.info("SQLI_STRICT: Ignoring XSS reflection signal for SQLi decision")
    
    logger.info(f"SQLI_SIGNALS error_based={sqli_error_based} boolean_delta={sqli_boolean_delta} timing_based={sqli_timing_based}")
    
    # Check for URL-like parameter suppression
    if is_url_like_param(target.param, getattr(target, 'param_value', '')):
        if not sqli_error_based:
            logger.info(f"SQLI_SUPPRESSED URL-like param {target.param} without error evidence")
            return ('clean', 'url_param_suppressed', {'param': target.param})
    
    # Decision logic in order of priority - STRICT POSITIVE REASONS ONLY
    
    # 1. Error-based SQLi (highest confidence)
    if sqli_error_based:
        logger.info("SQLI_POSITIVE error_signature")
        # Extract error signature details
        error_signature = {
            'pattern_id': 'sql_error_detected',
            'dbms_guess': 'unknown',  # Could be enhanced with DBMS detection
            'match_snippet': 'SQL error detected in response'
        }
        return ('positive', 'error_signature', {
            'error_based': True,
            'error_signature': error_signature
        })
    
    # 2. Boolean-based SQLi with confirmation (REQUIRED)
    if sqli_boolean_delta >= SQLI_BOOLEAN_THRESHOLD_POS:
        if confirm_helper_func:
            confirmed, confirm_stats = confirm_helper_func(
                'boolean', target, payload_used, 
                min_trials=SQLI_CONFIRM_TRIALS,
                min_delta=SQLI_BOOLEAN_THRESHOLD_POS,
                stable_status=True
            )
            if confirmed:
                logger.info(f"SQLI_POSITIVE boolean_confirmed delta={sqli_boolean_delta}")
                return ('positive', 'boolean_confirmed', {
                    'delta': sqli_boolean_delta,
                    'confirm_stats': confirm_stats.__dict__ if confirm_stats else None
                })
            else:
                logger.info(f"SQLI_SUSPECTED boolean_unconfirmed delta={sqli_boolean_delta}")
                return ('suspected', 'boolean_unconfirmed', {
                    'delta': sqli_boolean_delta,
                    'confirm_stats': confirm_stats.__dict__ if confirm_stats else None
                })
        else:
            # No confirmation helper available, downgrade to suspected
            logger.info(f"SQLI_SUSPECTED boolean_no_confirm delta={sqli_boolean_delta}")
            return ('suspected', 'boolean_no_confirm', {'delta': sqli_boolean_delta})
    
    # 3. Timing-based SQLi with confirmation (REQUIRED)
    if sqli_timing_based:
        if confirm_helper_func:
            confirmed, confirm_stats = confirm_helper_func(
                'timing', target, payload_used,
                min_trials=SQLI_CONFIRM_TRIALS,
                min_slowdown=SQLI_TIMING_SLOWDOWN_POS
            )
            if confirmed:
                logger.info("SQLI_POSITIVE time_based_confirmed")
                return ('positive', 'time_based_confirmed', {
                    'timing_based': True,
                    'confirm_stats': confirm_stats.__dict__ if confirm_stats else None
                })
            else:
                logger.info("SQLI_SUSPECTED time_based_unconfirmed")
                return ('suspected', 'time_based_unconfirmed', {
                    'timing_based': True,
                    'confirm_stats': confirm_stats.__dict__ if confirm_stats else None
                })
        else:
            # No confirmation helper available, downgrade to suspected
            logger.info("SQLI_SUSPECTED time_based_no_confirm")
            return ('suspected', 'time_based_no_confirm', {'timing_based': True})
    
    # 4. Weak boolean delta (suspected only)
    if sqli_boolean_delta >= SQLI_BOOLEAN_THRESHOLD_SUSPECT:
        logger.info(f"SQLI_SUSPECTED weak_boolean_delta={sqli_boolean_delta}")
        return ('suspected', 'weak_boolean_delta', {'delta': sqli_boolean_delta})
    
    # 5. No SQL evidence (clean)
    logger.info("SQLI_CLEAN no_sql_evidence")
    return ('clean', 'no_sql_evidence', {})

def should_suppress_sqli_for_param(param_name: str, param_value: str, 
                                 has_error_evidence: bool = False) -> bool:
    """
    Determine if SQLi should be suppressed for a URL-like parameter.
    
    Args:
        param_name: Parameter name
        param_value: Parameter value
        has_error_evidence: Whether hard SQL error evidence exists
    
    Returns:
        True if SQLi should be suppressed
    """
    if has_error_evidence:
        # Never suppress if we have hard SQL error evidence
        return False
    
    return is_url_like_param(param_name, param_value)
