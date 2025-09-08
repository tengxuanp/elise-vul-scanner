"""
Feature specification for ML ranking in vulnerability assessment.
Pure functions for building feature vectors from target and probe context.
"""

import re
import math
from typing import Dict, Any


def shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    
    # Count character frequencies
    char_counts = {}
    for char in text:
        char_counts[char] = char_counts.get(char, 0) + 1
    
    # Calculate entropy
    entropy = 0.0
    text_len = len(text)
    for count in char_counts.values():
        p = count / text_len
        if p > 0:
            entropy -= p * math.log2(p)
    
    return entropy


def calculate_ratio(text: str, pattern: str) -> float:
    """Calculate ratio of pattern matches in text."""
    if not text:
        return 0.0
    matches = len(re.findall(pattern, text))
    return matches / len(text)


def count_keywords(text: str, keywords: list) -> int:
    """Count occurrences of keywords in text (case-insensitive)."""
    if not text:
        return 0
    text_lower = text.lower()
    return sum(text_lower.count(keyword.lower()) for keyword in keywords)


def build_features(ctx: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build feature vector from target and probe context.
    
    Args:
        ctx: Context dictionary containing target info and probe results
        
    Returns:
        Flat dictionary of numeric/boolean features
    """
    features = {}
    
    # Basic context
    family = ctx.get('family', '').lower()
    param_in = ctx.get('param_in', '').lower()
    param = ctx.get('param', '')
    payload = ctx.get('payload', '')
    
    # Family and parameter type
    features['family_xss'] = 1 if family == 'xss' else 0
    features['family_sqli'] = 1 if family == 'sqli' else 0
    features['family_redirect'] = 1 if family == 'redirect' else 0
    features['param_in_query'] = 1 if param_in == 'query' else 0
    features['param_in_form'] = 1 if param_in == 'form' else 0
    features['param_in_json'] = 1 if param_in == 'json' else 0
    
    # Probe hints
    features['probe_sql_error'] = 1 if ctx.get('probe_sql_error', False) else 0
    features['probe_timing_delta_gt2s'] = 1 if ctx.get('probe_timing_delta_gt2s', False) else 0
    features['probe_reflection_html'] = 1 if ctx.get('probe_reflection_html', False) else 0
    features['probe_reflection_js'] = 1 if ctx.get('probe_reflection_js', False) else 0
    features['probe_redirect_location_reflects'] = 1 if ctx.get('probe_redirect_location_reflects', False) else 0
    
    # Response/meta
    status_class = ctx.get('status_class', 0)
    features['status_class_2'] = 1 if status_class == 2 else 0
    features['status_class_3'] = 1 if status_class == 3 else 0
    features['status_class_4'] = 1 if status_class == 4 else 0
    features['status_class_5'] = 1 if status_class == 5 else 0
    features['content_type_html'] = 1 if ctx.get('content_type_html', False) else 0
    features['content_type_json'] = 1 if ctx.get('content_type_json', False) else 0
    
    # Context flags
    features['ctx_html'] = 1 if ctx.get('ctx_html', False) else 0
    features['ctx_attr'] = 1 if ctx.get('ctx_attr', False) else 0
    features['ctx_js'] = 1 if ctx.get('ctx_js', False) else 0
    
    # Shape features
    features['param_len'] = len(param)
    features['payload_len'] = len(payload)
    features['alnum_ratio'] = calculate_ratio(payload, r'[a-zA-Z0-9]')
    features['digit_ratio'] = calculate_ratio(payload, r'[0-9]')
    features['symbol_ratio'] = calculate_ratio(payload, r'[^a-zA-Z0-9\s]')
    features['url_encoded_ratio'] = calculate_ratio(payload, r'%[0-9A-Fa-f]{2}')
    features['double_encoded_hint'] = 1 if '%25' in payload else 0
    features['shannon_entropy'] = shannon_entropy(payload)
    
    # XSS-ish features
    features['has_quote'] = 1 if ('"' in payload or "'" in payload) else 0
    features['has_angle'] = 1 if ('<' in payload or '>' in payload) else 0
    features['has_lt_gt'] = 1 if ('<' in payload and '>' in payload) else 0
    features['has_script_tag'] = 1 if '<script' in payload.lower() else 0
    features['has_event_handler'] = 1 if any(handler in payload.lower() for handler in ['onload', 'onerror', 'onclick', 'onmouseover']) else 0
    
    # SQL-ish features
    sql_keywords = ['select', 'union', 'insert', 'update', 'delete', 'drop', 'create', 'alter', 'exec', 'execute']
    features['sql_kw_hits'] = count_keywords(payload, sql_keywords)
    features['balanced_quotes'] = 1 if payload.count("'") % 2 == 0 and payload.count('"') % 2 == 0 else 0
    features['has_comment_seq'] = 1 if any(seq in payload for seq in ['--', '/*', '*/', '#']) else 0
    
    return features
