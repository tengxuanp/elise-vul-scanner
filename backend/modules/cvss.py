#!/usr/bin/env python3
"""
CVSS vector builder for vulnerability assessment
"""

from dataclasses import dataclass
from typing import Dict, Any, List

@dataclass
class CVSSVector:
    """CVSS vector representation"""
    vector: str
    score: float
    severity: str
    assumptions: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "vector": self.vector,
            "score": self.score,
            "severity": self.severity,
            "assumptions": self.assumptions
        }

def build_cvss_vector(vuln_type: str, context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build CVSS v3.1 vector with transparent assumptions for vulnerability assessment.
    
    Heuristics (documented):
    - XSS (reflected): AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
    - SQLi (error-based): AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H  
    - Redirect: AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N
    
    Args:
        vuln_type: Vulnerability type (xss, sqli, redirect, etc.)
        context: Additional context (e.g., xss_context, sql_error_type)
        
    Returns:
        Dictionary with vector, score, and assumptions
    """
    assumptions = []
    
    if vuln_type == "xss":
        # XSS (reflected): AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
        xss_context = context.get("xss_context", "html")
        
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
        score = 6.1
        
        # Document assumptions based on context
        assumptions.append("Reflected XSS vulnerability")
        assumptions.append("Network accessible (AV:N)")
        assumptions.append("Low attack complexity (AC:L)")
        assumptions.append("No privileges required (PR:N)")
        assumptions.append("User interaction required (UI:R)")
        assumptions.append("Scope changed (S:C)")
        assumptions.append("Low confidentiality impact (C:L)")
        assumptions.append("Low integrity impact (I:L)")
        assumptions.append("No availability impact (A:N)")
        
        if xss_context == "html":
            assumptions.append("XSS in HTML context - script execution possible")
        elif xss_context == "attr":
            assumptions.append("XSS in attribute context - limited execution")
        elif xss_context == "js":
            assumptions.append("XSS in JavaScript context - code injection possible")
        else:
            assumptions.append(f"XSS context: {xss_context}")
    
    elif vuln_type == "sqli":
        # SQLi (error-based): AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        score = 9.8
        
        # Document assumptions for SQL injection
        assumptions.append("SQL injection vulnerability")
        assumptions.append("Network accessible (AV:N)")
        assumptions.append("Low attack complexity (AC:L)")
        assumptions.append("No privileges required (PR:N)")
        assumptions.append("No user interaction required (UI:N)")
        assumptions.append("Scope unchanged (S:U)")
        assumptions.append("High confidentiality impact (C:H)")
        assumptions.append("High integrity impact (I:H)")
        assumptions.append("High availability impact (A:H)")
        assumptions.append("Database access assumed")
        assumptions.append("Error-based SQL injection detected")
        
        # Add context-specific assumptions
        if context.get("sql_error_type"):
            assumptions.append(f"SQL error type: {context['sql_error_type']}")
    
    elif vuln_type == "redirect":
        # Redirect: AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"
        score = 4.3
        
        # Document assumptions for open redirect
        assumptions.append("Open redirect vulnerability")
        assumptions.append("Network accessible (AV:N)")
        assumptions.append("Low attack complexity (AC:L)")
        assumptions.append("No privileges required (PR:N)")
        assumptions.append("User interaction required (UI:R)")
        assumptions.append("Scope unchanged (S:U)")
        assumptions.append("Low confidentiality impact (C:L)")
        assumptions.append("Low integrity impact (I:L)")
        assumptions.append("No availability impact (A:N)")
        assumptions.append("Redirects to external domains")
        assumptions.append("Potential for phishing attacks")
    
    else:
        # Generic vulnerability - conservative scoring
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"
        score = 5.4
        
        assumptions.append(f"Generic {vuln_type} vulnerability")
        assumptions.append("Network accessible (AV:N)")
        assumptions.append("Low attack complexity (AC:L)")
        assumptions.append("No privileges required (PR:N)")
        assumptions.append("User interaction required (UI:R)")
        assumptions.append("Scope unchanged (S:U)")
        assumptions.append("Low confidentiality impact (C:L)")
        assumptions.append("Low integrity impact (I:L)")
        assumptions.append("No availability impact (A:N)")
        assumptions.append("Conservative scoring applied")
    
    return {
        "vector": vector,
        "score": score,
        "assumptions": assumptions
    }

def calculate_cvss_score(vuln_type: str, context: Dict[str, Any] = None) -> float:
    """
    Calculate CVSS score for a vulnerability type.
    
    Args:
        vuln_type: Vulnerability type (xss, sqli, redirect, etc.)
        context: Additional context for scoring
        
    Returns:
        CVSS base score
    """
    if context is None:
        context = {}
    
    result = build_cvss_vector(vuln_type, context)
    return result["score"]
