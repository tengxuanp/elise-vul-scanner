"""
Canonical Fuzz Routes - /api/fuzz
Implements the standardized fuzzing endpoint contract
"""

from fastapi import APIRouter, HTTPException
from typing import List, Dict, Any
import logging
import uuid

# Import fuzzing modules
try:
    from pipeline.workflow import assess_endpoints
    from app_state import ml_state
    from modules.cvss import calculate_cvss_score
    FUZZ_AVAILABLE = True
except ImportError as e:
    logging.error(f"Failed to import fuzz modules: {e}")
    FUZZ_AVAILABLE = False

logger = logging.getLogger(__name__)
router = APIRouter(tags=["fuzz"])

@router.post("/fuzz")
async def fuzz_endpoint(request: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Canonical fuzz endpoint that performs vulnerability fuzzing on predicted endpoints.
    
    Request body:
    {
        "predictions": [
            {
                "endpoint": {...},
                "family": "xss"|"sqli"|"redirect"|"none",
                "confidence": number,
                "calibrated": true,
                "features_used": 48
            }
        ]
    }
    
    Response:
    [
        {
            "endpoint": {...},
            "family": "...",
            "payload": str,
            "signals": {
                "sql_error": bool,
                "xss_raw": bool,
                "xss_js": bool,
                "open_redirect": bool,
                "reflection": {
                    "raw": bool,
                    "encoded": bool,
                    "partial": bool,
                    "js_context": bool
                }
            },
            "evidence": [
                {
                    "type": "response"|"dom"|"redirect",
                    "detail": str
                }
            ],
            "cvss": {
                "base": number,
                "severity": "None"|"Low"|"Medium"|"High"|"Critical",
                "vector": str
            },
            "rationale": str
        }
    ]
    """
    try:
        predictions = request.get("predictions", [])
        
        if not predictions:
            raise HTTPException(400, "predictions array is required")
        
        # Check if fuzzing is available
        if not FUZZ_AVAILABLE:
            raise HTTPException(500, {
                "error": "FuzzUnavailable",
                "detail": "Fuzzing pipeline not available. Check dependencies."
            })
        
        if not ml_state.ready:
            raise HTTPException(500, {
                "error": "MLEngineUnavailable",
                "detail": ml_state.error or "ML engine not ready"
            })
        
        logger.info(f"🧪 Starting canonical fuzzing for {len(predictions)} predictions")
        
        # Convert predictions to endpoint format for workflow
        endpoints = []
        for pred in predictions:
            endpoint = pred.get("endpoint", {})
            endpoints.append(endpoint)
        
        # Generate job ID for evidence tracking
        job_id = str(uuid.uuid4())
        
        # Run the fuzzing workflow
        result = assess_endpoints(endpoints, job_id, top_k=5)
        
        # Convert to canonical format
        fuzz_results = []
        for finding in result.get("findings", []):
            target = finding.get("target", {})
            endpoint = finding.get("endpoint", {})
            
            # Map ML family to canonical family
            ml_family = finding.get("ml_family", "none")
            canonical_family = "none"
            
            if ml_family in ["xss", "reflected_xss", "stored_xss"]:
                canonical_family = "xss"
            elif ml_family in ["sqli", "sql_injection"]:
                canonical_family = "sqli"
            elif ml_family in ["redirect", "open_redirect"]:
                canonical_family = "redirect"
            
            # Extract signals from probe results
            probe_results = finding.get("probe_results", {})
            signals = {
                "sql_error": probe_results.get("sql_error", False),
                "xss_raw": probe_results.get("xss_raw", False),
                "xss_js": probe_results.get("xss_js", False),
                "open_redirect": probe_results.get("open_redirect", False),
                "reflection": {
                    "raw": probe_results.get("reflection_raw", False),
                    "encoded": probe_results.get("reflection_encoded", False),
                    "partial": probe_results.get("reflection_partial", False),
                    "js_context": probe_results.get("reflection_js_context", False)
                }
            }
            
            # Convert evidence to canonical format
            evidence = []
            for ev in finding.get("evidence", []):
                evidence.append({
                    "type": ev.get("type", "response"),
                    "detail": ev.get("detail", "")
                })
            
            # Calculate CVSS score
            cvss_base = finding.get("cvss_base_score", 0.0)
            cvss_severity = "None"
            if cvss_base >= 9.0:
                cvss_severity = "Critical"
            elif cvss_base >= 7.0:
                cvss_severity = "High"
            elif cvss_base >= 4.0:
                cvss_severity = "Medium"
            elif cvss_base > 0.0:
                cvss_severity = "Low"
            
            cvss_vector = finding.get("cvss_vector", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
            
            fuzz_result = {
                "endpoint": {
                    "url": endpoint.get("url", ""),
                    "method": endpoint.get("method", "GET"),
                    "params": endpoint.get("param_names", []),
                    "param_locs": endpoint.get("param_locs", {
                        "query": [],
                        "form": [],
                        "json": []
                    }),
                    "content_type": endpoint.get("content_type", "text/html")
                },
                "family": canonical_family,
                "payload": finding.get("payload", ""),
                "signals": signals,
                "evidence": evidence,
                "cvss": {
                    "base": cvss_base,
                    "severity": cvss_severity,
                    "vector": cvss_vector
                },
                "rationale": finding.get("rationale", f"ML confidence: {finding.get('ml_confidence', 0.0):.2f}")
            }
            fuzz_results.append(fuzz_result)
        
        logger.info(f"✅ Canonical fuzzing completed: {len(fuzz_results)} results")
        
        return fuzz_results
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Canonical fuzzing failed: {e}")
        raise HTTPException(500, f"Fuzzing failed: {str(e)}")

