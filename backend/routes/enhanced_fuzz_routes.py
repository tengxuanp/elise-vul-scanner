"""
Enhanced ML Fuzzer Routes with CVSS-based Vulnerability Classification
"""
from fastapi import APIRouter, HTTPException
from typing import List, Dict, Any, Optional
import logging
import json
from pydantic import BaseModel

# Import the enhanced ML fuzzer
try:
    from ..modules.enhanced_ml_fuzzer import EnhancedMLFuzzer, FuzzTarget, FuzzResult, VulnerabilityAssessment, CVSSMetrics
    print("✅ Enhanced ML Fuzzer imported successfully (relative)")
except ImportError as e:
    print(f"❌ Relative import failed: {e}")
    try:
        from modules.enhanced_ml_fuzzer import EnhancedMLFuzzer, FuzzTarget, FuzzResult, VulnerabilityAssessment, CVSSMetrics
        print("✅ Enhanced ML Fuzzer imported successfully (absolute)")
    except ImportError as e2:
        print(f"❌ Absolute import failed: {e2}")
        print("⚠️ Using fallback classes")
        # Fallback for development
        class FuzzTarget:
            def __init__(self, url: str, param: str, method: str = "GET"):
                self.url = url
                self.param = param
                self.method = method
        
        class FuzzResult:
            def __init__(self, target, payload: str, response_status: int, response_time: float):
                self.target = target
                self.payload = payload
                self.response_status = response_status
                self.response_time = response_time
                self.vulnerability_assessment = None
                self.exploitation_potential = 0.0
        
        class VulnerabilityAssessment:
            def __init__(self, vulnerability_type: str, confidence_score: float, cvss_base_score: float):
                self.vulnerability_type = vulnerability_type
                self.confidence_score = confidence_score
                self.cvss_base_score = cvss_base_score
        
        class EnhancedMLFuzzer:
            def __init__(self):
                print("⚠️ WARNING: Using fallback EnhancedMLFuzzer class!")
            
            def fuzz_multiple_targets(self, targets, top_k):
                print("⚠️ WARNING: Fallback fuzzer called - returning empty results")
                return []

logger = logging.getLogger(__name__)
router = APIRouter(tags=["enhanced-fuzz"])

# Initialize the enhanced ML fuzzer
_enhanced_fuzzer: Optional[EnhancedMLFuzzer] = None

def get_enhanced_fuzzer() -> EnhancedMLFuzzer:
    """Get or initialize the enhanced ML fuzzer"""
    global _enhanced_fuzzer
    if _enhanced_fuzzer is None:
        try:
            _enhanced_fuzzer = EnhancedMLFuzzer()
            logger.info("✅ Enhanced ML Fuzzer initialized successfully")
            logger.info(f"🔍 Fuzzer type: {type(_enhanced_fuzzer)}")
            logger.info(f"🔍 Has vulnerability_patterns: {hasattr(_enhanced_fuzzer, 'vulnerability_patterns')}")
            logger.info(f"🔍 Has cvss_templates: {hasattr(_enhanced_fuzzer, 'cvss_templates')}")
        except Exception as e:
            logger.error(f"❌ Failed to initialize Enhanced ML Fuzzer: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to initialize ML Fuzzer: {e}")
    return _enhanced_fuzzer

class FuzzRequest(BaseModel):
    """Request model for fuzzing"""
    url: str
    param: str
    method: str = "GET"

class FuzzResponse(BaseModel):
    """Response model for fuzzing results"""
    url: str
    param: str
    method: str
    payload: str
    response_status: int
    response_time: float
    vulnerability_type: Optional[str] = None
    ml_confidence: Optional[float] = None
    cvss_base_score: Optional[float] = None
    cvss_severity: Optional[str] = None
    combined_risk_score: Optional[float] = None
    exploitation_potential: float = 0.0
    evidence: List[str] = []
    exploitation_complexity: Optional[str] = None

@router.post("/enhanced-fuzz")
async def enhanced_fuzz_endpoint(targets: List[FuzzRequest], top_k: int = 5) -> Dict[str, Any]:
    """
    Enhanced ML Fuzzing with CVSS-based vulnerability classification
    
    This endpoint uses machine learning to:
    1. Classify vulnerabilities (XSS, SQLi, RCE, etc.)
    2. Calculate CVSS scores for industry-standard severity assessment
    3. Provide ML confidence scores
    4. Assess exploitation potential
    """
    try:
        logger.info(f"🚀 Starting enhanced ML fuzzing for {len(targets)} targets")
        
        # Get the enhanced ML fuzzer
        fuzzer = get_enhanced_fuzzer()
        logger.info(f"🔍 Fuzzer instance: {type(fuzzer)}")
        
        # Convert requests to FuzzTarget objects
        fuzz_targets = []
        for target in targets:
            fuzz_target = FuzzTarget(
                url=target.url,
                param=target.param,
                method=target.method
            )
            fuzz_targets.append(fuzz_target)
            logger.info(f"🎯 Created FuzzTarget: {fuzz_target.url} param={fuzz_target.param}")
        
        # Run enhanced ML fuzzing
        logger.info(f"🧪 Calling fuzzer.fuzz_multiple_targets with {len(fuzz_targets)} targets, top_k={top_k}")
        results = fuzzer.fuzz_multiple_targets(fuzz_targets, top_k)
        logger.info(f"🎉 Fuzzer returned {len(results)} results")
        
        # Convert results to response format
        response_results = []
        logger.info(f"🔄 Converting {len(results)} results to response format")
        
        for i, result in enumerate(results):
            logger.info(f"🔍 Processing result {i+1}: payload={result.payload[:30]}...")
            logger.info(f"🔍 Result type: {type(result)}")
            logger.info(f"🔍 Has vulnerability_assessment: {result.vulnerability_assessment is not None}")
            
            response_result = FuzzResponse(
                url=result.target.url,
                param=result.target.param,
                method=result.target.method,
                payload=result.payload,
                response_status=result.response_status,
                response_time=result.response_time,
                exploitation_potential=result.exploitation_potential
            )
            
            # Add vulnerability assessment if available
            if result.vulnerability_assessment:
                logger.info(f"✅ Adding vulnerability assessment for result {i+1}")
                response_result.vulnerability_type = result.vulnerability_assessment.vulnerability_type.value
                response_result.ml_confidence = result.vulnerability_assessment.confidence_score
                response_result.cvss_base_score = result.vulnerability_assessment.cvss_base_score
                response_result.cvss_severity = result.vulnerability_assessment.cvss_severity.name
                response_result.combined_risk_score = result.vulnerability_assessment.combined_risk_score
                response_result.evidence = result.vulnerability_assessment.evidence
                response_result.exploitation_complexity = result.vulnerability_assessment.exploitation_complexity
            else:
                logger.info(f"❌ No vulnerability assessment for result {i+1}")
            
            response_results.append(response_result)
            logger.info(f"✅ Added response result {i+1}")
        
        # Sort by exploitation potential
        response_results.sort(key=lambda x: x.exploitation_potential, reverse=True)
        
        logger.info(f"🎉 Enhanced ML fuzzing completed: {len(response_results)} results")
        
        return {
            "status": "success",
            "message": f"Enhanced ML fuzzing completed for {len(targets)} targets",
            "results": [result.dict() for result in response_results],
            "summary": {
                "total_targets": len(targets),
                "total_results": len(response_results),
                "vulnerabilities_found": len([r for r in response_results if r.vulnerability_type]),
                "high_risk_vulns": len([r for r in response_results if r.cvss_base_score and r.cvss_base_score >= 7.0]),
                "avg_confidence": sum([r.ml_confidence or 0 for r in response_results]) / len(response_results) if response_results else 0,
                "avg_cvss_score": sum([r.cvss_base_score or 0 for r in response_results]) / len(response_results) if response_results else 0
            }
        }
        
    except Exception as e:
        logger.error(f"❌ Enhanced ML fuzzing failed: {e}")
        raise HTTPException(status_code=500, detail=f"Enhanced ML fuzzing failed: {e}")

@router.post("/fuzz/single")
async def fuzz_single_target(target: FuzzRequest, top_k: int = 5) -> Dict[str, Any]:
    """Fuzz a single target with enhanced ML classification"""
    try:
        logger.info(f"🎯 Starting single target fuzzing: {target.url}")
        
        # Get the enhanced ML fuzzer
        fuzzer = get_enhanced_fuzzer()
        
        # Create FuzzTarget
        fuzz_target = FuzzTarget(
            url=target.url,
            param=target.param,
            method=target.method
        )
        
        # Run fuzzing
        results = fuzzer.fuzz_target(fuzz_target, top_k)
        
        # Convert to response format
        response_results = []
        for result in results:
            response_result = FuzzResponse(
                url=result.target.url,
                param=result.target.param,
                method=result.target.method,
                payload=result.payload,
                response_status=result.response_status,
                response_time=result.response_time,
                exploitation_potential=result.exploitation_potential
            )
            
            if result.vulnerability_assessment:
                response_result.vulnerability_type = result.vulnerability_assessment.vulnerability_type.value
                response_result.ml_confidence = result.vulnerability_assessment.confidence_score
                response_result.cvss_base_score = result.vulnerability_assessment.cvss_base_score
                response_result.cvss_severity = result.vulnerability_assessment.cvss_severity.name
                response_result.combined_risk_score = result.vulnerability_assessment.combined_risk_score
                response_result.evidence = result.vulnerability_assessment.evidence
                response_result.exploitation_complexity = result.vulnerability_assessment.exploitation_complexity
            
            response_results.append(response_result)
        
        # Sort by exploitation potential
        response_results.sort(key=lambda x: x.exploitation_potential, reverse=True)
        
        logger.info(f"✅ Single target fuzzing completed: {len(response_results)} results")
        
        return {
            "status": "success",
            "message": f"Single target fuzzing completed for {target.url}",
            "target": target.dict(),
            "results": [result.dict() for result in response_results],
            "summary": {
                "vulnerabilities_found": len([r for r in response_results if r.vulnerability_type]),
                "high_risk_vulns": len([r for r in response_results if r.cvss_base_score and r.cvss_base_score >= 7.0]),
                "avg_confidence": sum([r.ml_confidence or 0 for r in response_results]) / len(response_results) if response_results else 0,
                "avg_cvss_score": sum([r.cvss_base_score or 0 for r in response_results]) / len(response_results) if response_results else 0
            }
        }
        
    except Exception as e:
        logger.error(f"❌ Single target fuzzing failed: {e}")
        raise HTTPException(status_code=500, detail=f"Single target fuzzing failed: {e}")

@router.get("/enhanced-health")
async def enhanced_health():
    """Health check for enhanced ML fuzzer"""
    try:
        fuzzer = get_enhanced_fuzzer()
        return {
            "status": "healthy",
            "service": "Enhanced ML Fuzzer",
            "ml_models": fuzzer.ml_models,
            "vulnerability_types": [v.value for v in fuzzer.vulnerability_patterns.keys()],
            "cvss_templates": len(fuzzer.cvss_templates)
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "service": "Enhanced ML Fuzzer",
            "error": str(e)
        }

@router.get("/enhanced-info")
async def enhanced_info():
    """Information about the enhanced ML fuzzer"""
    return {
        "service": "Enhanced ML Fuzzer with CVSS-based Vulnerability Classification",
        "description": "Automation Detection & Exploitation of Web Application Vulnerabilities using Machine Learning",
        "features": [
            "ML-enhanced vulnerability classification",
            "CVSS-based severity scoring",
            "Context-aware vulnerability detection",
            "Exploitation potential assessment",
            "OWASP Top 10 coverage",
            "Industry-standard risk assessment"
        ],
        "vulnerability_types": [
            "Cross-Site Scripting (XSS)",
            "SQL Injection (SQLi)",
            "Command Injection (RCE)",
            "Path Traversal (LFI)",
            "Open Redirect",
            "Server-Side Request Forgery (SSRF)",
            "XML External Entity (XXE)",
            "Broken Authentication",
            "Broken Access Control",
            "Insecure Deserialization"
        ],
        "ml_capabilities": [
            "Pattern-based detection",
            "Context-aware scoring",
            "Response analysis",
            "False positive filtering",
            "Confidence scoring",
            "Adaptive payload generation"
        ],
        "cvss_integration": [
            "Base score calculation",
            "Severity level assessment",
            "Context customization",
            "Combined risk scoring",
            "Industry compliance"
        ]
    }
