"""
Enhanced Fuzzing Routes with Probe-Enhanced ML Workflow
"""
from fastapi import APIRouter, HTTPException, status
from typing import List, Dict, Any, Optional
import logging
from pydantic import BaseModel

# Import shared ML state
from app_state import is_ml_ready, get_ml_engine, get_ml_engine_error

# Import workflow and evidence
from pipeline.workflow import assess_endpoints
from modules.evidence_schema import write_evidence_row

logger = logging.getLogger(__name__)
router = APIRouter(tags=["enhanced-fuzz"])

class FuzzRequest(BaseModel):
    """Request model for fuzzing"""
    url: str
    param: str
    method: str = "GET"

class FuzzResponse(BaseModel):
    """Response model for fuzzing results with probe evidence"""
    url: str
    param: str
    method: str
    param_in: str
    vulnerability_type: Optional[str] = None
    ml_confidence: Optional[float] = None
    cvss_base_score: Optional[float] = None
    cvss_severity: Optional[str] = None
    evidence: List[str] = []
    probe_results: Optional[Dict[str, Any]] = None
    ml_family: Optional[str] = None

@router.post("/enhanced-fuzz")
async def enhanced_fuzz_endpoint(targets: List[FuzzRequest], top_k: int = 5) -> Dict[str, Any]:
    """
    Enhanced Fuzzing with Probe-Enhanced ML Workflow
    
    This endpoint uses the new workflow to:
    1. Run probes to gather evidence
    2. Apply strict gates based on probe results
    3. Use ML for triage and payload ordering
    4. Persist evidence for reporting
    """
    try:
        logger.info(f"🚀 Starting enhanced fuzzing for {len(targets)} targets")
        
        # Check ML availability - BLOCK if not ready
        if not is_ml_ready():
            error_detail = str(get_ml_engine_error()) if get_ml_engine_error() else "ML engine not initialized"
            logger.error(f"❌ ML not available: {error_detail}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={
                    "error": "MLUnavailable",
                    "detail": "Train and calibrate models before fuzzing."
                }
            )
        
        logger.info("✅ ML engine is ready - proceeding with fuzzing")
        
        # Convert requests to endpoint format for workflow
        endpoints = []
        for target in targets:
            endpoint = {
                "url": target.url,
                "method": target.method,
                "path": target.url.split("?")[0] if "?" in target.url else target.url,
                "param_locs": {
                    "query": [target.param] if "?" in target.url else [],
                    "form": [target.param] if "?" not in target.url else [],
                    "json": []
                }
            }
            endpoints.append(endpoint)
        
        # Generate job ID for evidence tracking
        import uuid
        job_id = str(uuid.uuid4())
        
        # Run the workflow
        logger.info(f"🧪 Running workflow for {len(endpoints)} endpoints")
        workflow_result = assess_endpoints(endpoints, job_id, top_k)
        logger.info(f"🎉 Workflow returned {len(workflow_result.get('findings', []))} findings")
        
        # Convert findings to response format
        response_results = []
        for finding in workflow_result.get('findings', []):
            target = finding.get('target', {})
            response_result = FuzzResponse(
                url=target.get('url', ''),
                param=target.get('param', ''),
                method=target.get('method', ''),
                param_in=target.get('param_in', ''),
                vulnerability_type=finding.get('vulnerability_type'),
                ml_confidence=finding.get('ml_confidence'),
                cvss_base_score=finding.get('cvss_base_score'),
                cvss_severity=finding.get('cvss_severity'),
                evidence=finding.get('evidence', []),
                probe_results=finding.get('probe_results'),
                ml_family=finding.get('ml_family')
            )
            response_results.append(response_result)
        
        # Sort by CVSS score (highest first)
        response_results.sort(key=lambda x: x.cvss_base_score or 0, reverse=True)
        
        logger.info(f"🎉 Enhanced fuzzing completed: {len(response_results)} results")
        
        return {
            "status": "success",
            "message": f"Enhanced fuzzing completed for {len(targets)} targets",
            "job_id": job_id,
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
        
    except HTTPException:
        # Re-raise HTTP exceptions (like 503 MLUnavailable) without wrapping
        raise
    except Exception as e:
        logger.error(f"❌ Enhanced fuzzing failed: {e}")
        raise HTTPException(status_code=500, detail=f"Enhanced fuzzing failed: {e}")

@router.post("/fuzz/single")
async def fuzz_single_target(target: FuzzRequest, top_k: int = 5) -> Dict[str, Any]:
    """Fuzz a single target with enhanced ML classification"""
    try:
        logger.info(f"🎯 Starting single target fuzzing: {target.url}")
        
        # Check ML availability - BLOCK if not ready
        if not is_ml_ready():
            error_detail = str(get_ml_engine_error()) if get_ml_engine_error() else "ML engine not initialized"
            logger.error(f"❌ ML not available: {error_detail}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={
                    "error": "MLUnavailable",
                    "detail": "Train and calibrate models before fuzzing."
                }
            )
        
        logger.info("✅ ML engine is ready - proceeding with single target fuzzing")
        
        # Convert single target to endpoint format
        endpoint = {
            "url": target.url,
            "method": target.method,
            "path": target.url.split("?")[0] if "?" in target.url else target.url,
            "param_locs": {
                "query": [target.param] if "?" in target.url else [],
                "form": [target.param] if "?" not in target.url else [],
                "json": []
            }
        }
        
        # Generate job ID for evidence tracking
        import uuid
        job_id = str(uuid.uuid4())
        
        # Run the workflow
        logger.info(f"🧪 Running workflow for single endpoint")
        workflow_result = assess_endpoints([endpoint], job_id, top_k)
        logger.info(f"🎉 Workflow returned {len(workflow_result.get('findings', []))} findings")
        
        # Convert findings to response format
        response_results = []
        for finding in workflow_result.get('findings', []):
            target = finding.get('target', {})
            response_result = FuzzResponse(
                url=target.get('url', ''),
                param=target.get('param', ''),
                method=target.get('method', ''),
                param_in=target.get('param_in', ''),
                vulnerability_type=finding.get('vulnerability_type'),
                ml_confidence=finding.get('ml_confidence'),
                cvss_base_score=finding.get('cvss_base_score'),
                cvss_severity=finding.get('cvss_severity'),
                evidence=finding.get('evidence', []),
                probe_results=finding.get('probe_results'),
                ml_family=finding.get('ml_family')
            )
            response_results.append(response_result)
        
        # Sort by CVSS score (highest first)
        response_results.sort(key=lambda x: x.cvss_base_score or 0, reverse=True)
        
        logger.info(f"🎉 Single target fuzzing completed: {len(response_results)} results")
        
        return {
            "status": "success",
            "message": f"Single target fuzzing completed for {target.url}",
            "job_id": job_id,
            "results": [result.dict() for result in response_results],
            "summary": {
                "total_targets": 1,
                "total_results": len(response_results),
                "vulnerabilities_found": len([r for r in response_results if r.vulnerability_type]),
                "high_risk_vulns": len([r for r in response_results if r.cvss_base_score and r.cvss_base_score >= 7.0]),
                "avg_confidence": sum([r.ml_confidence or 0 for r in response_results]) / len(response_results) if response_results else 0,
                "avg_cvss_score": sum([r.cvss_base_score or 0 for r in response_results]) / len(response_results) if response_results else 0
            }
        }
        
    except HTTPException:
        # Re-raise HTTP exceptions (like 503 MLUnavailable) without wrapping
        raise
    except Exception as e:
        logger.error(f"❌ Single target fuzzing failed: {e}")
        raise HTTPException(status_code=500, detail=f"Single target fuzzing failed: {e}")

@router.get("/fuzz/status")
async def fuzz_status() -> Dict[str, Any]:
    """Get the status of the enhanced fuzzing system"""
    try:
        # Check ML availability
        ml_ready = is_ml_ready()
        ml_error = get_ml_engine_error()
        
        return {
            "status": "ok",
            "ml_ready": ml_ready,
            "ml_error": ml_error,
            "message": "Enhanced fuzzing system status retrieved successfully"
        }
        
    except Exception as e:
        logger.error(f"❌ Failed to get fuzzing status: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get fuzzing status: {e}")