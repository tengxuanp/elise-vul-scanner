"""
Assessment API routes - handles vulnerability assessment with clear mode semantics.
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field, validator
from typing import Optional, List, Dict, Any, Union, Literal
import json
import os
from pathlib import Path
from starlette.concurrency import run_in_threadpool

from backend.app_state import DATA_DIR, USE_ML, REQUIRE_RANKER
from backend.modules.fuzzer_core import run_job
from backend.pipeline.workflow import assess_endpoints
from backend.modules.strategy import parse_strategy, validate_strategy_requirements, ScanStrategy
from backend.modules.event_aggregator import reset_aggregator
# from backend.modules.ml.infer_ranker import available_models, using_defaults  # Not used in this file
from backend.routes.canonical_healthz_routes import get_healthz_data

router = APIRouter()

class AssessRequest(BaseModel):
    job_id: str = Field(..., description="Unique job identifier")
    
    # Pathway A: Explicit endpoint selection
    endpoints: Optional[List[Dict[str, Any]]] = Field(None, description="Explicit endpoints to assess")
    
    # Pathway B: Direct target URL assessment
    target_url: Optional[str] = Field(None, description="Target URL for direct assessment")
    persist_after_crawl: Optional[bool] = Field(False, description="Persist endpoints after crawl")
    
    # Common options
    top_k: Optional[int] = Field(3, description="Number of top payloads to try per family")
    strategy: Optional[str] = Field(None, description="Scan strategy: auto, probe_only, ml_only, hybrid")
    xss_ctx_invoke: Optional[Literal["auto", "always", "never", "force_ml"]] = Field(None, description="XSS context classifier invocation mode")
    
    @validator('*', pre=True, always=True)
    def validate_single_pathway(cls, v, values):
        """Ensure exactly one pathway is specified."""
        if 'endpoints' in values and 'target_url' in values:
            if values['endpoints'] is not None and values['target_url'] is not None:
                raise ValueError("Cannot specify both 'endpoints' and 'target_url'. Choose one pathway.")
        return v

class AssessResponse(BaseModel):
    job_id: str
    mode: str  # "direct" | "from_persisted" | "crawl_then_assess"
    summary: Dict[str, int]
    results: List[Dict[str, Any]]
    findings: List[Dict[str, Any]]
    meta: Dict[str, Any]
    healthz: Dict[str, Any]

@router.post("/assess", response_model=AssessResponse)
async def assess_vulnerabilities(request: AssessRequest):
    """
    Assess vulnerabilities using one of three pathways:
    - (A) endpoints[]: explicit endpoint selection
    - (B) target_url: direct assessment with optional persistence
    - (C) job_id only: load from persisted endpoints.json
    """
    try:
        # Parse and validate strategy
        strategy = parse_strategy(request.strategy)
        
        # Get health data to check ML availability
        health_data = get_healthz_data()
        ml_available = health_data.get("ml_active", False) and any(
            model.get("has_model", False) for model in health_data.get("models_available", {}).values()
        )
        
        # Validate strategy requirements
        strategy_validation = validate_strategy_requirements(strategy, ml_available)
        
        # Reset event aggregator for this assessment
        reset_aggregator()
        
        # Get XSS context invoke mode
        ctx_mode = request.xss_ctx_invoke or os.getenv("ELISE_XSS_CTX_INVOKE", "auto")
        
        # Determine pathway and mode
        mode = None
        endpoints = None
        target_url = None
        
        if request.endpoints is not None:
            # Pathway A: Explicit endpoints
            mode = "direct"
            endpoints = request.endpoints
        elif request.target_url is not None:
            # Pathway B: Direct target URL
            mode = "crawl_then_assess" if request.persist_after_crawl else "direct"
            target_url = request.target_url
        else:
            # Pathway C: Load from persisted endpoints
            mode = "from_persisted"
            endpoints_path = DATA_DIR / "jobs" / request.job_id / "endpoints.json"
            
            if not endpoints_path.exists():
                raise HTTPException(
                    status_code=422, 
                    detail=f"No persisted endpoints found for job_id: {request.job_id}. Run /api/crawl first or provide endpoints/target_url."
                )
            
            with open(endpoints_path, 'r') as f:
                persisted_data = json.load(f)
                endpoints = persisted_data.get("endpoints", [])
                target_url = persisted_data.get("target_url")
        
        # Run assessment
        if target_url and mode != "from_persisted":
            # Use target_url pathway (but not for from_persisted mode)
            result = await run_in_threadpool(
                run_job,
                target_url=target_url,
                job_id=request.job_id,
                top_k=request.top_k or 3,
                strategy=strategy.value,
                ctx_mode=ctx_mode
            )
        else:
            # Use endpoints pathway with deterministic enumeration
            if not endpoints:
                raise HTTPException(status_code=422, detail="No endpoints provided")
            
            result = await run_in_threadpool(
                assess_endpoints,
                endpoints=endpoints,
                job_id=request.job_id,
                top_k=request.top_k or 3,
                strategy=strategy.value,
                ctx_mode=ctx_mode
            )
        
        # Handle persist-after-crawl for target_url pathway
        persist_warning = None
        if target_url and request.persist_after_crawl:
            try:
                # Get endpoints from the pipeline result
                pipeline_endpoints = result.get("endpoints", [])
                if pipeline_endpoints:
                    # Create job directory
                    job_dir = DATA_DIR / "jobs" / request.job_id
                    job_dir.mkdir(parents=True, exist_ok=True)
                    
                    # Write endpoints.json with same shape as /api/crawl
                    endpoints_path = job_dir / "endpoints.json"
                    with open(endpoints_path, 'w') as f:
                        json.dump({
                            "job_id": request.job_id,
                            "target_url": target_url,
                            "endpoints": pipeline_endpoints,
                            "endpoints_count": len(pipeline_endpoints),
                            "crawl_opts": {}  # Default crawl options
                        }, f, indent=2)
                    
                    # Set mode to crawl_then_assess
                    mode = "crawl_then_assess"
            except Exception as e:
                persist_warning = f"Failed to persist endpoints: {str(e)}"
        
        # Use summary from workflow result (includes confirmed_probe and confirmed_ml_inject)
        results = result.get("results", [])
        summary = result.get("summary", {
            "total": len(results),
            "positive": len([r for r in results if r.get("decision") == "positive"]),
            "suspected": len([r for r in results if r.get("decision") == "suspected"]),
            "abstain": len([r for r in results if r.get("decision") == "abstain"]),
            "na": len([r for r in results if r.get("decision") == "not_applicable"])
        })
        
        # Get healthz data
        healthz_data = get_healthz_data()
        
        # Prepare meta with persist warning if applicable
        meta = result.get("meta", {})
        if persist_warning:
            meta["persist_warning"] = persist_warning
        
        # Add strategy information to meta
        meta["strategy"] = strategy.value
        meta["strategy_validation"] = strategy_validation
        meta["xss_ctx_invoke"] = ctx_mode
        
        return AssessResponse(
            job_id=request.job_id,
            mode=mode,
            summary=summary,
            results=results,
            findings=result.get("findings", []),
            meta=meta,
            healthz=healthz_data
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Assessment failed: {str(e)}")
