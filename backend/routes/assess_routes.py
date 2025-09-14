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
from backend.modules.event_aggregator import reset_aggregator, set_current_job
# from backend.modules.ml.infer_ranker import available_models, using_defaults  # Not used in this file
from backend.routes.canonical_healthz_routes import get_healthz_data

router = APIRouter()

class XSSConfig(BaseModel):
    ml_mode: Literal["auto", "always", "never", "force_ml"] = "auto"
    tau_ml: float = Field(0.80, ge=0.0, le=1.0)
    rule_conf_gate: float = Field(0.85, ge=0.0, le=1.0)
    topk: int = Field(3, ge=1, le=20)

class SQLiConfig(BaseModel):
    ml_mode: Literal["auto", "always", "never", "force_ml"] = "never"
    short_circuit: Dict[str, Any] = Field(default_factory=lambda: {"enabled": True, "M": 12, "K": 20})
    topk: int = Field(6, ge=1, le=20)

class StrategyConfig(BaseModel):
    strategy: Literal["rules_only", "smart_xss", "full_smart", "exhaustive"] = "smart_xss"
    families: List[str] = Field(default_factory=lambda: ["xss", "sqli"])
    xss: XSSConfig = Field(default_factory=XSSConfig)
    sqli: SQLiConfig = Field(default_factory=SQLiConfig)

def apply_strategy_config(strategy_config: Optional[StrategyConfig]) -> Dict[str, Any]:
    """
    Apply strategy configuration to environment variables and return effective settings.
    
    Args:
        strategy_config: Strategy configuration object
        
    Returns:
        Dictionary with effective settings for the assessment
    """
    if not strategy_config:
        # Default to Smart-XSS (Auto) semantics
        return {
            "strategy": "auto",
            "xss_ctx_invoke": "auto",
            "top_k": 3,
            "families": ["xss", "sqli"]
        }
    
    # Map new strategy names to legacy strategy values
    strategy_mapping = {
        "rules_only": "probe_only",
        "smart_xss": "auto", 
        "full_smart": "ml_with_context",
        "exhaustive": "auto"  # Use auto as base, will be overridden by ML settings
    }
    
    # Map strategy config to internal flags
    effective_settings = {
        "strategy": strategy_mapping.get(strategy_config.strategy, "auto"),
        "families": strategy_config.families
    }
    
    # XSS configuration
    if strategy_config.xss:
        effective_settings["xss_ctx_invoke"] = strategy_config.xss.ml_mode
        effective_settings["top_k"] = strategy_config.xss.topk
        
        # Set environment variables for XSS gates
        os.environ["ELISE_ML_OVERRIDE_GATE"] = str(strategy_config.xss.tau_ml)
        os.environ["ELISE_RULE_CONF_GATE"] = str(strategy_config.xss.rule_conf_gate)
    
    # SQLi configuration
    if strategy_config.sqli:
        # Set SQLi ML mode
        effective_settings["sqli_ml_mode"] = strategy_config.sqli.ml_mode
        effective_settings["sqli_topk"] = strategy_config.sqli.topk
        
        # Set SQLi short-circuit environment variables
        if strategy_config.sqli.short_circuit.get("enabled", True):
            os.environ["ELISE_SQLI_SHORTCIRCUIT_M"] = str(strategy_config.sqli.short_circuit.get("M", 12))
            os.environ["ELISE_SQLI_SHORTCIRCUIT_K"] = str(strategy_config.sqli.short_circuit.get("K", 20))
        else:
            # Disable short-circuit by setting very high values
            os.environ["ELISE_SQLI_SHORTCIRCUIT_M"] = "999"
            os.environ["ELISE_SQLI_SHORTCIRCUIT_K"] = "0"
    
    # Special handling for exhaustive strategy
    if strategy_config.strategy == "exhaustive":
        # Exhaustive should use "always" ML mode and disable short-circuit
        effective_settings["xss_ctx_invoke"] = "always"
        # Short-circuit is already disabled by the SQLi config above
    
    return effective_settings

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
    strategy_config: Optional[StrategyConfig] = Field(None, description="New strategy configuration object")
    
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
    summary: Dict[str, Any]  # Changed from Dict[str, int] to Dict[str, Any] to support nested structure
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
        # FAMILY ENFORCEMENT: Validate strategy_config.families at API boundary
        if request.strategy_config and request.strategy_config.families:
            valid_families = {"xss", "sqli", "redirect"}
            invalid_families = set(request.strategy_config.families) - valid_families
            if invalid_families:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid families in strategy_config: {list(invalid_families)}. Must be one of: {list(valid_families)}"
                )
        
        # Apply strategy configuration if provided
        if request.strategy_config:
            effective_settings = apply_strategy_config(request.strategy_config)
            # Override request parameters with strategy config values
            request.strategy = effective_settings.get("strategy", request.strategy)
            request.xss_ctx_invoke = effective_settings.get("xss_ctx_invoke", request.xss_ctx_invoke)
            request.top_k = effective_settings.get("top_k", request.top_k)
        else:
            # Create default effective_settings for legacy mode
            effective_settings = {
                "strategy": request.strategy,
                "families": ["xss", "sqli", "redirect"],
                "xss_ctx_invoke": request.xss_ctx_invoke or os.getenv("ELISE_XSS_CTX_INVOKE", "auto")
            }
        
        # Parse and validate strategy
        strategy = parse_strategy(request.strategy)
        
        # Get health data to check ML availability
        health_data = get_healthz_data()
        ml_available = health_data.get("ml_active", False) and any(
            model.get("has_model", False) for model in health_data.get("models_available", {}).values()
        )
        
        # Validate strategy requirements
        strategy_validation = validate_strategy_requirements(strategy, ml_available)
        
        # Set current job and reset event aggregator for this assessment
        set_current_job(request.job_id)
        reset_aggregator()
        
        # Get XSS context invoke mode from effective settings
        ctx_mode = effective_settings.get("xss_ctx_invoke", request.xss_ctx_invoke or os.getenv("ELISE_XSS_CTX_INVOKE", "auto"))
        
        # Get SQLi ML mode from strategy config
        sqli_ml_mode = "never"  # Default
        if request.strategy_config and hasattr(request.strategy_config, 'sqli'):
            sqli_ml_mode = request.strategy_config.sqli.ml_mode
        
        
        # Log strategy information
        if request.strategy_config:
            xss = request.strategy_config.xss
            sqli = request.strategy_config.sqli
            sc_enabled = sqli.short_circuit.get('enabled', True)
            sc_text = f"on(M={sqli.short_circuit.get('M', 12)}/K={sqli.short_circuit.get('K', 20)})" if sc_enabled else "off"
            effective_ml_mode = effective_settings.get("xss_ctx_invoke", xss.ml_mode)
            print(f"ASSESS_STRATEGY preset={request.strategy_config.strategy} legacy_strategy={effective_settings['strategy']} xss.ml={effective_ml_mode} xss.topk={xss.topk} sqli.ml={sqli.ml_mode} sqli.topk={sqli.topk} sqli.sc={sc_text}")
        else:
            print(f"ASSESS_STRATEGY preset=legacy strategy={strategy.value} xss.ml={ctx_mode} xss.topk={request.top_k or 3}")
        
        # Determine pathway and mode
        mode = None
        endpoints = None
        target_url = None
        
        if request.endpoints is not None:
            # Pathway A: Explicit endpoints
            mode = "direct"
            endpoints = request.endpoints
        else:
            # Check for persisted endpoints first (Pathway C)
            endpoints_path = DATA_DIR / "jobs" / request.job_id / "endpoints.json"
            
            if endpoints_path.exists():
                # Pathway C: Load from persisted endpoints (preferred for Re-Assess)
                mode = "from_persisted"
                with open(endpoints_path, 'r') as f:
                    persisted_data = json.load(f)
                    endpoints = persisted_data.get("endpoints", [])
                    target_url = persisted_data.get("target_url")
            elif request.target_url is not None:
                # Pathway B: Direct target URL (fallback when no persisted endpoints)
                mode = "crawl_then_assess" if request.persist_after_crawl else "direct"
                target_url = request.target_url
            else:
                # No endpoints or target_url provided
                raise HTTPException(
                    status_code=422, 
                    detail=f"No persisted endpoints found for job_id: {request.job_id}. Run /api/crawl first or provide endpoints/target_url."
                )
        
        # Run assessment
        if target_url and mode != "from_persisted":
            # Use target_url pathway (but not for from_persisted mode)
            result = await run_in_threadpool(
                run_job,
                target_url=target_url,
                job_id=request.job_id,
                top_k=request.top_k or 3,
                strategy=strategy.value,
                ctx_mode=ctx_mode,
                sqli_ml_mode=sqli_ml_mode
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
                ctx_mode=ctx_mode,
                sqli_ml_mode=sqli_ml_mode
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
        
        # Add strategy and plan information to meta
        if request.strategy_config:
            meta["strategy_config"] = request.strategy_config.dict()
            meta["strategy"] = request.strategy_config.strategy
            # Generate plan summary
            xss = request.strategy_config.xss
            sqli = request.strategy_config.sqli
            sc_enabled = sqli.short_circuit.get('enabled', True)
            sc_m = sqli.short_circuit.get('M', 12)
            sc_k = sqli.short_circuit.get('K', 20)
            sc_text = f"M={sc_m}/K={sc_k}" if sc_enabled else "OFF"
            plan_summary = f"XSS={xss.ml_mode} (τ={xss.tau_ml}, rule={xss.rule_conf_gate}), XSS Top-K={xss.topk} • SQLi={sqli.ml_mode}, SQLi Top-K={sqli.topk} • Short-circuit {sc_text} • Families: {', '.join(request.strategy_config.families)}"
            meta["plan_summary"] = plan_summary
        else:
            # Fallback to legacy strategy
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
