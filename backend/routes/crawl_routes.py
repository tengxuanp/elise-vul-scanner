"""
Crawl API routes - handles crawling and endpoint discovery with persistence.
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
import json
import os
from pathlib import Path
from starlette.concurrency import run_in_threadpool

from backend.app_state import DATA_DIR
from backend.modules.playwright_crawler import crawl_site

router = APIRouter()

class CrawlRequest(BaseModel):
    job_id: str = Field(..., description="Unique job identifier")
    target_url: str = Field(..., description="Target URL to crawl")
    crawl_opts: Optional[Dict[str, Any]] = Field(None, description="Optional crawl configuration")

class CrawlResponse(BaseModel):
    job_id: str
    mode: str = "crawl_only"
    endpoints_count: int
    endpoints: List[Dict[str, Any]]
    persisted: bool
    path: str

@router.post("/crawl", response_model=CrawlResponse)
async def crawl_endpoints(request: CrawlRequest):
    """
    Crawl a target URL and persist discovered endpoints.
    
    Returns endpoints count and persistence path for subsequent assessment.
    """
    try:
        # Validate target URL
        if not request.target_url.startswith(('http://', 'https://')):
            raise HTTPException(status_code=422, detail="target_url must start with http:// or https://")
        
        # Extract crawl options with defaults
        crawl_opts = request.crawl_opts or {}
        max_depth = crawl_opts.get('max_depth', 2)
        max_endpoints = crawl_opts.get('max_endpoints', 30)
        submit_get_forms = crawl_opts.get('submit_get_forms', True)
        submit_post_forms = crawl_opts.get('submit_post_forms', True)
        click_buttons = crawl_opts.get('click_buttons', True)
        
        # Run crawler in thread pool to avoid sync/async conflict
        crawl_result = await run_in_threadpool(
            crawl_site,
            target_url=request.target_url,
            max_depth=max_depth,
            max_endpoints=max_endpoints,
            submit_get_forms=submit_get_forms,
            submit_post_forms=submit_post_forms,
            click_buttons=click_buttons
        )
        
        endpoints = crawl_result.get("endpoints", [])
        endpoints_count = len(endpoints)
        
        # Persist endpoints to job directory
        job_dir = DATA_DIR / "jobs" / request.job_id
        job_dir.mkdir(parents=True, exist_ok=True)
        
        endpoints_path = job_dir / "endpoints.json"
        with open(endpoints_path, 'w') as f:
            json.dump({
                "job_id": request.job_id,
                "target_url": request.target_url,
                "crawl_opts": crawl_opts,
                "endpoints": endpoints,
                "endpoints_count": endpoints_count
            }, f, indent=2)
        
        return CrawlResponse(
            job_id=request.job_id,
            mode="crawl_only",
            endpoints_count=endpoints_count,
            endpoints=endpoints,  # endpoints are already dictionaries
            persisted=True,
            path=f"jobs/{request.job_id}/endpoints.json"
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Crawl failed: {str(e)}")
