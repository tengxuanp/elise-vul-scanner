from fastapi import APIRouter
from pydantic import BaseModel
from typing import List, Dict, Any
from starlette.concurrency import run_in_threadpool
from backend.modules.playwright_crawler import crawl_site

router = APIRouter()

class CrawlReq(BaseModel):
    target_url: str

@router.post("/crawl")
async def crawl(req: CrawlReq):
    # Use the real crawler to discover endpoints
    result = await run_in_threadpool(
        crawl_site,
        target_url=req.target_url,
        max_depth=2,
        max_endpoints=30,
        submit_get_forms=True,
        submit_post_forms=True,
        click_buttons=True
    )
    
    # Extract endpoints from the crawl result
    endpoints = result.get("endpoints", [])
    
    return {"endpoints": endpoints}