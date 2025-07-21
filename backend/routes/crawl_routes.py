from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from modules.crawler import crawl_site

router = APIRouter()

class CrawlRequest(BaseModel):
    target_url: str

@router.post("/crawl")
def crawl_endpoint(request: CrawlRequest):
    try:
        endpoints = crawl_site(request.target_url)
        return {"endpoints": endpoints}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Crawling failed: {e}")
