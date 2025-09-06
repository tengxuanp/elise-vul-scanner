from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, AnyUrl
from typing import List, Optional, Literal
from starlette.concurrency import run_in_threadpool
from modules.playwright_crawler import crawl_site

router = APIRouter()

class AuthConfig(BaseModel):
    type: Literal["form"]
    login_url: AnyUrl
    username_field: str
    password_field: str
    username: str
    password: str
    submit_selector: Optional[str] = None

class CrawlReq(BaseModel):
    target_url: AnyUrl
    max_depth: int = 2
    max_endpoints: int = 30
    submit_get_forms: bool = True
    submit_post_forms: bool = True
    click_buttons: bool = True
    seeds: Optional[List[str]] = None
    auth: Optional[AuthConfig] = None

@router.post("/crawl")
async def crawl(req: CrawlReq):
    print(f"🔍 CANONICAL ROUTE CALLED: target_url={req.target_url}")
    
    # Assert we are calling the correct function
    if getattr(crawl_site, "__module__", "") != "modules.playwright_crawler":
        raise HTTPException(500, detail="Wrong crawler bound (not playwright_crawler.crawl_site)")

    try:
        print(f"🔍 Calling crawl_site with: {str(req.target_url)}, {req.max_depth}, {req.max_endpoints}")
        res = await run_in_threadpool(
            crawl_site,
            str(req.target_url),
            req.max_depth,
            req.max_endpoints,
            req.submit_get_forms,
            req.submit_post_forms,
            req.seeds or [],
            req.auth.dict() if req.auth else None,
            req.click_buttons,
        )
        print(f"🔍 Crawl result: {res.get('meta', {})}")
        print(f"🔍 First endpoint keys: {list(res.get('endpoints', [{}])[0].keys()) if res.get('endpoints') else 'No endpoints'}")
    except Exception as e:
        print(f"🔍 Crawler error: {e}")
        raise HTTPException(500, detail=f"Crawler error: {e}")

    # Hard sanity: endpoints must come from real interaction
    meta = res.get("meta") or {}
    if len(res.get("endpoints") or []) > 0 and (meta.get("pagesVisited", 0) == 0):
        raise HTTPException(500, detail="Crawler produced endpoints without visiting any page (wrong engine?)")
    return res