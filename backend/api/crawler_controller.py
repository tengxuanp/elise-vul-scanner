from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
from subprocess import Popen
import json
import os
import time

router = APIRouter()

PROXY_SCRIPT = "./proxy_api_crawler.py"
CAPTURE_FILE = "./proxy_captured_endpoints.json"

# Simple in-memory status tracking (for demo only)
crawl_status = {"status": "idle"}

class CrawlRequest(BaseModel):
    target_domains: list[str]

@router.post("/crawl")
def start_crawl(request: CrawlRequest, background_tasks: BackgroundTasks):
    if crawl_status["status"] == "running":
        raise HTTPException(status_code=400, detail="Crawl already running.")

    # Save target domains to a file or env
    with open("target_domains.json", "w") as f:
        json.dump(request.target_domains, f)

    # Start mitmproxy as a background process
    background_tasks.add_task(run_proxy_with_script)
    crawl_status["status"] = "running"
    return {"message": "Proxy-based crawl started."}

def run_proxy_with_script():
    try:
        # Clean previous captures
        if os.path.exists(CAPTURE_FILE):
            os.remove(CAPTURE_FILE)

        # Start mitmdump with inline script (uses saved target_domains.json)
        proc = Popen(["mitmdump", "-s", PROXY_SCRIPT])
        time.sleep(60)  # Run proxy for 60 seconds (adjust as needed)
        proc.terminate()
    finally:
        crawl_status["status"] = "completed"

@router.get("/crawl/result")
def get_crawl_result():
    if crawl_status["status"] == "running":
        return {"status": "pending"}
    
    if not os.path.exists(CAPTURE_FILE):
        return {"status": "completed", "endpoints": [], "captured_requests": []}

    with open(CAPTURE_FILE) as f:
        captured = json.load(f)

    return {
        "status": "completed",
        "endpoints": [],  # You can merge this with deduped results if you want
        "captured_requests": captured
    }
