from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from modules.playwright_crawler import crawl_site
from modules.categorize_endpoints import process_crawl_results
from urllib.parse import urlparse
import json
import os
from pathlib import Path
import threading

router = APIRouter()

DATA_PATH = "./data"
CRAWL_RESULT_FILE = os.path.join(DATA_PATH, "crawl_result.json")
crawl_status = {"status": "idle"}

class CrawlRequest(BaseModel):
    target_url: str

@router.post("/crawl")
def start_crawl(request: CrawlRequest):
    if crawl_status["status"] == "running":
        raise HTTPException(status_code=400, detail="Crawl already running.")

    crawl_status["status"] = "running"
    os.makedirs(DATA_PATH, exist_ok=True)

    def run_crawl():
        try:
            endpoints, captured_requests = crawl_site(request.target_url)

            with open(CRAWL_RESULT_FILE, "w", encoding="utf-8") as f:
                json.dump({
                    "endpoints": endpoints,
                    "captured_requests": captured_requests
                }, f, indent=2)

            process_crawl_results(
                input_path=Path(CRAWL_RESULT_FILE),
                output_dir=Path(DATA_PATH) / "results",
                target_url=request.target_url
            )

            crawl_status["status"] = "completed"
        except Exception as e:
            crawl_status["status"] = "error"
            print(f"[ERROR] Crawl failed: {e}")

    # 🔁 Fire-and-forget crawl in background
    threading.Thread(target=run_crawl).start()

    return {"status": "started"}

@router.get("/crawl/result")
def get_crawl_result():
    if crawl_status["status"] == "running":
        return {"status": "pending"}

    if not os.path.exists(CRAWL_RESULT_FILE):
        return {"status": "completed", "endpoints": [], "captured_requests": []}

    with open(CRAWL_RESULT_FILE, encoding="utf-8") as f:
        result = json.load(f)
        return {
            "status": "completed",
            "endpoints": result.get("endpoints", []),
            "captured_requests": result.get("captured_requests", [])
        }
