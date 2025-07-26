# File: routes/categorized.py
from fastapi import APIRouter
import json
import os
from modules.categorize_endpoints import categorize_endpoint

DATA_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "crawl_result.json")

router = APIRouter()

@router.get("/categorized-endpoints")
def get_categorized_endpoints():
    if not os.path.exists(DATA_PATH):
        return {"error": "Crawl result not found."}

    with open(DATA_PATH, "r") as f:
        data = json.load(f)

    return {"categorized_endpoints": data}
