from fastapi import APIRouter, Query, HTTPException
import json
from pathlib import Path
from urllib.parse import urlparse

router = APIRouter()

@router.get("/categorized-endpoints")
def get_categorized_endpoints(target_url: str = Query(...)):
    host = urlparse(target_url).netloc.replace(":", "_")
    file_path = Path(f"data/results/{host}/categorized_endpoints.json")
    
    if not file_path.exists():
        raise HTTPException(status_code=404, detail=f"No scan results found for {target_url}")

    with file_path.open("r", encoding="utf-8") as f:
        return json.load(f)
