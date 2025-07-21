from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import requests
import time

router = APIRouter()

ZAP_API = "http://localhost:8080"
ZAP_KEY = "uc55j8bripcqblbbnevgrdq8nh"  # Change this to your ZAP key

class ZapActiveScanRequest(BaseModel):
    target_urls: list[str]  # List of URLs to actively scan

@router.post("/zap/active-scan")
def start_zap_active_scan(request: ZapActiveScanRequest):
    scan_results = []
    try:
        for url in request.target_urls:
            resp = requests.get(f"{ZAP_API}/JSON/ascan/action/scan/", params={
                'apikey': ZAP_KEY,
                'url': url,
                'recurse': True
            }).json()
            scan_id = resp.get('scan')

            # Optional: Poll status
            time.sleep(2)

            scan_results.append({"url": url, "scan_id": scan_id})

        return {"results": scan_results}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"ZAP Active Scan Error: {e}")
