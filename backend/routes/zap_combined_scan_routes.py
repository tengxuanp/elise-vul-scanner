from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import requests
import time

router = APIRouter()

ZAP_API = "http://localhost:8080"
ZAP_KEY = "uc55j8bripcqblbbnevgrdq8nh"

class ZapScanRequest(BaseModel):
    target_urls: list[str]

@router.post("/zap/scan-and-alerts")
def zap_scan_and_fetch_alerts(request: ZapScanRequest):
    try:
        for url in request.target_urls:
            requests.get(f"{ZAP_API}/JSON/ascan/action/scan/", params={
                'apikey': ZAP_KEY,
                'url': url,
                'recurse': False
            })
        
        time.sleep(10)  # Wait for scans (adjust as needed)

        alerts_resp = requests.get(f"{ZAP_API}/JSON/core/view/alerts/", params={
            'apikey': ZAP_KEY
        }).json()

        filtered_alerts = [
            {
                "url": a.get('url'),
                "risk": a.get('risk'),
                "alert": a.get('alert'),
                "param": a.get('param')
            }
            for a in alerts_resp.get('alerts', [])
            if a.get('url') in request.target_urls
        ]

        return {"alerts": filtered_alerts}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"ZAP Scan or Fetch Error: {e}")
