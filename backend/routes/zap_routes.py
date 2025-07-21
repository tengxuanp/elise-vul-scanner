from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import requests
import time

router = APIRouter()

ZAP_API = "http://localhost:8080"
ZAP_KEY = "uc55j8bripcqblbbnevgrdq8nh"  # Replace with your ZAP API key

class ZapSpiderRequest(BaseModel):
    target_url: str

@router.post("/zap/spider")
def start_zap_spider(request: ZapSpiderRequest):
    try:
        # Start Spider
        resp = requests.get(f"{ZAP_API}/JSON/spider/action/scan/", params={
            'apikey': ZAP_KEY,
            'url': request.target_url,
            'recurse': True
        }).json()
        scan_id = resp.get('scan')

        if not scan_id:
            raise Exception("Spider did not start.")

        # Polling for Spider Status
        status = "0"
        while status != "100":
            time.sleep(2)
            status_resp = requests.get(f"{ZAP_API}/JSON/spider/view/status/", params={
                'apikey': ZAP_KEY,
                'scanId': scan_id
            }).json()
            status = status_resp.get('status', "0")

        # Get Results
        results_resp = requests.get(f"{ZAP_API}/JSON/spider/view/results/", params={
            'apikey': ZAP_KEY,
            'scanId': scan_id
        }).json()

        return {"results": results_resp.get('results', [])}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"ZAP Spider Error: {e}")
