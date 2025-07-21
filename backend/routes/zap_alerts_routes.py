from fastapi import APIRouter, HTTPException
import requests

router = APIRouter()

ZAP_API = "http://localhost:8080"
ZAP_KEY = "uc55j8bripcqblbbnevgrdq8nh"  # Replace with your actual key

@router.get("/zap/alerts")
def get_zap_alerts():
    try:
        resp = requests.get(f"{ZAP_API}/JSON/core/view/alerts/", params={
            'apikey': ZAP_KEY
        }).json()
        return {"alerts": resp.get('alerts', [])}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch alerts: {e}")
