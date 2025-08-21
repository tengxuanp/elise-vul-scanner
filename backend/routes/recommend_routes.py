from fastapi import APIRouter
from pydantic import BaseModel
from pathlib import Path
import json

from ..modules.feature_extractor import FeatureExtractor
from ..modules.recommender import Recommender

router = APIRouter()
fe = FeatureExtractor()
reco = Recommender()

PROBED_OUTPUT_FILE = Path("data/probed_endpoints.json")

class RecoRequest(BaseModel):
    url: str
    param: str
    payload: str = "' OR 1=1 --"

@router.post("/recommend_payloads")
def recommend_payloads(req: RecoRequest):
    feats = fe.extract_features(req.url, req.param, req.payload)
    if feats is None:
        return {"error": "No reflection found"}
    return {"payloads": reco.recommend(feats)}


@router.get("/recommend_probed")
def recommend_for_probed():
    if not PROBED_OUTPUT_FILE.exists():
        return {"error": "Probed endpoints file not found."}

    with open(PROBED_OUTPUT_FILE, "r", encoding="utf-8") as f:
        probed = json.load(f)

    recommendations = []
    for entry in probed:
        feats = entry.get("features")
        if feats:
            recommendations.append(
                {
                    "url": entry.get("url"),
                    "param": entry.get("param"),
                    "method": entry.get("method", "GET"),
                    "recommendations": reco.recommend(feats),
                }
            )

    return {"recommendations": recommendations}
