from fastapi import APIRouter
from pydantic import BaseModel
from modules.feature_extractor import FeatureExtractor
from modules.recommender import Recommender

router = APIRouter()
fe = FeatureExtractor()
reco = Recommender()

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
