from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List
from modules.fuzzer_ffuf import run_ffuf
from modules.feature_extractor import FeatureExtractor
from modules.recommender import Recommender
import os
import uuid

router = APIRouter()
fe = FeatureExtractor()
reco = Recommender()

class FuzzTarget(BaseModel):
    url: str
    param: str

@router.post("/fuzz")
def fuzz_many(targets: List[FuzzTarget]):
    results = []
    for t in targets:
        # You can rotate the payload used for feature reflection test
        base_payload = "' OR 1=1 --"  # could later randomize this
        feats = fe.extract_features(t.url, t.param, payload=base_payload)

        if feats is None:
            results.append({
                "url": t.url,
                "param": t.param,
                "status": "skip",
                "reason": "not reflected"
            })
            continue

        top_payloads = reco.recommend(feats)

        for payload, confidence in top_payloads:
            payload_file = create_payload_file(payload)

            try:
                result = run_ffuf(t.url, t.param, payload_file=payload_file)
                results.append({
                    "url": t.url,
                    "param": t.param,
                    "payload": payload,
                    "confidence": confidence,
                    "output_file": result.get("output_file", None),
                    "status": "ok"
                })
            except Exception as e:
                results.append({
                    "url": t.url,
                    "param": t.param,
                    "payload": payload,
                    "status": "error",
                    "error": str(e)
                })
            finally:
                try:
                    os.remove(payload_file)  # ✅ Clean up temp file
                except Exception as e:
                    print(f"⚠️ Failed to delete temp payload file: {payload_file}")

    return {"results": results}

def create_payload_file(payload: str, directory: str = "payloads/temp") -> str:
    os.makedirs(directory, exist_ok=True)
    file_id = str(uuid.uuid4())
    file_path = os.path.join(directory, f"{file_id}.txt")

    with open(file_path, "w", encoding="utf-8") as f:
        f.write(payload.strip() + "\n")

    return file_path
