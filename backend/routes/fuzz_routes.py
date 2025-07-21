from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import requests

router = APIRouter()

class FuzzRequest(BaseModel):
    endpoint_url: str
    method: str  # "GET" or "POST"
    payloads: list[str]

@router.post("/fuzz")
def fuzz_endpoint(request: FuzzRequest):
    results = []

    for param in request.payloads or ["test"]:
        for payload in request.payloads:
            try:
                if request.method.upper() == "GET":
                    resp = requests.get(request.endpoint_url, params={param: payload}, timeout=5)
                elif request.method.upper() == "POST":
                    # resp = requests.post(request.endpoint_url, data={param: payload}, timeout=5)
                        for param in request.payloads:
                            for payload in request.payloads:
                                fuzz_data = {param: payload}
                                try:
                                    resp = requests.post(
                                        request.endpoint_url,
                                        json=fuzz_data,  # Send as JSON body
                                        timeout=5
                                    )
                                    results.append({
                                        "url": request.endpoint_url,
                                        "param": param,
                                        "payload": payload,
                                        "status_code": resp.status_code,
                                        "length": len(resp.text)
                                    })
                                except Exception as e:
                                    print(f"[ERROR] POST Fuzzing {request.endpoint_url} failed: {e}")
                else:
                    continue

                results.append({
                    "param": param,
                    "payload": payload,
                    "status_code": resp.status_code,
                    "length": len(resp.text)
                })

            except Exception as e:
                print(f"[ERROR] Fuzzing {request.endpoint_url} failed: {e}")

    return {"results": results}
