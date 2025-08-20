from fastapi import APIRouter
from pathlib import Path
import json

from ..modules.feature_extractor import FeatureExtractor

router = APIRouter()
fe = FeatureExtractor()

CRAWL_RESULT_FILE = Path("data/crawl_result.json")
PROBED_OUTPUT_FILE = Path("data/probed_endpoints.json")

SMART_PROBE_PAYLOADS = [
    '" onerror=alert(1) x="',
    "' onerror=alert(1) x='",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "<script>alert(1)</script>",
    "javascript:alert(1)",
    "`-alert(1)-`"
]

SKIP_PARAMS = {"password", "csrf", "authenticity_token"}

@router.post("/probe")
def probe_endpoints():
    if not CRAWL_RESULT_FILE.exists():
        return {"error": "Crawl result file not found."}

    with open(CRAWL_RESULT_FILE, "r", encoding="utf-8") as f:
        raw_data = json.load(f)
        endpoints = raw_data.get("endpoints", []) + raw_data.get("captured_requests", [])

    probed_results = []
    seen = set()

    for ep in endpoints:
        url = ep.get("url")
        params = ep.get("params", [])
        method = ep.get("method", "GET")

        for param in params:
            sig = (url, param)
            if sig in seen or param.lower() in SKIP_PARAMS or "#/" in url:
                continue
            seen.add(sig)

            for payload in SMART_PROBE_PAYLOADS:
                features = fe.extract_features(url, param, payload, method=method)

                result = {
                    "url": url,
                    "param": param,
                    "method": method,
                    "reflected": features is not None,
                    "features": features if features else [],
                    "probe_payload": payload
                }

                # If reflected, extract metadata for logging
                if features:
                    result["reflection_type"] = {
                        1: "raw",
                        2: "encoded",
                        3: "partial"
                    }.get(features[5], "unknown")
                    result["context"] = {
                        1: "html",
                        2: "attribute",
                        3: "js"
                    }.get(features[6], "unknown")
                    result["executed"] = bool(features[7])

                probed_results.append(result)
                if features:
                    break  # stop after first success

    PROBED_OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(PROBED_OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(probed_results, f, indent=2)

    return {"status": "done", "probed_count": len(probed_results)}
