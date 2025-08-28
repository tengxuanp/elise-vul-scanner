# backend/routes/recommend_routes.py
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

# ---- optional ML/feature plumbing (safe fallbacks) ----
try:
    from ..modules.feature_extractor import FeatureExtractor  # type: ignore
except Exception:  # pragma: no cover
    class FeatureExtractor:  # minimal stub
        def extract_features(self, *a, **kw): return {}
        def extract_endpoint_features(self, *a, **kw): return []

try:
    from ..modules.recommender import Recommender  # type: ignore
except Exception:  # pragma: no cover
    class Recommender:  # minimal stub
        def load(self): ...
        def recommend_with_meta(self, *a, **kw): return ([], {"used_path": "none"})

router = APIRouter()

REPO_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = REPO_ROOT / "data"
PROBED_OUTPUT_FILE = DATA_DIR / "probed_endpoints.json"

fe = FeatureExtractor()


def _init_reco() -> Recommender:
    """Instantiate and best-effort load recommender (rankers, plugin, etc.)."""
    r = Recommender()
    try:
        if hasattr(r, "load"):
            r.load()  # no-op if not needed
    except Exception:
        # keep going with an uninitialized object; routes will degrade gracefully
        pass
    return r


# -------------------- helpers --------------------

def _choose_family(url: str, param: str, content_type: Optional[str]) -> str:
    """
    Very small heuristic, kept aligned with fuzz_routes.
    """
    p = (param or "").lower()
    u = (url or "").lower()
    if p in {"to", "return_to", "redirect", "url", "next", "callback", "continue"} or "redirect" in u:
        return "redirect"
    if p in {"q", "query", "search", "comment", "message", "content", "text", "title", "name"} and (
        not content_type or "html" in str(content_type).lower()
    ):
        return "xss"
    return "sqli"


# -------------------- models --------------------

class RecoRequest(BaseModel):
    url: str
    param: str
    method: str = "GET"
    family: Optional[str] = Field(default=None, description="Optional override: sqli | xss | redirect")
    top_n: int = Field(default=3, ge=1, le=20)
    threshold: float = Field(default=0.2, ge=0.0, le=1.0)
    pool: Optional[List[str]] = Field(default=None, description="Optional candidate payloads to rank")
    seed_payload: str = Field(
        default="' OR 1=1 --",
        description="Seed used during lightweight feature extraction",
    )


# -------------------- routes --------------------

@router.post("/recommend_payloads")
def recommend_payloads(
    req: RecoRequest,
    reco: Recommender = Depends(_init_reco),
):
    """
    Rank payloads for a single (url, param, method).
    Returns ranked payloads with confidences and ranker meta.
    """
    # Feature extraction (best-effort; tolerate failures)
    try:
        feats = fe.extract_features(req.url, req.param, payload=req.seed_payload, method=req.method)
    except Exception:
        feats = {}

    fam = (req.family or _choose_family(req.url, req.param, (feats or {}).get("content_type"))).lower()

    recs, meta = reco.recommend_with_meta(
        feats=feats,
        top_n=max(1, req.top_n),
        threshold=req.threshold,
        family=fam,
        pool=req.pool,
    )

    return {
        "url": req.url,
        "param": req.param,
        "method": req.method.upper(),
        "family": fam,
        "recommendations": [{"payload": p, "confidence": float(c)} for p, c in recs],
        "ranker_meta": meta,
    }


@router.get("/recommend_probed")
def recommend_for_probed(
    top_n: int = 3,
    threshold: float = 0.2,
    reco: Recommender = Depends(_init_reco),
):
    """
    Load probed endpoints (written by probing phase) and produce payload
    recommendations for each, returning confidences + meta.
    """
    if not PROBED_OUTPUT_FILE.exists():
        return {"error": f"Probed endpoints file not found at {PROBED_OUTPUT_FILE}"}

    try:
        probed = json.loads(PROBED_OUTPUT_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {"error": "Failed to parse probed_endpoints.json"}

    recommendations: List[Dict[str, Any]] = []
    for entry in probed or []:
        url = entry.get("url")
        param = entry.get("param")
        method = (entry.get("method") or "GET").upper()
        if not url or not param:
            continue

        # Prefer precomputed features; otherwise compute quickly
        try:
            feats = entry.get("features") or fe.extract_features(url, param, payload="' OR 1=1 --", method=method)
        except Exception:
            feats = {}

        fam = (entry.get("family") or _choose_family(url, param, (feats or {}).get("content_type"))).lower()
        recs, meta = reco.recommend_with_meta(
            feats=feats,
            top_n=max(1, int(top_n)),
            threshold=float(threshold),
            family=fam,
        )

        recommendations.append(
            {
                "url": url,
                "param": param,
                "method": method,
                "family": fam,
                "recommendations": [{"payload": p, "confidence": float(c)} for p, c in recs],
                "ranker_meta": meta,
            }
        )

    return {"count": len(recommendations), "recommendations": recommendations}
