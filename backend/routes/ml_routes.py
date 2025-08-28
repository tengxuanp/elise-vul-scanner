# backend/routes/ml_routes.py
from __future__ import annotations

from typing import Any, Dict, List, Optional
from pathlib import Path
import time

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field, ConfigDict

# ---- Stage A: Family router (ML + rules) ----
try:
    from ..modules.family_router import FamilyClassifier, choose_family, rank_families, payload_pool_for
except Exception as e:
    FamilyClassifier = None  # type: ignore
    choose_family = None     # type: ignore
    rank_families = None     # type: ignore
    def payload_pool_for(_: str) -> List[str]:  # type: ignore
        return []

# ---- Stage B: Payload ranker (LTR) ----
from ..modules.recommender import Recommender

# ---- Endpoint feature extraction (cheap) ----
from ..modules.feature_extractor import FeatureExtractor

router = APIRouter(prefix="/ml", tags=["ml"])

# Reuse singletons across requests
fe = FeatureExtractor(headless=True)
reco = Recommender()
fam_clf = FamilyClassifier() if FamilyClassifier is not None else None


# ------------------------------ Schemas --------------------------------------

class TargetSpec(BaseModel):
    url: str
    method: str = "GET"
    location: str = Field(default="query", alias="in")
    target_param: str
    content_type: Optional[str] = None
    headers: Optional[Dict[str, str]] = None
    control_value: Optional[str] = None

    model_config = ConfigDict(populate_by_name=True)  # allow using "in" in payloads


class FamilyProbaResponse(BaseModel):
    proba: Dict[str, float]
    top_family: str
    rule_fallback: Optional[Dict[str, Any]] = None
    rules_ranked: Optional[List[Dict[str, Any]]] = None
    model_loaded: bool
    calibrator_loaded: bool


class RecommendRequest(BaseModel):
    url: str
    param: str
    method: str = "GET"
    content_type: Optional[str] = None
    headers: Optional[Dict[str, str]] = None
    family: Optional[str] = None
    candidates: Optional[List[str]] = None  # explicit overrides
    top_n: int = 3
    threshold: float = 0.2


class RecommendItem(BaseModel):
    payload: str
    p: float


class RecommendResponse(BaseModel):
    family: str
    family_proba: Optional[Dict[str, float]] = None
    payloads: List[RecommendItem]
    payload_origin: str = "ml"
    ranker_meta: Dict[str, Any]


# ------------------------------ Routes ---------------------------------------

@router.get("/info")
def ml_info() -> Dict[str, Any]:
    """
    Introspection: model availability, rankers loaded, canonical pool sizes.
    """
    # Recommender info
    rinfo = reco.info().__dict__  # dataclass -> dict

    # Family classifier info
    clf_loaded = bool(getattr(fam_clf, "model", None)) if fam_clf else False
    cal_loaded = bool(getattr(fam_clf, "cal", None)) if fam_clf else False

    # Pools
    pools = {}
    for fam in ("sqli", "xss", "redirect"):
        try:
            pools[fam] = len(payload_pool_for(fam))
        except Exception:
            pools[fam] = 0

    return {
        "recommender": rinfo,
        "family_classifier": {
            "loaded": clf_loaded,
            "calibrator": cal_loaded,
        },
        "payload_pools": pools,
    }


@router.post("/family_proba", response_model=FamilyProbaResponse)
def family_proba(spec: TargetSpec) -> FamilyProbaResponse:
    """
    Stage A: return P(family) distribution and best family.
    Falls back to deterministic rules when classifier not loaded.
    """
    t = {
        "url": spec.url,
        "method": spec.method,
        "in": spec.location,
        "target_param": spec.target_param,
        "content_type": spec.content_type,
        "headers": spec.headers,
        "control_value": spec.control_value,
    }

    proba: Dict[str, float]
    model_loaded = bool(getattr(fam_clf, "model", None)) if fam_clf else False
    calibrator_loaded = bool(getattr(fam_clf, "cal", None)) if fam_clf else False

    if fam_clf and getattr(fam_clf, "predict_proba", None):
        try:
            proba = fam_clf.predict_proba(t)  # type: ignore
        except Exception:
            proba = {}
    else:
        proba = {}

    rule_best = None
    rules_ranked = None
    if not proba or max(proba.values()) <= 0.0:
        # fallback to rules
        if choose_family is None or rank_families is None:
            raise HTTPException(status_code=500, detail="Family router unavailable")
        rule_best = choose_family(t)
        ranked = rank_families(t)
        # turn into normalized proba
        rs = {r["family"]: float(r.get("raw_score", 0.0)) for r in ranked}
        rs["base"] = max(rs.get("base", 0.0), 1e-3)
        s = sum(max(0.0, v) for v in rs.values()) or 1.0
        proba = {k: max(0.0, v) / s for k, v in rs.items()}
        rules_ranked = ranked

    top_family = max(proba.items(), key=lambda kv: kv[1])[0] if proba else "base"

    return FamilyProbaResponse(
        proba=proba,
        top_family=top_family,
        rule_fallback=rule_best,
        rules_ranked=rules_ranked,
        model_loaded=model_loaded,
        calibrator_loaded=calibrator_loaded,
    )


@router.post("/recommend", response_model=RecommendResponse)
def recommend(req: RecommendRequest) -> RecommendResponse:
    """
    Stage B: per-family Learning-to-Rank (LTR) recommendation.
    If `family` not provided, uses Stage A to pick one.
    `candidates` overrides canonical pool for the chosen family.
    """
    # Stage A (optional)
    fam_proba: Optional[Dict[str, float]] = None
    family = (req.family or "").strip().lower()
    if not family:
        if fam_clf and getattr(fam_clf, "predict_proba", None):
            fam_proba = fam_clf.predict_proba({
                "url": req.url, "method": req.method, "in": "query",
                "target_param": req.param, "content_type": req.content_type, "headers": req.headers,
            })
            family = max(fam_proba.items(), key=lambda kv: kv[1])[0]
        else:
            # fallback to rules
            if choose_family is None:
                raise HTTPException(status_code=500, detail="Family router unavailable")
            family = choose_family({
                "url": req.url, "method": req.method, "in": "query",
                "target_param": req.param, "content_type": req.content_type, "headers": req.headers,
            })["family"]

    # Candidate pool
    pool = list(req.candidates) if req.candidates else list(payload_pool_for(family))
    if not pool:
        raise HTTPException(status_code=400, detail=f"No candidate payloads for family '{family}'")

    # Endpoint features (payload-agnostic)
    feats = fe.extract_endpoint_features(
        url=req.url, param=req.param, method=req.method, content_type=req.content_type, headers=req.headers
    )

    ranked = reco.recommend(
        feats=feats,
        top_n=max(1, req.top_n),
        threshold=max(0.0, min(1.0, req.threshold)),
        family=family,
        pool=pool,
    )

    items = [RecommendItem(payload=p, p=float(s)) for p, s in ranked]

    # Meta for caller to log into evidence
    info = reco.info()
    ranker_meta = {
        "family": family,
        "top_n": req.top_n,
        "threshold": req.threshold,
        "model_type": info.model_type,
        "model_path": info.model_path,
        "rankers_loaded": info.rankers_loaded if hasattr(info, "rankers_loaded") else {},
        "timestamp": int(time.time()),
    }

    return RecommendResponse(
        family=family,
        family_proba=fam_proba,
        payloads=items,
        payload_origin="ml",
        ranker_meta=ranker_meta,
    )


@router.get("/pools")
def payload_pools() -> Dict[str, Any]:
    """
    Expose canonical curated payload pools and counts.
    """
    out = {}
    for fam in ("sqli", "xss", "redirect"):
        try:
            pool = payload_pool_for(fam)
        except Exception:
            pool = []
        out[fam] = {
            "count": len(pool),
            "payloads": pool,
        }
    return out
