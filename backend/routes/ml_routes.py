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

# Try to import EnhancedInferenceEngine for enhanced ML scoring - DISABLED FOR CVSS-BASED FUZZER
# try:
#     from ..modules.ml.enhanced_inference import EnhancedInferenceEngine
#     _ENHANCED_ENGINE = EnhancedInferenceEngine()
#     _ENHANCED_OK = True
# except Exception as _e:
_ENHANCED_ENGINE = None  # type: ignore
_ENHANCED_OK = False

router = APIRouter(prefix="/ml", tags=["ml"])

# Reuse singletons across requests
fe = FeatureExtractor(headless=True)
reco = Recommender()

# Lazy initialization of family classifier to ensure enhanced ML engine is loaded
_fam_clf_singleton = None

def get_fam_clf():
    global _fam_clf_singleton
    if _fam_clf_singleton is None:
        _fam_clf_singleton = FamilyClassifier() if FamilyClassifier is not None else None
    return _fam_clf_singleton


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


# New request schema for enhanced ML scoring endpoint
class EnhancedScoreRequest(BaseModel):
    url: str
    method: str = "GET"
    params: Optional[Dict[str, Any]] = None
    param: Optional[str] = None
    family: Optional[str] = Field(default=None, alias="vulnerability_type")
    headers: Optional[Dict[str, str]] = None
    content_type: Optional[str] = None
    top_n: int = 3

    model_config = ConfigDict(populate_by_name=True)


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

    # Family classifier info - check for both legacy and enhanced ML
    fam_clf = get_fam_clf()
    clf_loaded = bool(getattr(fam_clf, "model", None) or getattr(fam_clf, "enhanced_engine", None)) if fam_clf else False
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


@router.get("/healthz")
def ml_healthz() -> Dict[str, Any]:
    """
    Tiny health endpoint for probes. Returns minimal readiness info.
    """
    try:
        rinfo = reco.info()
        recommender_ready = bool(rinfo.ready)
    except Exception:
        recommender_ready = False

    family_router_available = FamilyClassifier is not None
    fam_clf = get_fam_clf()
    family_classifier_loaded = bool(getattr(fam_clf, "model", None) or getattr(fam_clf, "enhanced_engine", None)) if fam_clf else False

    return {
        "ok": recommender_ready or family_router_available,  # minimal liveness
        "recommender_ready": recommender_ready,
        "family_router_available": family_router_available,
        "family_classifier_loaded": family_classifier_loaded,
        "timestamp": int(time.time()),
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
    fam_clf = get_fam_clf()
    model_loaded = bool(getattr(fam_clf, "model", None) or getattr(fam_clf, "enhanced_engine", None)) if fam_clf else False
    calibrator_loaded = bool(getattr(fam_clf, "cal", None)) if fam_clf else False

    # Try enhanced ML first
    if _ENHANCED_ENGINE is not None and _ENHANCED_OK:
        try:
            endpoint = {
                "url": spec.url,
                "method": spec.method,
                "content_type": spec.content_type
            }
            param = {
                "name": spec.target_param,
                "value": spec.control_value or "",
                "loc": spec.location
            }
            
            # Get predictions for each family using enhanced ML
            family_probs = {}
            for family in ["sqli", "xss", "redirect"]:
                try:
                    result = _ENHANCED_ENGINE.predict_with_confidence(endpoint, param, family)
                    prob = result.get("calibrated_probability", result.get("raw_probability", 0.0))
                    family_probs[family] = float(prob)
                except Exception as e:
                    print(f"Enhanced ML prediction failed for {family}: {e}")
                    family_probs[family] = 0.0
            
            # Normalize probabilities
            s = sum(family_probs.values()) or 1.0
            proba = {k: v / s for k, v in family_probs.items()}
            
            model_loaded = True
            calibrator_loaded = True
            
            print(f"✅ Enhanced ML used for family prediction: {proba}")
            
        except Exception as e:
            print(f"⚠️ Enhanced ML failed, falling back to legacy: {e}")
            # Fallback to legacy
            fam_clf = get_fam_clf()
            if fam_clf and getattr(fam_clf, "predict_proba", None):
                try:
                    proba = fam_clf.predict_proba(t)  # type: ignore
                    model_loaded = True
                except Exception:
                    proba = {}
            else:
                proba = {}
    else:
        # Legacy path
        fam_clf = get_fam_clf()
        if fam_clf and getattr(fam_clf, "predict_proba", None):
            try:
                proba = fam_clf.predict_proba(t)  # type: ignore
                model_loaded = True
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
        fam_clf = get_fam_clf()
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

    # Try enhanced ML first, fallback to legacy
    if _ENHANCED_ENGINE is not None and _ENHANCED_OK:
        try:
            # Use enhanced ML engine
            endpoint = {
                "url": req.url,
                "method": req.method,
                "content_type": req.content_type
            }
            param = {
                "name": req.param,
                "value": "",  # No control value in this context
                "loc": "query"
            }
            
            # Use enhanced payload ranking
            ranked_payloads = _ENHANCED_ENGINE.rank_payloads(
                endpoint, param, family, pool, top_k=req.top_n
            )
            
            if ranked_payloads:
                # Convert to expected format
                ranked = []
                for item in ranked_payloads:
                    ranked.append((item["payload"], item["score"]))
                
                # Build enhanced ML metadata
                meta = {
                    "used_path": "enhanced_ml",
                    "family": family,
                    "enhanced": True,
                    "confidence": ranked_payloads[0].get("confidence", 0.0),
                    "uncertainty": ranked_payloads[0].get("uncertainty", 0.0),
                    "ranker_score": ranked_payloads[0].get("score", 0.0),
                    "family_probs": {family: 1.0},
                    "model_ids": {"ranker_path": f"enhanced_{family}_xgboost", "enhanced_ml": True},
                    "feature_dim_total": 48,
                    "family_chosen": family,
                    "enhanced_ml": True,
                    "is_ml_prediction": True,
                    "fallback_used": False
                }
                
                print(f"✅ Enhanced ML used for {family} - {len(ranked)} payloads ranked")
                
            else:
                raise Exception("Enhanced ML returned no results")
                
            # Ensure meta is defined for enhanced ML path
            if 'meta' not in locals():
                meta = {"used_path": "enhanced_ml", "family": family}
                
        except Exception as e:
            print(f"⚠️ Enhanced ML failed, falling back to legacy: {e}")
            # Fallback to legacy
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
            meta = {"used_path": "legacy", "family": family}
    else:
        # Legacy path
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
        meta = {"used_path": "legacy", "family": family}

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


@router.post("/enhanced-score")
def enhanced_score(req: EnhancedScoreRequest) -> Dict[str, Any]:
    """
    Enhanced ML scoring endpoint.
    Returns family probabilities and top payload ranking metadata compatible with UI/evidence.
    """
    # Determine target parameter
    param_name = (req.param or "").strip()
    if not param_name:
        d = req.params or {}
        if isinstance(d, dict) and d:
            # pick first non-empty key
            for k in d.keys():
                if str(k).strip():
                    param_name = str(k)
                    break
        if not param_name:
            param_name = "id"

    # Determine family
    family = (req.family or "").strip().lower()
    fam_proba: Dict[str, float] = {}

    # Try ML family classifier first
    if not family:
        fam_clf = get_fam_clf()
        if fam_clf and getattr(fam_clf, "predict_proba", None):
            try:
                fam_proba = fam_clf.predict_proba({
                    "url": req.url,
                    "method": req.method,
                    "in": "query",
                    "target_param": param_name,
                    "content_type": req.content_type,
                    "headers": req.headers,
                })  # type: ignore
                if fam_proba:
                    family = max(fam_proba.items(), key=lambda kv: kv[1])[0]
            except Exception:
                fam_proba = {}

    # Fallback to rules router
    if not family:
        if choose_family is not None:
            try:
                family = choose_family({
                    "url": req.url, "method": req.method, "in": "query",
                    "target_param": param_name, "content_type": req.content_type, "headers": req.headers,
                })["family"]
            except Exception:
                family = "sqli"
        else:
            family = "sqli"

    # Ensure family probs non-empty
    if not fam_proba:
        fam_proba = {family: 1.0}

    # Candidate payloads
    try:
        pool = payload_pool_for(family)  # type: ignore[name-defined]
    except Exception:
        pool = []
    if not pool:
        pool = ["test"]
    candidates = pool[: max(1, req.top_n * 5)]  # widen pool a bit

    # Build endpoint/param dicts for the engine
    endpoint = {"url": req.url, "method": req.method, "content_type": req.content_type}
    param = {"name": param_name, "value": (req.params or {}).get(param_name, ""), "loc": "query"}
    context = {"headers": req.headers or {}, "payload_origin": "ml"}

    ranked: List[Dict[str, Any]] = []
    if _ENHANCED_OK and _ENHANCED_ENGINE is not None:
        try:
            ranked = _ENHANCED_ENGINE.rank_payloads(endpoint, param, family, candidates, context=context, top_k=req.top_n)
        except Exception as e:
            ranked = []
    # Minimal fallback scoring when enhanced engine unavailable
    if not ranked:
        ranked = [{"payload": p, "score": 0.4, "confidence": 0.4, "family": family, "features_used": 0, "fallback_used": True} for p in candidates[: req.top_n]]

    top = ranked[0] if ranked else {"score": 0.0, "confidence": 0.0, "features_used": 0, "fallback_used": True}

    ranker_raw = {
        "confidence": float(top.get("confidence", top.get("score", 0.0))),
        "calibrated_probability": float(top.get("calibrated_probability", top.get("score", 0.0))),
        "raw_probability": float(top.get("raw_probability", top.get("score", 0.0))),
    }

    resp = {
        "family": family,
        "family_probs": fam_proba,
        "used_path": "enhanced_ml" if _ENHANCED_OK else "heuristic",
        "ranker_score": ranker_raw["confidence"],
        "flags": {
            "enhanced_ml": bool(_ENHANCED_OK),
            "is_ml_prediction": True,
            "fallback_used": bool(top.get("fallback_used", False)),
        },
        "model_ids": {
            "ranker_path": f"enhanced_{family}_xgboost",
            "enhanced_ml": True,
        },
        "feature_dim_total": int(top.get("features_used", 0)) or None,
        "ranker_raw": ranker_raw,
        "ranked": ranked,
    }
    return resp


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
