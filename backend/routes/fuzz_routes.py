# backend/routes/fuzz_routes.py
from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Optional, Dict, Any
import uuid

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from ..modules.fuzzer_ffuf import run_ffuf
from ..modules.feature_extractor import FeatureExtractor
from ..modules.recommender import Recommender
from ..modules.target_builder import build_fuzz_targets_for_job

from ..db import SessionLocal
from ..models import ScanJob, JobPhase

# -------- storage locations --------
REPO_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = REPO_ROOT / "data" / "results" / "ffuf"
DATA_DIR.mkdir(parents=True, exist_ok=True)

# -------- optional evidence sink --------
try:
    from ..modules.evidence_sink import persist_evidence  # type: ignore
except Exception:
    def persist_evidence(**kwargs):  # type: ignore
        return {"endpoint_id": None, "test_case_id": None, "evidence_id": None}

router = APIRouter()
fe = FeatureExtractor()


# -------- helpers --------
def create_payload_file(payload: str, directory: Optional[Path] = None) -> Path:
    directory = directory or (REPO_ROOT / "payloads" / "temp")
    directory.mkdir(parents=True, exist_ok=True)
    p = directory / f"{uuid.uuid4()}.txt"
    p.write_text(payload.strip() + "\n", encoding="utf-8")
    return p

def _fallback_payloads() -> List[str]:
    return [
        "' OR 1=1--",
        "\"/><script>console.log('ELISE_XSS_MARK')</script>",
        "';WAITFOR DELAY '0:0:5'--",
    ]

def _guess_label(payload: str) -> str:
    s = payload.lower()
    if "or 1=1" in s or "--" in s or "waitfor delay" in s or "';" in s:
        return "sqli"
    if "<script" in s or "onerror=" in s or "onload=" in s or "elise_xss_mark" in s:
        return "xss"
    return "benign"

def _derive_confidence(base_conf: float, match_count: int) -> float:
    """
    If recommender isn't available (base_conf ~ 0), nudge confidence based on findings.
    """
    if base_conf and base_conf > 0:
        return float(base_conf)
    return min(1.0, 0.2 + 0.2 * match_count)

def _merge_headers(h1: Optional[Dict[str, str]], h2: Optional[Dict[str, str]]) -> Dict[str, str]:
    """
    Merge headers with h2 overriding h1 on key collisions.
    """
    out: Dict[str, str] = {}
    for src in (h1 or {}), (h2 or {}):
        for k, v in src.items():
            out[k] = v
    return out


# -------- dependencies --------
def get_recommender(request: Request) -> Optional[Recommender]:
    """Return a ready recommender or None (fallback to static payloads)."""
    obj = getattr(request.app.state, "reco", None)
    if obj is not None:
        return obj

    try:
        r = Recommender()
    except FileNotFoundError:
        return None

    load = getattr(r, "load", None)
    if callable(load):
        try:
            r.load()
        except FileNotFoundError:
            return None

    request.app.state.reco = r
    return r


# -------- models --------
class FuzzTarget(BaseModel):
    url: str
    param: str
    method: str = "GET"
    job_id: Optional[str] = None
    headers: Dict[str, str] = Field(default_factory=dict)  # optional passthrough
    meta: Dict[str, Any] = Field(default_factory=dict)     # should contain body/body_type if POST


# -------- endpoints --------
@router.post("/fuzz")
def fuzz_many(
    targets: List[FuzzTarget],
    reco: Optional[Recommender] = Depends(get_recommender),
):
    results: List[Dict[str, Any]] = []

    for t in targets:
        # 1) Feature extraction (best-effort; do not block fuzzing)
        try:
            base_payload = "' OR 1=1 --"
            feats = fe.extract_features(
                t.url, t.param, payload=base_payload, method=t.method
            )
        except Exception as e:
            logging.exception("feature_extractor failed for %s %s", t.url, t.param)
            feats = None

        # 2) Payload selection (ML or fallback)
        try:
            if reco is not None and feats is not None:
                pairs = reco.recommend(feats, top_n=3, threshold=0.2)  # [(payload, prob), ...]
                candidates = [(p, float(conf)) for p, conf in pairs]
            else:
                candidates = [(p, 0.0) for p in _fallback_payloads()]
        except Exception:
            logging.exception("recommender failed; falling back")
            candidates = [(p, 0.0) for p in _fallback_payloads()]

        # 3) Build request context from target.meta (headers/body/body_type)
        meta = t.meta or {}
        meta_headers: Dict[str, str] = meta.get("headers") or {}
        meta_body = meta.get("body")
        meta_body_type = meta.get("body_type")  # "json" | "form" | None
        eff_headers = _merge_headers(meta_headers, t.headers)

        # 4) Execute ffuf per candidate and (optionally) persist evidence
        for payload, base_conf in candidates:
            payload_file = create_payload_file(payload)
            try:
                ffuf_out = run_ffuf(
                    url=t.url,
                    param=t.param,
                    payload_file=str(payload_file),
                    method=t.method,
                    headers=eff_headers or None,
                    body=meta_body,
                    body_type=meta_body_type,
                    output_dir=str(DATA_DIR),
                )

                matches = ffuf_out.get("matches") or []
                derived_conf = _derive_confidence(base_conf, len(matches))

                # Result item
                one = {
                    "url": t.url,
                    "param": t.param,
                    "method": t.method,
                    "payload": payload,
                    "confidence": derived_conf,
                    "output_file": ffuf_out.get("output_file"),
                    "status": "ok",
                    "meta": t.meta,
                }
                results.append(one)

                # Persist evidence if job_id provided
                if t.job_id:
                    try:
                        # Decide param location for bookkeeping
                        param_in_body = isinstance(meta_body, dict) and t.param in meta_body
                        param_locs = {"body": [t.param]} if (t.method.upper() != "GET" and param_in_body) else {"query": [t.param]}

                        signals = {
                            "ffuf_match_count": len(matches),
                            "ffuf_first_three": [
                                {
                                    "status": m.get("status"),
                                    "length": m.get("length"),
                                    "words": m.get("words"),
                                    "lines": m.get("lines"),
                                    "url": m.get("url"),
                                } for m in matches[:3]
                            ],
                            "ffuf_errors": ffuf_out.get("errors"),
                        }
                        request_meta = {
                            "method": t.method,
                            "url": t.url,
                            "param": t.param,
                            "payload_path": ffuf_out.get("payload_file") or str(payload_file),
                            "headers": eff_headers,
                            "body_type": meta_body_type,
                        }
                        response_meta = {
                            "elapsed_ms": ffuf_out.get("elapsed_ms"),
                            "output_file": ffuf_out.get("output_file"),
                            # best-effort legacy fields from wrapper
                            "status": ffuf_out.get("status"),
                            "len": ffuf_out.get("response_length"),
                        }
                        label = _guess_label(payload)

                        persist_evidence(
                            job_id=t.job_id,
                            method=t.method,
                            url=t.url,
                            param_locs=param_locs,
                            param=t.param,
                            family=label,
                            payload_id="auto",
                            request_meta=request_meta,
                            response_meta=response_meta,
                            signals=signals,
                            confidence=derived_conf,
                            label=label,
                        )
                    except Exception:
                        logging.exception("persist_evidence failed")

            except Exception as e:
                logging.exception("ffuf run failed for %s %s", t.url, t.param)
                results.append({
                    "url": t.url,
                    "param": t.param,
                    "method": t.method,
                    "payload": payload,
                    "status": "error",
                    "stage": "ffuf",
                    "error": str(e),
                    "meta": t.meta,
                })
            finally:
                try:
                    payload_file.unlink(missing_ok=True)
                except Exception:
                    pass

    # Never bubble exceptions → no 500s from this endpoint
    return {"results": results}

@router.post("/fuzz/by_job/{job_id}")
def fuzz_by_job(job_id: str, request: Request, reco: Optional[Recommender] = Depends(get_recommender)):
    raw_targets = build_fuzz_targets_for_job(job_id)
    targets = [FuzzTarget(**t) for t in raw_targets]
    out = fuzz_many(targets, reco)

    # auto-advance phase
    with SessionLocal() as db:
        row = db.query(ScanJob).filter_by(job_id=job_id).first()
        if row:
            row.phase = JobPhase.triage
            db.commit()
    return out
