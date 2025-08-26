# backend/modules/recommender.py
from __future__ import annotations

import json
import logging
import os
import pickle
from dataclasses import dataclass
from importlib import import_module
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple, Union

try:
    import numpy as np
except Exception:  # numpy is optional; we degrade gracefully
    np = None  # type: ignore

try:
    import joblib  # for loading ranker_*.joblib
except Exception:
    joblib = None  # type: ignore

# Prefer canonical pools via family_router; degrade gracefully if missing
try:
    from .family_router import payload_pool_for as _payload_pool_for
except Exception:
    _payload_pool_for = None  # type: ignore

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)


# ---- configuration -----------------------------------------------------------

ML_DIR = Path(__file__).resolve().parent / "ml"

# Legacy / generic model (not per-family). Kept for backward compatibility.
MODEL_PATHS = [
    ML_DIR / "recommender_model.pkl",
    ML_DIR / "recommender_model.joblib",
]
PIPELINE_PATHS = [
    ML_DIR / "feature_pipeline.pkl",          # optional transformer for feats
]
META_PATHS = [
    ML_DIR / "recommender_meta.json",         # optional: {"feature_names":[...], "feature_dim": N}
]

# Per-family LTR rankers (LambdaMART / XGBRanker)
RANKER_PATHS = {
    "sqli": ML_DIR / "ranker_sqli.joblib",
    "xss": ML_DIR / "ranker_xss.joblib",
    "redirect": ML_DIR / "ranker_redirect.joblib",
}

# Optional plugin to support pairwise scoring:
#   ELISE_RANKER_PLUGIN="backend.modules.ml.ranker:score"
# The callable signature must be: score(feats: Any, payloads: List[str]) -> List[float]
PLUGIN_ENV = "ELISE_RANKER_PLUGIN"


# ---- data structures ---------------------------------------------------------

@dataclass
class RecommenderInfo:
    ready: bool
    model_type: str
    model_path: Optional[str]
    pipeline_path: Optional[str]
    plugin: Optional[str]
    feature_dim: Optional[int]
    rankers_loaded: Dict[str, bool]


# ---- utility ----------------------------------------------------------------

def _load_first_existing(paths: Sequence[Path]) -> Optional[Path]:
    for p in paths:
        if p.exists():
            return p
    return None


def _import_plugin(spec: str) -> Callable[[Any, List[str]], List[float]]:
    """
    Import "module.sub:callable" and return the callable.
    """
    if ":" not in spec:
        raise ValueError(f"Invalid plugin spec '{spec}', expected 'module.sub:callable'")
    mod_name, func_name = spec.split(":", 1)
    mod = import_module(mod_name)
    fn = getattr(mod, func_name, None)
    if not callable(fn):
        raise ValueError(f"Plugin target '{func_name}' in '{mod_name}' is not callable")
    return fn


def _softmax(xs: Sequence[float]) -> List[float]:
    try:
        if np is not None:
            a = np.asarray(xs, dtype=float)
            a = a - np.max(a)
            exp = np.exp(a)
            s = float(exp.sum()) or 1.0
            return (exp / s).tolist()
    except Exception:
        pass
    # Pure-Python fallback
    m = max(xs) if xs else 0.0
    exps = [pow(2.718281828, x - m) for x in xs]
    s = sum(exps) or 1.0
    return [x / s for x in exps]


def _as_feature_vector(
    feats: Any,
    expected_dim: Optional[int] = None,
    feature_names: Optional[List[str]] = None,
) -> Optional[List[float]]:
    """
    Convert arbitrary features into a flat numeric vector.
    - If feats is list/tuple of numbers, return as-is (validated to expected_dim if provided).
    - If feats is dict and feature_names provided, order by names.
    - If feats is dict without names, order by sorted keys (stable, but risky across versions).
    """
    try:
        if feats is None:
            return None
        # numpy array
        if np is not None and isinstance(feats, np.ndarray):
            v = feats.astype(float).ravel().tolist()
        # plain list/tuple
        elif isinstance(feats, (list, tuple)):
            v = [float(x) for x in feats]
        # dict mapping
        elif isinstance(feats, dict):
            keys = feature_names or sorted(feats.keys())
            v = [float(feats.get(k, 0.0)) for k in keys]
        else:
            # best effort: try to cast
            v = [float(feats)]
        if expected_dim is not None and len(v) != expected_dim:
            log.warning("Feature length %d != expected %d; continuing anyway", len(v), expected_dim)
        return v
    except Exception as e:
        log.warning("Failed to coerce features to vector: %s", e)
        return None


def _heuristic_score(payload: str, family: str, hints: Dict[str, Any]) -> float:
    """
    Very lightweight, explainable heuristic for fallback ranking.
    This is NOT ML, but gives sane ordering when no model is available.
    Returns a score in [0, 1].
    """
    p = payload.lower()
    score = 0.1  # base

    # Basic boosts per family
    if family == "xss":
        if "<script" in p or "onerror=" in p or "onload=" in p:
            score += 0.6
        if "svg" in p or "img" in p:
            score += 0.2
        if "javascript:" in p:
            score += 0.15
    elif family == "sqli":
        if "union select" in p:
            score += 0.5
        if "' or" in p or "\" or" in p:
            score += 0.3
        if "sleep(" in p or "benchmark(" in p:
            score += 0.2
    elif family in ("open_redirect", "redirect"):
        if "://" in p or p.startswith("//"):
            score += 0.5
        if "@@" in p or "%2f%2f" in p:
            score += 0.2
    elif family in ("ssti",):
        for t in ("{{7*7}}", "${{7*7}}", "<%=", "#{", "${"):
            if t in p:
                score += 0.5
                break

    # Hints based on content-type or sink
    ct = str(hints.get("content_type") or "").lower()
    if family == "xss" and ("text/html" in ct or "application/xhtml" in ct):
        score += 0.15
    if family == "sqli" and ("application/json" in ct or "x-www-form-urlencoded" in ct):
        score += 0.1

    # Clip to [0, 1]
    return max(0.0, min(1.0, score))


def _payload_desc(payload: str) -> List[float]:
    """Cheap, deterministic payload features (must match trainer)."""
    s = payload or ""
    specials = sum(1 for ch in s if not ch.isalnum())
    lower = s.lower()
    return [
        float(len(s)),
        float(specials),
        1.0 if ("<script" in lower or "onerror=" in lower or "onload=" in lower) else 0.0,  # XSS-ish
        1.0 if (" or 1=1" in lower or "union select" in lower or "waitfor" in lower or "sleep(" in lower) else 0.0,  # SQLi-ish
        1.0 if (lower.startswith("http") or lower.startswith("//")) else 0.0,  # Redirect-ish
    ]


# ---- canonical pool access (compat shim) ------------------------------------

def default_payloads_by_family(family: str) -> List[str]:
    """Return canonical payload pool for a family (via family_router)."""
    fam = (family or "").lower()
    if _payload_pool_for:
        try:
            return list(_payload_pool_for(fam))  # type: ignore
        except Exception:
            pass
    # minimal fallback
    if fam == "sqli":
        return ["' OR 1=1--", "') OR ('1'='1' -- ", "1 OR 1=1 -- ", "' UNION SELECT NULL-- "]
    if fam == "xss":
        return ['"/><script>alert(1)</script>', "<img src=x onerror=alert(1)>", "<svg/onload=alert(1)>"]
    if fam == "redirect":
        return ["https://example.org/", "//evil.tld", "https:%2F%2Fevil.tld"]
    return []


# ---- recommender -------------------------------------------------------------

class Recommender:
    """
    Rank payloads for a given request/features.

    Load order preference:
      1) Per-family LTR rankers (ranker_{family}.joblib) if `family` is provided.
      2) Optional plugin:   ELISE_RANKER_PLUGIN="module.sub:score" -> score(feats, payloads) -> list[float]
      3) Generic model:     recommender_model.(pkl|joblib), optionally with feature_pipeline.pkl
      4) Heuristic fallback.

    Public API (backward compatible):
      recommend(feats, top_n=3, threshold=0.2, family=None, candidates=None, pool=None)
        - `pool` is an alias for `candidates` (to match fuzzer_core integration).
    """

    def __init__(self) -> None:
        self.ready: bool = False
        self.model: Any = None              # legacy/generic model
        self.pipeline: Any = None           # optional feature transformer
        self.meta: Dict[str, Any] = {}
        self.plugin_fn: Optional[Callable[[Any, List[str]], List[float]]] = None

        self._model_path: Optional[str] = None
        self._pipeline_path: Optional[str] = None
        self._feature_dim: Optional[int] = None
        self._feature_names: Optional[List[str]] = None

        # Per-family rankers
        self.rankers: Dict[str, Any] = {}

    # ---------------------- lifecycle ----------------------------------------

    def load(self) -> None:
        """
        Load per-family rankers, plugin, model/pipeline/meta if present. Idempotent.
        """
        # Per-family rankers first (authoritative when family is specified)
        for fam, path in RANKER_PATHS.items():
            try:
                if joblib is not None and path.exists():
                    self.rankers[fam] = joblib.load(path)
                    log.info("Loaded LTR ranker for %s: %s", fam, path)
                else:
                    self.rankers[fam] = None
            except Exception as e:
                log.warning("Failed to load ranker for %s at %s: %s", fam, path, e)
                self.rankers[fam] = None

        # Plugin (optional)
        plugin_spec = os.getenv(PLUGIN_ENV, "").strip()
        if plugin_spec:
            try:
                self.plugin_fn = _import_plugin(plugin_spec)
                log.info("Loaded ranker plugin: %s", plugin_spec)
            except Exception as e:
                log.warning("Failed to load plugin '%s': %s", plugin_spec, e)

        # Pipeline (optional)
        p_path = _load_first_existing(PIPELINE_PATHS)
        if p_path:
            try:
                with open(p_path, "rb") as f:
                    self.pipeline = pickle.load(f)
                self._pipeline_path = str(p_path)
                log.info("Loaded feature pipeline: %s", p_path)
            except Exception as e:
                log.warning("Failed to load pipeline '%s': %s", p_path, e)
                self.pipeline = None

        # Generic model (optional)
        m_path = _load_first_existing(MODEL_PATHS)
        if m_path:
            try:
                # Prefer joblib if available by extension
                if str(m_path).endswith(".joblib") and joblib is not None:
                    self.model = joblib.load(m_path)
                else:
                    with open(m_path, "rb") as f:
                        self.model = pickle.load(f)
                self._model_path = str(m_path)
                log.info("Loaded recommender model: %s", m_path)
            except Exception as e:
                log.warning("Failed to load model '%s': %s", m_path, e)
                self.model = None

        # Meta (optional)
        meta_path = _load_first_existing(META_PATHS)
        if meta_path:
            try:
                self.meta = json.loads(meta_path.read_text(encoding="utf-8"))
                self._feature_dim = int(self.meta.get("feature_dim")) if self.meta.get("feature_dim") else None
                fn = self.meta.get("feature_names")
                if isinstance(fn, list) and all(isinstance(x, str) for x in fn):
                    self._feature_names = fn  # type: ignore
            except Exception as e:
                log.warning("Failed to parse meta '%s': %s", meta_path, e)
                self.meta = {}

        self.ready = True
        log.info(
            "Recommender ready: plugin=%s, model=%s, pipeline=%s, feature_dim=%s, rankers=%s",
            bool(self.plugin_fn), bool(self.model), bool(self.pipeline), self._feature_dim,
            {k: bool(v) for k, v in self.rankers.items()},
        )

    # ---------------------- internals ----------------------------------------

    def _vectorize_pair(self, feats: Any, payload: str) -> List[float]:
        """
        Combine endpoint features (vectorizable by _as_feature_vector) with payload descriptors.
        Must match the trainer used for ranker_{family}.joblib.
        """
        base = _as_feature_vector(feats, expected_dim=self._feature_dim, feature_names=self._feature_names) or []
        return base + _payload_desc(payload)

    def _rank_with_family_ranker(self, family: str, feats: Any, pool: List[str]) -> Optional[List[Tuple[str, float]]]:
        fam = (family or "").lower()
        rk = self.rankers.get(fam)
        if not rk:
            return None
        try:
            X = [self._vectorize_pair(feats, p) for p in pool]
            # XGBRanker.predict returns ranking scores; larger is better
            if hasattr(rk, "predict"):
                scores = rk.predict(X)  # type: ignore
            elif hasattr(rk, "decision_function"):
                scores = rk.decision_function(X)  # type: ignore
            elif hasattr(rk, "predict_proba"):
                proba = rk.predict_proba(X)  # type: ignore
                scores = [float(row[-1]) for row in proba]
            else:
                return None
            probs = _softmax([float(s) for s in scores])
            ranked = sorted(zip(pool, probs), key=lambda x: x[1], reverse=True)
            return [(p, float(prob)) for p, prob in ranked]
        except Exception as e:
            log.warning("Family ranker for %s failed: %s", fam, e)
            return None

    # ---------------------- public API ---------------------------------------

    def info(self) -> RecommenderInfo:
        return RecommenderInfo(
            ready=self.ready,
            model_type=type(self.model).__name__ if self.model else "none",
            model_path=self._model_path,
            pipeline_path=self._pipeline_path,
            plugin=os.getenv(PLUGIN_ENV) or None,
            feature_dim=self._feature_dim,
            rankers_loaded={k: bool(v) for k, v in self.rankers.items()},
        )

    def recommend(
        self,
        feats: Any,
        top_n: int = 3,
        threshold: float = 0.2,
        family: Optional[str] = None,
        candidates: Optional[Sequence[str]] = None,
        pool: Optional[Sequence[str]] = None,  # alias for candidates (matches fuzzer_core)
    ) -> List[Tuple[str, float]]:
        """
        Return [(payload, confidence)] ranked desc.
        Guarantees at least 1 item (unless no candidates found).
        """
        if not self.ready:
            self.load()

        fam = (family or "sqli").lower().strip()
        # Prefer `pool` kwarg (new) but accept legacy `candidates`
        pool_list: List[str] = list(pool) if pool is not None else (list(candidates) if candidates is not None else [])
        if not pool_list:
            pool_list = list(default_payloads_by_family(fam))

        if not pool_list:
            return []

        # 1) Per-family LTR ranker (authoritative if available and we know the family)
        ranker_ranked = self._rank_with_family_ranker(fam, feats, pool_list) if family else None
        if ranker_ranked:
            out = [(p, s) for p, s in ranker_ranked if s >= threshold][: max(1, top_n)]
            if out:
                return out

        # 2) Plugin path (authoritative if available)
        if self.plugin_fn:
            try:
                scores = self.plugin_fn(feats, pool_list)  # type: ignore
                if not isinstance(scores, (list, tuple)) or len(scores) != len(pool_list):
                    raise ValueError("Plugin returned invalid scores")
                probs = _softmax([float(s) for s in scores])
                ranked = sorted(zip(pool_list, probs), key=lambda x: x[1], reverse=True)
                out = [(p, float(s)) for p, s in ranked if s >= threshold][: max(1, top_n)]
                if out:
                    return out
            except Exception as e:
                log.warning("Plugin scoring failed, falling back: %s", e)

        # 3) Generic pointwise/probabilistic model path
        if self.model is not None:
            # Prepare feature vector (try pipeline first)
            X_vec: Optional[List[float]] = None
            if self.pipeline is not None:
                try:
                    # Let the pipeline decide how to transform feats (dict or raw)
                    X = self.pipeline.transform([feats])  # type: ignore
                    if np is not None:
                        X_vec = np.asarray(X).ravel().tolist()
                    else:
                        try:
                            X_vec = list(X.toarray().ravel())  # type: ignore
                        except Exception:
                            X_vec = list(X[0])  # type: ignore
                except Exception as e:
                    log.warning("Pipeline.transform failed: %s", e)
            else:
                X_vec = _as_feature_vector(feats, expected_dim=self._feature_dim, feature_names=self._feature_names)

            try:
                per_candidate_scores: Optional[List[float]] = None

                # Try a convention: model.score_candidates(feats, pool) -> list[float]
                if hasattr(self.model, "score_candidates"):
                    per_candidate_scores = list(self.model.score_candidates(feats, pool_list))  # type: ignore

                # Try a callable model(feats, pool) -> list[float]
                elif callable(self.model):
                    try:
                        per_candidate_scores = list(self.model(feats, pool_list))  # type: ignore
                    except TypeError:
                        per_candidate_scores = None  # signature mismatch

                if per_candidate_scores is not None and len(per_candidate_scores) == len(pool_list):
                    probs = _softmax([float(s) for s in per_candidate_scores])
                    ranked = sorted(zip(pool_list, probs), key=lambda x: x[1], reverse=True)
                    out = [(p, float(s)) for p, s in ranked if s >= threshold][: max(1, top_n)]
                    if out:
                        return out

                # Fall back to single-score path: predict_proba / decision_function / predict
                if X_vec is not None:
                    single_score = None
                    arr = [X_vec]

                    if hasattr(self.model, "predict_proba"):
                        proba = self.model.predict_proba(arr)  # type: ignore
                        try:
                            # If binary shape (1, 2), take class-1 prob
                            single_score = float(proba[0][-1])
                        except Exception:
                            single_score = float(proba[0])  # type: ignore
                    elif hasattr(self.model, "decision_function"):
                        df = self.model.decision_function(arr)  # type: ignore
                        if isinstance(df, (list, tuple)):
                            single_score = float(df[0])  # type: ignore
                        else:
                            single_score = float(df)      # type: ignore
                    elif hasattr(self.model, "predict"):
                        y = self.model.predict(arr)  # type: ignore
                        single_score = float(y[0]) if isinstance(y, (list, tuple)) else float(y)  # type: ignore

                    if single_score is not None:
                        # Normalize to [0,1] via logistic; then combine with heuristic ordering
                        try:
                            if np is not None:
                                p_hat = float(1.0 / (1.0 + np.exp(-single_score)))
                            else:
                                p_hat = 1.0 / (1.0 + pow(2.718281828, -single_score))
                        except Exception:
                            p_hat = 0.5

                        hints = _extract_hints(feats)
                        h_scores = [_heuristic_score(pl, fam, hints) for pl in pool_list]
                        # Blend: ML prior (same for all) + heuristic per-payload
                        blended = [0.5 * p_hat + 0.5 * h for h in h_scores]
                        probs = _softmax(blended)
                        ranked = sorted(zip(pool_list, probs), key=lambda x: x[1], reverse=True)
                        out = [(p, float(s)) for p, s in ranked if s >= threshold][: max(1, top_n)]
                        if out:
                            return out
            except Exception as e:
                log.warning("Model scoring failed, falling back: %s", e)

        # 4) Heuristic fallback (no model / plugin / ranker)
        hints = _extract_hints(feats)
        h_scores = [_heuristic_score(pl, fam, hints) for pl in pool_list]
        probs = _softmax(h_scores)
        ranked = sorted(zip(pool_list, probs), key=lambda x: x[1], reverse=True)
        out = [(p, float(s)) for p, s in ranked if s >= threshold][: max(1, top_n)]

        # Guarantee at least one payload
        if not out and pool_list:
            out = [(pool_list[0], 0.6 if family else 0.4)]
        return out


# ---- helpers ----------------------------------------------------------------

def _extract_hints(feats: Any) -> Dict[str, Any]:
    """
    Pull lightweight hints from features dict for heuristics.
    Non-fatal: returns {} if not applicable.
    """
    if isinstance(feats, dict):
        ct = feats.get("content_type") or feats.get("headers", {}).get("content-type")
        return {
            "content_type": ct,
        }
    return {}
