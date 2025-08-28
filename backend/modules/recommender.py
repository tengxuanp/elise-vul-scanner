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

# Per-family minimum probability thresholds (after softmax over rank scores)
PER_FAMILY_THRESHOLDS: Dict[str, float] = {
    "redirect": 0.35,
    "xss": 0.30,
    "sqli": 0.30,
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
        if np is not None and xs:
            a = np.asarray(xs, dtype=float)
            a = a - np.max(a)
            exp = np.exp(a)
            s = float(exp.sum()) or 1.0
            return (exp / s).tolist()
    except Exception:
        pass
    # Pure-Python fallback
    if not xs:
        return []
    m = max(xs)
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


def _extract_hints(feats: Any) -> Dict[str, Any]:
    """
    Pull lightweight hints from features dict for heuristics/filters.
    Non-fatal: returns {} if not applicable.
    Expected keys (best-effort):
      - content_type (or headers['content-type'])
      - injection_mode ('query'|'json'|'form'|'headers'|'path'|'multipart')
      - recent_fail_counts: {'xss': int, 'sqli': int, 'redirect': int}
    """
    hints: Dict[str, Any] = {}
    if isinstance(feats, dict):
        headers = feats.get("headers") or {}
        ct = feats.get("content_type") or headers.get("content-type") or headers.get("Content-Type")
        hints["content_type"] = ct
        hints["injection_mode"] = feats.get("injection_mode") or feats.get("mode")  # alias
        rf = feats.get("recent_fail_counts")
        if isinstance(rf, dict):
            hints["recent_fail_counts"] = {str(k): int(v) for k, v in rf.items() if isinstance(v, (int, float))}
    return hints


def _negative_feedback_penalty(family: str, hints: Dict[str, Any]) -> float:
    """
    Produce a penalty in [0, 0.35] based on recent failures for this family on the same endpoint shape.
    Softens overzealous retrying when oracles repeatedly return negatives.
    """
    rf = hints.get("recent_fail_counts") or {}
    n = int(rf.get(family, 0) or 0)
    if n <= 0:
        return 0.0
    # Sublinear: 1→0.10, 2→0.18, 3→0.24, 5→0.30, >=8→0.35
    table = {1: 0.10, 2: 0.18, 3: 0.24, 4: 0.28, 5: 0.30, 6: 0.32, 7: 0.34}
    return float(table.get(n, 0.35))


def _heuristic_score(payload: str, family: str, hints: Dict[str, Any]) -> float:
    """
    Very lightweight, explainable heuristic for fallback ranking.
    This is NOT ML, but gives sane ordering when no model is available.
    Returns a score in [0, 1].
    """
    p = (payload or "").lower()
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
        if "sleep(" in p or "benchmark(" in p or "waitfor" in p:
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

    # Hints: content-type / injection mode
    ct = str(hints.get("content_type") or "").lower()
    mode = str(hints.get("injection_mode") or "").lower()

    if family == "xss":
        # XSS is more plausible for HTML responses, less for pure JSON APIs
        if "text/html" in ct or "application/xhtml" in ct:
            score += 0.15
        elif "application/json" in ct:
            score -= 0.15
        if mode in ("json", "headers"):
            score -= 0.10  # DOM payloads rarely make sense here
    if family == "sqli":
        if mode in ("json", "form"):
            score += 0.12
        if "application/json" in ct or "x-www-form-urlencoded" in ct:
            score += 0.08

    # Clip to [0, 1]
    score = max(0.0, min(1.0, score))

    # Apply negative-feedback penalty (downweight families with recent failures)
    score = max(0.0, score - _negative_feedback_penalty(family, hints))
    return score


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

def default_payloads_by_family(family: str, *, context: Optional[Dict[str, Any]] = None) -> List[str]:
    """
    Return canonical payload pool for a family (via family_router if available).
    We best-effort pass context to family_router if it accepts it.
    """
    fam = (family or "").lower()
    # Try family_router with context if possible
    if _payload_pool_for:
        try:
            # Newer routers may accept context=...
            return list(_payload_pool_for(fam, context=context))  # type: ignore
        except TypeError:
            try:
                return list(_payload_pool_for(fam))  # type: ignore
            except Exception:
                pass
        except Exception:
            pass
    # minimal fallback
    if fam == "sqli":
        return ["' OR 1=1--", "') OR ('1'='1' -- ", "1 OR 1=1 -- ", "' UNION SELECT NULL-- "]
    if fam == "xss":
        return ['"/><script>alert(1)</script>', "<img src=x onerror=alert(1)>", "<svg/onload=alert(1)>"]
    if fam in ("redirect", "open_redirect"):
        return ["https://example.org/", "//evil.tld", "https:%2F%2Fevil.tld"]
    return []


def _filter_pool_by_context(pool: List[str], family: str, hints: Dict[str, Any]) -> List[str]:
    """
    Light filtering to avoid obviously-wrong payloads for a context.
    Non-destructive: if filtering would empty the pool, return the original pool.
    """
    if not pool:
        return pool
    ct = str(hints.get("content_type") or "").lower()
    mode = str(hints.get("injection_mode") or "").lower()
    out = pool

    try:
        if family == "xss":
            # For JSON body injection, avoid payloads with naked angle brackets (likely to break JSON too early)
            if mode == "json":
                filtered = [p for p in pool if "\"</" not in p and "<script" not in p]
                if filtered:
                    out = filtered
            # For headers mode, prefer javascript: or event-attr style over full <script>
            if mode == "headers":
                filtered = [p for p in out if "javascript:" in p or "onerror=" in p or "onload=" in p] or out
                out = filtered
        elif family == "sqli":
            # Path-only injection often tolerates short boolean tests better than UNION
            if mode == "path":
                filtered = [p for p in pool if "union select" not in p.lower()] or pool
                out = filtered
        # Redirect family rarely needs filtering.
    except Exception:
        return pool

    return out or pool


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

    Preferred API:
      recommend_with_meta(
        feats, top_n=3, threshold=0.2, family=None, candidates=None, pool=None,
        family_thresholds=None, feedback=None
      ) -> (recommendations, meta_dict)

      - feedback (optional): {"recent_fail_counts": {"xss": 2, "sqli": 5, ...}}
        Downweights families with repeated negatives on the same endpoint shape.
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

    def _rank_with_family_ranker(self, family: str, feats: Any, pool: List[str]) -> Optional[Tuple[List[Tuple[str, float]], Dict[str, Any]]]:
        """
        Returns (ranked_payloads, meta) where ranked_payloads = [(payload, prob)], prob in [0,1].
        meta includes per-candidate raw scores and probabilities.
        """
        fam = (family or "").lower()
        rk = self.rankers.get(fam)
        if not rk:
            return None
        try:
            X = [self._vectorize_pair(feats, p) for p in pool]
            # Predict raw scores; larger is better
            if hasattr(rk, "predict"):
                scores = rk.predict(X)  # type: ignore
            elif hasattr(rk, "decision_function"):
                scores = rk.decision_function(X)  # type: ignore
            elif hasattr(rk, "predict_proba"):
                proba = rk.predict_proba(X)  # type: ignore
                # If predict_proba exists, take the positive class or the last class
                try:
                    scores = [float(row[-1]) for row in proba]
                except Exception:
                    scores = [float(proba[i]) for i in range(len(pool))]  # type: ignore
            else:
                return None

            scores = [float(s) for s in (scores.tolist() if hasattr(scores, "tolist") else scores)]
            probs = _softmax(scores)
            ranked_pairs = sorted(zip(pool, probs, scores), key=lambda x: x[1], reverse=True)
            ranked: List[Tuple[str, float]] = [(p, float(prob)) for p, prob, _ in ranked_pairs]
            meta = {
                "used_path": "family_ranker",
                "family": fam,
                "scores": [{"payload": p, "raw": float(raw), "prob": float(prob)} for p, prob, raw in ranked_pairs],
                "model_ids": {
                    "ranker_path": str(RANKER_PATHS.get(fam)) if RANKER_PATHS.get(fam) and RANKER_PATHS[fam].exists() else None,
                    "plugin": os.getenv(PLUGIN_ENV) or None,
                    "generic_model": self._model_path,
                    "pipeline": self._pipeline_path,
                },
            }
            return ranked, meta
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

    def recommend_with_meta(
        self,
        feats: Any,
        top_n: int = 3,
        threshold: float = 0.2,
        family: Optional[str] = None,
        candidates: Optional[Sequence[str]] = None,
        pool: Optional[Sequence[str]] = None,  # alias for candidates (matches fuzzer_core)
        family_thresholds: Optional[Dict[str, float]] = None,
        feedback: Optional[Dict[str, Any]] = None,  # {"recent_fail_counts": {"xss": 2, ...}}
    ) -> Tuple[List[Tuple[str, float]], Dict[str, Any]]:
        """
        Return ([(payload, confidence)], meta) ranked desc.
        Guarantees at least 1 item (unless no candidates found).
        meta is suitable to be attached to evidence as `ranker_meta`.

        feedback: optional dict to downweight families that recently failed on the same endpoint+param shape.
        """
        if not self.ready:
            self.load()

        fam = (family or "sqli").lower().strip()
        # Prefer `pool` kwarg (new) but accept legacy `candidates`
        pool_list: List[str] = list(pool) if pool is not None else (list(candidates) if candidates is not None else [])

        # Extract hints & merge feedback
        hints = _extract_hints(feats)
        if isinstance(feedback, dict):
            # merge user-provided feedback into hints (non-destructive)
            if isinstance(feedback.get("recent_fail_counts"), dict):
                hints["recent_fail_counts"] = {
                    **(hints.get("recent_fail_counts") or {}),
                    **{str(k): int(v) for k, v in feedback["recent_fail_counts"].items() if isinstance(v, (int, float))}
                }

        if not pool_list:
            pool_list = list(default_payloads_by_family(fam, context=hints))

        # Contextual filtering (never empty the pool)
        pool_list = _filter_pool_by_context(pool_list, fam, hints)

        meta_out: Dict[str, Any] = {
            "used_path": "none",
            "family": fam if family else None,
            "applied_threshold": float(threshold),
            "scores": [],
            "ranker_score": None,
            "top_payload": None,
            "model_ids": {
                "ranker_path": str(RANKER_PATHS.get(fam)) if family and RANKER_PATHS.get(fam) and RANKER_PATHS[fam].exists() else None,
                "plugin": os.getenv(PLUGIN_ENV) or None,
                "generic_model": self._model_path,
                "pipeline": self._pipeline_path,
            },
            "hints": hints,
        }

        if not pool_list:
            return [], meta_out

        # Effective threshold (per-family override)
        fam_thresholds = (family_thresholds or PER_FAMILY_THRESHOLDS).copy()
        # Also nudge threshold upward if we have strong negative feedback for this family
        eff_threshold = float(max(threshold, fam_thresholds.get(fam, threshold)))
        penalty = _negative_feedback_penalty(fam, hints)
        eff_threshold = min(0.95, eff_threshold + 0.5 * penalty)  # raise threshold modestly on repeated fails
        meta_out["applied_threshold"] = eff_threshold

        # 1) Per-family LTR ranker (authoritative if available and we know the family)
        ranked_with_meta = self._rank_with_family_ranker(fam, feats, pool_list) if family else None
        if ranked_with_meta:
            ranked, m = ranked_with_meta
            meta_out.update(m)
            # Apply penalty to probabilities, then threshold & top_n
            penalized = [(p, max(0.0, s - penalty)) for (p, s) in ranked]
            out = [(p, s) for p, s in penalized if s >= eff_threshold][: max(1, top_n)]
            if out:
                meta_out["ranker_score"] = float(out[0][1])
                meta_out["top_payload"] = out[0][0]
                return out, meta_out

        # 2) Plugin path (authoritative if available)
        if self.plugin_fn:
            try:
                scores = self.plugin_fn(feats, pool_list)  # type: ignore
                if not isinstance(scores, (list, tuple)) or len(scores) != len(pool_list):
                    raise ValueError("Plugin returned invalid scores")
                scores = [float(s) for s in scores]
                probs = _softmax(scores)
                ranked_pairs = sorted(zip(pool_list, probs, scores), key=lambda x: x[1], reverse=True)
                penalized = [(p, max(0.0, float(prob) - penalty), raw) for p, prob, raw in ranked_pairs]
                out = [(p, s) for (p, s, _raw) in penalized if s >= eff_threshold][: max(1, top_n)]
                meta_out.update({
                    "used_path": "plugin",
                    "scores": [{"payload": p, "raw": float(raw), "prob": float(prob)} for p, prob, raw in ranked_pairs],
                    "penalty_applied": penalty,
                })
                if out:
                    meta_out["ranker_score"] = float(out[0][1])
                    meta_out["top_payload"] = out[0][0]
                    return out, meta_out
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
                    scores = [float(s) for s in per_candidate_scores]
                    probs = _softmax(scores)
                    ranked_pairs = sorted(zip(pool_list, probs, scores), key=lambda x: x[1], reverse=True)
                    penalized = [(p, max(0.0, float(prob) - penalty), raw) for p, prob, raw in ranked_pairs]
                    out = [(p, s) for (p, s, _raw) in penalized if s >= eff_threshold][: max(1, top_n)]
                    meta_out.update({
                        "used_path": "generic_pairwise",
                        "scores": [{"payload": p, "raw": float(raw), "prob": float(prob)} for p, prob, raw in ranked_pairs],
                        "penalty_applied": penalty,
                    })
                    if out:
                        meta_out["ranker_score"] = float(out[0][1])
                        meta_out["top_payload"] = out[0][0]
                        return out, meta_out

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
                        meta_out["used_path"] = "generic_predict_proba"
                    elif hasattr(self.model, "decision_function"):
                        df = self.model.decision_function(arr)  # type: ignore
                        if isinstance(df, (list, tuple)):
                            single_score = float(df[0])  # type: ignore
                        else:
                            single_score = float(df)      # type: ignore
                        meta_out["used_path"] = "generic_decision_function"
                    elif hasattr(self.model, "predict"):
                        y = self.model.predict(arr)  # type: ignore
                        single_score = float(y[0]) if isinstance(y, (list, tuple)) else float(y)  # type: ignore
                        meta_out["used_path"] = "generic_predict"

                    if single_score is not None:
                        # Normalize to [0,1] via logistic; then combine with heuristic ordering
                        try:
                            if np is not None:
                                p_hat = float(1.0 / (1.0 + np.exp(-single_score)))
                            else:
                                p_hat = 1.0 / (1.0 + pow(2.718281828, -single_score))
                        except Exception:
                            p_hat = 0.5

                        h_scores = [_heuristic_score(pl, fam, hints) for pl in pool_list]
                        blended = [0.5 * p_hat + 0.5 * h for h in h_scores]
                        probs = _softmax(blended)
                        ranked_pairs = sorted(zip(pool_list, probs, blended), key=lambda x: x[1], reverse=True)
                        penalized = [(p, max(0.0, float(prob) - penalty), raw) for p, prob, raw in ranked_pairs]
                        out = [(p, s) for (p, s, _raw) in penalized if s >= eff_threshold][: max(1, top_n)]
                        meta_out["scores"] = [{"payload": p, "raw": float(raw), "prob": float(prob)} for p, prob, raw in ranked_pairs]
                        meta_out["penalty_applied"] = penalty
                        if out:
                            meta_out["ranker_score"] = float(out[0][1])
                            meta_out["top_payload"] = out[0][0]
                            return out, meta_out
            except Exception as e:
                log.warning("Model scoring failed, falling back: %s", e)

        # 4) Heuristic fallback (no model / plugin / ranker)
        h_scores = [_heuristic_score(pl, fam, hints) for pl in pool_list]
        probs = _softmax(h_scores)
        ranked_pairs = sorted(zip(pool_list, probs, h_scores), key=lambda x: x[1], reverse=True)
        penalized = [(p, max(0.0, float(prob) - penalty), raw) for p, prob, raw in ranked_pairs]
        out = [(p, s) for (p, s, _raw) in penalized if s >= eff_threshold][: max(1, top_n)]

        meta_out.update({
            "used_path": "heuristic",
            "scores": [{"payload": p, "raw": float(raw), "prob": float(prob)} for p, prob, raw in ranked_pairs],
            "penalty_applied": penalty,
        })

        # Guarantee at least one payload
        if not out and pool_list:
            fallback = (pool_list[0], max(0.0, 0.4 - penalty))
            out = [fallback]
            meta_out["ranker_score"] = float(fallback[1])
            meta_out["top_payload"] = fallback[0]
        elif out:
            meta_out["ranker_score"] = float(out[0][1])
            meta_out["top_payload"] = out[0][0]

        return out, meta_out

    def recommend(
        self,
        feats: Any,
        top_n: int = 3,
        threshold: float = 0.2,
        family: Optional[str] = None,
        candidates: Optional[Sequence[str]] = None,
        pool: Optional[Sequence[str]] = None,  # alias for candidates (matches fuzzer_core)
        feedback: Optional[Dict[str, Any]] = None,
    ) -> List[Tuple[str, float]]:
        """
        Backward-compatible wrapper: returns only [(payload, confidence)].
        Prefer `recommend_with_meta` in the core so you can log `ranker_meta`.
        """
        out, _meta = self.recommend_with_meta(
            feats=feats,
            top_n=top_n,
            threshold=threshold,
            family=family,
            candidates=candidates,
            pool=pool,
            feedback=feedback,
        )
        return out
