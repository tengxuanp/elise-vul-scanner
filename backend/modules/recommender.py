# backend/modules/recommender.py
from __future__ import annotations

import json
import logging
import os
import pickle
import re
from dataclasses import dataclass
from importlib import import_module
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

try:
    import numpy as np
except Exception:  # numpy is optional; we degrade gracefully
    np = None  # type: ignore

# Delegate per-family LTR to the authoritative inference module
try:
    from .ml.infer_ranker import rank_payloads as ltr_rank_payloads  # type: ignore
except Exception as _e:
    ltr_rank_payloads = None  # type: ignore
    logging.getLogger(__name__).warning(
        "Per-family ranker unavailable (ml.infer_ranker import failed): %s", _e
    )

try:
    import joblib  # used only for family_clf and optional generic .joblib model
except Exception:
    joblib = None  # type: ignore

# Prefer canonical pools via family_router; degrade gracefully if missing
try:
    from .family_router import payload_pool_for as _payload_pool_for
except Exception:
    _payload_pool_for = None  # type: ignore

log = logging.getLogger(__name__)

# ------------------------- runtime debug toggle ------------------------------

def _env_true(name: str, default: bool = False) -> bool:
    v = str(os.getenv(name, "")).strip().lower()
    if v in ("1", "true", "yes", "on"):
        return True
    if v in ("0", "false", "no", "off"):
        return False
    return default

_DEBUG_STATE = {
    "enabled": _env_true("ELISE_ML_DEBUG", False)
}
STRICT_SHAPE = _env_true("ELISE_STRICT_SHAPE", True)  # hard-fail on feature dim mismatches

def _is_debug() -> bool:
    # dynamic: honors both process env and runtime switch
    return _DEBUG_STATE["enabled"] or _env_true("ELISE_ML_DEBUG", False)

def set_ml_debug(enabled: bool) -> None:
    """Enable/disable verbose ML logging at runtime (usable from web UI/admin)."""
    _DEBUG_STATE["enabled"] = bool(enabled)
    log.setLevel(logging.DEBUG if enabled else logging.INFO)
    os.environ["ELISE_ML_DEBUG"] = "1" if enabled else "0"
    log.info("ML debug %s", "ENABLED" if enabled else "DISABLED")

# initialize logger level once on import
log.setLevel(logging.DEBUG if _is_debug() else logging.INFO)
if _is_debug():
    log.debug("ELISE_ML_DEBUG enabled -> verbose logging (STRICT_SHAPE=%s)", STRICT_SHAPE)

# ---- configuration -----------------------------------------------------------

# Resolve the base dir for ML artifacts (env override supported)
def _model_base_dir() -> Path:
    env_dir = os.getenv("MODEL_DIR") or os.getenv("ELISE_MODEL_DIR")
    if env_dir:
        p = Path(env_dir)
        if p.exists() and any((p / f"ranker_{fam}.joblib").exists() for fam in ("sqli", "xss", "redirect")):
            return p
    return Path(__file__).resolve().parent / "ml"

ML_BASE = _model_base_dir()
ML_DIR = Path(__file__).resolve().parent / "ml"  # historical location (still used for legacy files)

# Legacy / generic model (not per-family). Kept for backward compatibility.
MODEL_PATHS = [
    ML_BASE / "recommender_model.pkl",
    ML_BASE / "recommender_model.joblib",
    ML_DIR / "recommender_model.pkl",      # fallback to old location
    ML_DIR / "recommender_model.joblib",
]
PIPELINE_PATHS = [
    ML_BASE / "feature_pipeline.pkl",
    ML_DIR / "feature_pipeline.pkl",       # fallback
]
META_PATHS = [
    ML_BASE / "recommender_meta.json",
    ML_DIR / "recommender_meta.json",      # fallback
]

# Per-family LTR ranker file locations (existence check only; loading is done in infer_ranker)
RANKER_PATHS = {
    "sqli": (ML_BASE / "ranker_sqli.joblib"),
    "xss": (ML_BASE / "ranker_xss.joblib"),
    "redirect": (ML_BASE / "ranker_redirect.joblib"),
}

# Optional FAMILY CLASSIFIER to choose a family when caller doesn't pass one
FAMILY_CLF_PATH = (ML_BASE / "family_clf.joblib") if (ML_BASE / "family_clf.joblib").exists() else (ML_DIR / "family_clf.joblib")

# Per-family minimum probability thresholds (after softmax over rank scores)
# Overridable via ELISE_FAM_THRESHOLDS env (e.g., "sqli:0.2,xss:0.2,redirect:0.18")
PER_FAMILY_THRESHOLDS: Dict[str, float] = {
    "redirect": 0.18,
    "xss": 0.20,
    "sqli": 0.20,
    "base": 0.10,
}

# Optional plugin to support pairwise scoring:
#   ELISE_RANKER_PLUGIN="backend.modules.ml.ranker:score"
# The callable signature must be: score(feats: Any, payloads: List[str]) -> List[float]
PLUGIN_ENV = "ELISE_RANKER_PLUGIN"

# Weak prior keywords used when family_clf is missing
PRIORS = {
    "sqli": {"id", "uid", "user", "prod", "item", "cat", "page", "sort", "order"},
    "xss": {"q", "query", "search", "term", "msg", "name", "email", "comment"},
    "redirect": {"return", "return_to", "next", "url", "dest", "target", "to", "redir"},
}

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
    family_clf_loaded: bool

# ---- utility ----------------------------------------------------------------

def _load_first_existing(paths: Sequence[Path]) -> Optional[Path]:
    for p in paths:
        if p.exists():
            if _is_debug():
                log.debug("Using first existing path: %s", p)
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
            v = [float(feats)]
        if expected_dim is not None and len(v) != expected_dim:
            msg = (
                f"Feature length {len(v)} != expected {expected_dim}; "
                f"(Check FeatureExtractor and recommender_meta.json)"
            )
            if STRICT_SHAPE:
                raise ValueError(msg)
            log.error(msg)
        if _is_debug():
            log.debug("Vectorized endpoint features: len=%s expected=%s", len(v), expected_dim)
        return v
    except Exception as e:
        log.exception("Failed to coerce features to vector: %s", e)
        if STRICT_SHAPE:
            raise
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
        if "text/html" in ct or "application/xhtml" in ct:
            score += 0.15
        elif "application/json" in ct:
            score -= 0.15
        if mode in ("json", "headers"):
            score -= 0.10
    if family == "sqli":
        if mode in ("json", "form"):
            score += 0.12
        if "application/json" in ct or "x-www-form-urlencoded" in ct:
            score += 0.08

    score = max(0.0, min(1.0, score))
    score = max(0.0, score - _negative_feedback_penalty(family, hints))
    return score

# -------------------- Payload descriptor (20 dims) for legacy model ----------

_BASE64ISH_RE = re.compile(r'^[A-Za-z0-9+/=]{12,}$')

def _payload_desc(payload: str) -> List[float]:
    """
    Deterministic payload features (kept ONLY for the legacy generic path).
    LTR models use ml.infer_ranker exclusively.
    """
    s = payload or ""
    lower = s.lower()
    specials = sum(1 for ch in s if not ch.isalnum())

    # XSS cues
    has_script_tag    = "<script" in lower or "</script>" in lower
    has_event_attr    = ("onerror=" in lower) or ("onload=" in lower) or ("onclick=" in lower)
    has_img           = "<img" in lower
    has_svg           = "<svg" in lower
    has_js_url        = "javascript:" in lower
    starts_with_angle = s[:1] in "<>"
    has_attr_breakout = (('"' in s or "'" in s) and (" on" in lower or "javascript:" in lower))
    has_close_script  = "</script>" in lower

    # SQLi cues
    has_union         = "union select" in lower
    has_or_1eq1       = (" or 1=1" in lower) or ("' or" in lower) or ('" or' in lower)
    has_comment       = "--" in lower or "/*" in lower or "*/" in lower
    has_time_fn       = ("sleep(" in lower) or ("benchmark(" in lower) or ("waitfor" in lower)
    is_numeric_like   = lower.strip().isdigit() or lower.strip().replace(".", "", 1).isdigit()

    # Redirect cues
    is_proto_rel      = lower.startswith("//")
    has_double_urlenc = "%252f%252f" in lower or "%2f%2f" in lower
    has_js_location   = "window.location" in lower
    has_http          = lower.startswith("http://") or lower.startswith("https://")
    looks_base64      = bool(_BASE64ISH_RE.match(s))

    return [
        float(len(s)),                # 0 length
        float(specials),              # 1 specials
        1.0 if has_script_tag else 0.0,     # 2
        1.0 if has_event_attr else 0.0,     # 3
        1.0 if has_img else 0.0,            # 4
        1.0 if has_svg else 0.0,            # 5
        1.0 if has_js_url else 0.0,         # 6
        1.0 if starts_with_angle else 0.0,  # 7
        1.0 if has_attr_breakout else 0.0,  # 8
        1.0 if has_close_script else 0.0,   # 9
        1.0 if has_union else 0.0,          # 10
        1.0 if has_or_1eq1 else 0.0,        # 11
        1.0 if has_comment else 0.0,        # 12
        1.0 if has_time_fn else 0.0,        # 13
        1.0 if is_numeric_like else 0.0,    # 14
        1.0 if is_proto_rel else 0.0,       # 15
        1.0 if has_double_urlenc else 0.0,  # 16
        1.0 if has_js_location else 0.0,    # 17
        1.0 if has_http else 0.0,           # 18
        1.0 if looks_base64 else 0.0,       # 19
    ]

def _tokenize(s: str) -> List[str]:
    return [t for t in re.split(r"[/\-_\.?=&:#]+", (s or "").lower()) if t]

def _extract_family_text(feats: Any) -> Tuple[str, str, str]:
    """
    Build a simple family-classifier text "METHOD path_tokens param_tokens".
    """
    if isinstance(feats, dict):
        method = str(feats.get("method") or "GET").upper()
        url = str(feats.get("url") or feats.get("path") or "/")
        param = str(feats.get("param") or feats.get("param_name") or "")
    else:
        method, url, param = "GET", "/", ""
    path_tokens = " ".join(_tokenize(url))
    param_tokens = " ".join(_tokenize(param))
    return method, path_tokens, param_tokens

def _prior_family_from_tokens(param: str, path_tokens: str) -> str:
    p = (param or "").lower()
    for fam, keys in PRIORS.items():
        if any(k in p for k in keys):
            return fam
    if "search" in path_tokens or "query" in path_tokens:
        return "xss"
    if any(k in path_tokens for k in ("prod", "item", "order", "cat", "id")):
        return "sqli"
    if any(k in path_tokens for k in ("login", "redir", "return")):
        return "redirect"
    return "base"

# ---- canonical pool access (compat shim) ------------------------------------

def default_payloads_by_family(family: str, *, context: Optional[Dict[str, Any]] = None) -> List[str]:
    """
    Return canonical payload pool for a family (via family_router if available).
    We best-effort pass context to family_router if it accepts it.
    Always returns a list, even if router hands us a set/generator.
    """
    fam = (family or "").lower()
    if _payload_pool_for:
        try:
            res = _payload_pool_for(fam, context=context)  # type: ignore
        except TypeError:
            try:
                res = _payload_pool_for(fam)  # type: ignore
            except Exception:
                res = None
        except Exception:
            res = None
        try:
            return list(res) if res is not None else []
        except Exception:
            return []
    # minimal fallback
    if fam == "sqli":
        return ["' OR 1=1--", "') OR ('1'='1' -- ", "1 OR 1=1 -- ", "' UNION SELECT NULL-- "]
    if fam == "xss":
        return ['"/><script>alert(1)</script>', "<img src=x onerror=alert(1)>", "<svg/onload=alert(1)>"]
    if fam in ("redirect", "open_redirect"):
        return ["https://example.org/", "//evil.tld", "https:%2F%2Fevil.tld"]
    if fam == "base":
        return ["*", "%27", "%22", "()", "{}"]
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
            if mode == "json":
                # Keep quote-breakouts (common in JSON reflection); only drop literal <script>
                filtered = [p for p in pool if "<script" not in p.lower()] or pool
                out = filtered
            if mode == "headers":
                filtered = [p for p in out if ("javascript:" in p or "onerror=" in p or "onload=" in p)] or out
                out = filtered
        elif family == "sqli":
            if mode == "path":
                filtered = [p for p in pool if "union select" not in p.lower()] or pool
                out = filtered
    except Exception:
        return pool

    return out or pool

# ---- env parsing -------------------------------------------------------------

def _parse_family_thresholds_env(env_str: str) -> Dict[str, float]:
    """
    Parse ELISE_FAM_THRESHOLDS like: "sqli:0.2,xss:0.2,redirect:0.18"
    """
    out: Dict[str, float] = {}
    for part in (env_str or "").split(","):
        part = part.strip()
        if not part or ":" not in part:
            continue
        k, v = part.split(":", 1)
        k = k.strip().lower()
        try:
            out[k] = float(v.strip())
        except Exception:
            continue
    return out

# ---- LTR shim (tolerate signature drift) ------------------------------------

def _call_ltr(endpoint_meta: Dict[str, Any], fam: str, candidates: List[Dict[str, Any]], top_k: int):
    if ltr_rank_payloads is None:
        return None
    try:
        return ltr_rank_payloads(endpoint_meta, fam, candidates, top_k=top_k)
    except TypeError:
        try:
            return ltr_rank_payloads(fam, endpoint_meta, candidates, top_k)
        except TypeError:
            try:
                return ltr_rank_payloads(context=endpoint_meta, family=fam, candidates=candidates, top_k=top_k)
            except TypeError:
                try:
                    return ltr_rank_payloads(context=endpoint_meta, family=fam, candidates=candidates)
                except Exception:
                    return None
    except Exception:
        return None

# ---- recommender -------------------------------------------------------------

class Recommender:
    """
    Rank payloads for a given request/features.

    Load/decision order:
      1) Per-family LTR rankers via ml.infer_ranker (authoritative if available).
      2) Optional plugin:   ELISE_RANKER_PLUGIN="module.sub:score" -> score(feats, payloads) -> list[float]
      3) Generic model:     recommender_model.(pkl|joblib) (legacy, optional)
      4) Heuristic fallback.

    Public API (backward compatible):
      recommend(feats, top_n=3, threshold=0.2, family=None, candidates=None, pool=None)

    Preferred API:
      recommend_with_meta(...) -> (recommendations, meta_dict)
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

        # Family classifier (optional)
        self.family_clf: Any = None
        self.family_classes: Optional[List[str]] = None

    # ---------------------- lifecycle ----------------------------------------

    def load(self) -> None:
        """
        Load meta first, then plugin, pipeline/model, and family classifier.
        (Per-family rankers are loaded lazily by ml.infer_ranker; we do not duplicate it here.)
        """
        # Meta (load first so we know expected endpoint feature length)
        meta_path = _load_first_existing(META_PATHS)
        if meta_path:
            try:
                self.meta = json.loads(meta_path.read_text(encoding="utf-8"))
                self._feature_dim = int(self.meta.get("feature_dim")) if self.meta.get("feature_dim") else None
                fn = self.meta.get("endpoint_feature_names") or self.meta.get("feature_names")
                if isinstance(fn, list) and all(isinstance(x, str) for x in fn):
                    self._feature_names = fn  # type: ignore
                log.info("Loaded recommender meta: %s (feature_dim=%s)", meta_path, self._feature_dim)
            except Exception as e:
                log.exception("Failed to parse meta '%s': %s", meta_path, e)
                self.meta = {}

        # Plugin (optional)
        plugin_spec = os.getenv(PLUGIN_ENV, "").strip()
        if plugin_spec:
            try:
                self.plugin_fn = _import_plugin(plugin_spec)
                log.info("Loaded ranker plugin: %s", plugin_spec)
            except Exception as e:
                log.exception("Failed to load plugin '%s': %s", plugin_spec, e)

        # Pipeline (optional)
        p_path = _load_first_existing(PIPELINE_PATHS)
        if p_path:
            try:
                with open(p_path, "rb") as f:
                    self.pipeline = pickle.load(f)
                self._pipeline_path = str(p_path)
                log.info("Loaded feature pipeline: %s", p_path)
            except Exception as e:
                log.exception("Failed to load pipeline '%s': %s", p_path, e)
                self.pipeline = None

        # Generic model (optional)
        m_path = _load_first_existing(MODEL_PATHS)
        if m_path:
            try:
                if str(m_path).endswith(".joblib") and joblib is not None:
                    self.model = joblib.load(m_path)
                else:
                    with open(m_path, "rb") as f:
                        self.model = pickle.load(f)
                self._model_path = str(m_path)
                log.info("Loaded generic recommender model: %s", m_path)
            except Exception as e:
                log.exception("Failed to load generic model '%s': %s", m_path, e)
                self.model = None

        # Family classifier (optional)
        if joblib is not None and FAMILY_CLF_PATH.exists():
            try:
                self.family_clf = joblib.load(FAMILY_CLF_PATH)
                self.family_classes = list(getattr(self.family_clf, "classes_", []) or ["sqli", "xss", "redirect", "base"])
                log.info("Loaded family classifier: %s (classes=%s)", FAMILY_CLF_PATH, self.family_clf.classes_ if hasattr(self.family_clf, "classes_") else None)
            except Exception as e:
                log.exception("Failed to load family classifier '%s': %s", FAMILY_CLF_PATH, e)
                self.family_clf, self.family_classes = None, None

        self.ready = True
        # Report existence using the env-resolved base dir
        log.info(
            "Recommender ready: plugin=%s, model=%s, pipeline=%s, feature_dim=%s, rankers_exist=%s, family_clf=%s, model_dir=%s",
            bool(self.plugin_fn), bool(self.model), bool(self.pipeline), self._feature_dim,
            {k: p.exists() for k, p in RANKER_PATHS.items()}, bool(self.family_clf), str(ML_BASE),
        )

    # ---------------------- internals ----------------------------------------

    def _endpoint_meta_from_feats(self, feats: Any) -> Dict[str, Any]:
        """
        Build the endpoint_meta dict expected by ml.infer_ranker:
        {url, param, method, content_type, headers}
        """
        if isinstance(feats, dict):
            headers = feats.get("headers") or {}
            return {
                "url": feats.get("url") or feats.get("path") or "",
                "param": feats.get("param") or feats.get("param_name") or "",
                "method": (feats.get("method") or "GET"),
                "content_type": feats.get("content_type") or headers.get("content-type") or headers.get("Content-Type"),
                "headers": headers or None,
            }
        # best-effort defaults
        return {"url": "", "param": "", "method": "GET", "content_type": None, "headers": None}

    def _rank_with_family_ranker(
        self,
        family: str,
        feats: Any,
        pool: List[str],
        fam_probs: Optional[Dict[str, float]] = None,
    ) -> Optional[Tuple[List[Tuple[str, float]], Dict[str, Any]]]:
        """
        Delegate to ml.infer_ranker.rank_payloads and convert raw scores → softmax probs.
        Returns ([(payload, prob)], meta)
        """
        if ltr_rank_payloads is None:
            return None

        fam = (family or "").lower()
        try:
            endpoint_meta = self._endpoint_meta_from_feats(feats)
            candidates = [{"payload_id": None, "payload": p} for p in pool]
            ranked = _call_ltr(endpoint_meta, fam, candidates, top_k=len(pool))
            if not isinstance(ranked, list) or not ranked:
                return None

            # Extract raw scores & whether a real model was used
            raw_scores: List[float] = []
            payloads_out: List[str] = []
            used_model_path = None
            total_dim = None
            for i, item in enumerate(ranked):
                payloads_out.append(str(item.get("payload", "")))
                rs = item.get("ranker_score")
                if rs is None:
                    rs = float(len(ranked) - i)  # deterministic fallback if not attached
                raw_scores.append(float(rs))
                if item.get("ranker_used_model"):
                    used_model_path = item.get("ranker_used_model")
                total_dim = total_dim or item.get("ranker_feature_dim_total")

            probs = _softmax(raw_scores)
            ranked_pairs = list(zip(payloads_out, probs, raw_scores))  # [(payload, prob, raw)]
            ranked_pairs.sort(key=lambda x: x[1], reverse=True)

            model_used = bool(used_model_path)
            used_path_label = "family_ranker" if model_used else "heuristic"

            meta = {
                "used_path": used_path_label,
                "family": fam,
                # preserve family probs if we had them; else make a degenerate dist so UI won't synthesize
                "family_probs": (fam_probs if fam_probs else {
                    "sqli": 1.0 if fam == "sqli" else 0.0,
                    "xss": 1.0 if fam == "xss" else 0.0,
                    "redirect": 1.0 if fam == "redirect" else 0.0,
                }),
                "scores": [{"payload": p, "raw": float(r), "prob": float(pr)} for (p, pr, r) in ranked_pairs],
                "model_ids": {
                    "ranker_path": str(used_model_path) if used_model_path else (
                        str(RANKER_PATHS.get(fam)) if RANKER_PATHS.get(fam) and RANKER_PATHS[fam].exists() else None
                    ),
                    "plugin": os.getenv(PLUGIN_ENV) or None,
                    "generic_model": self._model_path,
                    "pipeline": self._pipeline_path,
                },
                "feature_dim": self._feature_dim,
                "expected_total_dim": total_dim or ((self._feature_dim + 20) if self._feature_dim is not None else None),
            }
            return ([(p, float(pr)) for (p, pr, _r) in ranked_pairs], meta)
        except Exception as e:
            log.exception("Family ranker (infer_ranker) failed for '%s': %s. Falling back.", fam, e)
            return None

    def _predict_family(self, feats: Any, prob_threshold: float = 0.55) -> Tuple[str, Dict[str, float], str]:
        """
        Choose a payload family.
        """
        method, path_tokens, param_tokens = _extract_family_text(feats)
        text = f"{method} {path_tokens} {param_tokens}".strip()

        # Default priors
        fallback_fam = _prior_family_from_tokens(param_tokens, path_tokens)
        probs = {"sqli": 0.25, "xss": 0.25, "redirect": 0.25, "base": 0.25}

        if self.family_clf is not None:
            try:
                if hasattr(self.family_clf, "predict_proba"):
                    proba = self.family_clf.predict_proba([text])[0]  # type: ignore
                    classes = list(getattr(self.family_clf, "classes_", []) or ["sqli", "xss", "redirect", "base"])
                    probs = {str(c): float(p) for c, p in zip(classes, proba)}
                elif hasattr(self.family_clf, "decision_function"):
                    df = self.family_clf.decision_function([text])  # type: ignore
                    if isinstance(df, (list, tuple, np.ndarray)):
                        scores = list(df if isinstance(df, (list, tuple)) else df.tolist())
                    else:
                        scores = [float(df)]
                    classes = list(getattr(self.family_clf, "classes_", []) or ["sqli", "xss", "redirect", "base"])
                    if len(scores) != len(classes):
                        scores = scores * len(classes)
                    s_probs = _softmax(scores)
                    probs = {str(c): float(p) for c, p in zip(classes, s_probs)}
                fam_sorted = sorted(probs.items(), key=lambda kv: kv[1], reverse=True)
                top_f, top_p = fam_sorted[0][0], fam_sorted[0][1]
                reason = "model_confident" if top_p >= prob_threshold else "below_threshold_explore"
                # normalize alias if any
                probs = {("redirect" if k == "open_redirect" else k): float(v) for k, v in probs.items()}
                return top_f, probs, reason
            except Exception as e:
                log.exception("Family classifier failed: %s; falling back to priors", e)

        # Priors fallback
        base = {"sqli", "xss", "redirect", "base"}
        if fallback_fam not in base:
            fallback_fam = "base"
        rem = list(base - {fallback_fam})
        probs = {f: (0.2) for f in rem}
        probs[fallback_fam] = 0.4 if fallback_fam == "base" else 0.6
        return fallback_fam, probs, "prior"

    # ---------------------- public API ---------------------------------------

    def info(self) -> RecommenderInfo:
        return RecommenderInfo(
            ready=self.ready,
            model_type=type(self.model).__name__ if self.model else "none",
            model_path=self._model_path,
            pipeline_path=self._pipeline_path,
            plugin=os.getenv(PLUGIN_ENV) or None,
            feature_dim=self._feature_dim,
            # We don’t load rankers here; report existence instead of load state.
            rankers_loaded={k: p.exists() for k, p in RANKER_PATHS.items()},
            family_clf_loaded=bool(self.family_clf),
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
        """
        if not self.ready:
            self.load()

        # Select / predict family if not provided
        fam_decision = "caller_provided"
        fam_probs: Dict[str, float] = {}
        if not family:
            selected_fam, fam_probs, fam_decision = self._predict_family(feats, prob_threshold=0.55)
            family = selected_fam

        fam = (family or "sqli").lower().strip()
        if fam == "open_redirect":
            fam = "redirect"  # normalize aliases

        # Prefer `pool` kwarg (new) but accept legacy `candidates`
        pool_list: List[str] = list(pool) if pool is not None else (list(candidates) if candidates is not None else [])

        # Extract hints & merge feedback
        hints = _extract_hints(feats)
        if isinstance(feedback, dict):
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
            "family": fam,
            "family_probs": fam_probs or None,
            "family_decision": fam_decision,
            "applied_threshold": float(threshold),
            "scores": [],
            "ranker_score": None,
            "top_payload": None,
            "model_ids": {
                "ranker_path": str(RANKER_PATHS.get(fam)) if RANKER_PATHS.get(fam) and RANKER_PATHS[fam].exists() else None,
                "plugin": os.getenv(PLUGIN_ENV) or None,
                "generic_model": self._model_path,
                "pipeline": self._pipeline_path,
                "family_clf": str(FAMILY_CLF_PATH) if (FAMILY_CLF_PATH.exists()) else None,
            },
            "hints": hints,
            "feature_dim": self._feature_dim,
            "expected_total_dim": (self._feature_dim + 20) if self._feature_dim is not None else None,
        }

        if not pool_list:
            return [], meta_out

        # Effective threshold (per-family override + env override)
        fam_thresholds_eff = (family_thresholds or PER_FAMILY_THRESHOLDS).copy()
        env_override = _parse_family_thresholds_env(os.getenv("ELISE_FAM_THRESHOLDS", ""))
        if env_override:
            fam_thresholds_eff.update({k: float(v) for k, v in env_override.items()})

        eff_threshold = float(max(threshold, fam_thresholds_eff.get(fam, threshold)))

        # Also nudge threshold upward if we have strong negative feedback for this family
        penalty = _negative_feedback_penalty(fam, hints)
        eff_threshold = min(0.95, eff_threshold + 0.5 * penalty)  # raise threshold modestly on repeated fails
        meta_out["applied_threshold"] = eff_threshold

        # 1) Per-family LTR ranker (authoritative if available and we know the family)
        ranked_with_meta = self._rank_with_family_ranker(fam, feats, pool_list, fam_probs=fam_probs or None)
        if ranked_with_meta:
            ranked, m = ranked_with_meta
            # keep previously-computed family_probs if the ranker didn't provide them
            meta_out.update(m)
            if not meta_out.get("family_probs"):
                meta_out["family_probs"] = fam_probs or {
                    "sqli": 1.0 if fam == "sqli" else 0.0,
                    "xss": 1.0 if fam == "xss" else 0.0,
                    "redirect": 1.0 if fam == "redirect" else 0.0,
                }

            # Adaptive cap: don't let an overly-high threshold discard all candidates
            best_penalized = max((max(0.0, s - penalty) for (_p, s) in ranked), default=0.0)
            eff_threshold = min(eff_threshold, max(0.05, best_penalized - 1e-3))
            meta_out["applied_threshold"] = eff_threshold
            meta_out["penalty_applied"] = penalty

            # Apply penalty to probabilities, then threshold & top_n
            penalized = [(p, max(0.0, s - penalty)) for (p, s) in ranked]
            out = [(p, s) for p, s in penalized if s >= eff_threshold][: max(1, top_n)]

            # Never discard ranker entirely: keep top-1 even if below threshold
            if not out and ranked:
                bp, bs = ranked[0]
                out = [(bp, max(0.0, bs - penalty))]
                meta_out["note"] = "kept_top1_from_ranker"

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

                best_penalized = max((max(0.0, float(prob) - penalty) for (_p, prob, _r) in ranked_pairs), default=0.0)
                eff_threshold = min(eff_threshold, max(0.05, best_penalized - 1e-3))
                meta_out["applied_threshold"] = eff_threshold

                penalized = [(p, max(0.0, float(prob) - penalty), raw) for p, prob, raw in ranked_pairs]
                out = [(p, s) for (p, s, _raw) in penalized if s >= eff_threshold][: max(1, top_n)]
                meta_out.update({
                    "used_path": "plugin",
                    "scores": [{"payload": p, "raw": float(raw), "prob": float(prob)} for p, prob, raw in ranked_pairs],
                    "penalty_applied": penalty,
                })
                if not out and ranked_pairs:
                    bp, bprob, _ = ranked_pairs[0]
                    out = [(bp, max(0.0, float(bprob) - penalty))]
                    meta_out["note"] = "kept_top1_from_plugin"
                if out:
                    meta_out["ranker_score"] = float(out[0][1])
                    meta_out["top_payload"] = out[0][0]
                    return out, meta_out
            except Exception as e:
                log.exception("Plugin scoring failed, falling back: %s", e)

        # 3) Generic pointwise/probabilistic model path (legacy)
        if self.model is not None:
            X_vec: Optional[List[float]] = None
            if self.pipeline is not None:
                try:
                    X = self.pipeline.transform([feats])  # type: ignore
                    if np is not None:
                        X_vec = np.asarray(X).ravel().tolist()
                    else:
                        try:
                            X_vec = list(X.toarray().ravel())  # type: ignore
                        except Exception:
                            X_vec = list(X[0])  # type: ignore
                except Exception as e:
                    log.exception("Pipeline.transform failed: %s", e)
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

                    best_penalized = max((max(0.0, float(prob) - penalty) for (_p, prob, _r) in ranked_pairs), default=0.0)
                    eff_threshold = min(eff_threshold, max(0.05, best_penalized - 1e-3))
                    meta_out["applied_threshold"] = eff_threshold

                    penalized = [(p, max(0.0, float(prob) - penalty), raw) for p, prob, raw in ranked_pairs]
                    out = [(p, s) for (p, s, _raw) in penalized if s >= eff_threshold][: max(1, top_n)]
                    meta_out.update({
                        "used_path": "generic_pairwise",
                        "scores": [{"payload": p, "raw": float(raw), "prob": float(prob)} for p, prob, raw in ranked_pairs],
                        "penalty_applied": penalty,
                    })
                    if not out and ranked_pairs:
                        bp, bprob, _ = ranked_pairs[0]
                        out = [(bp, max(0.0, float(bprob) - penalty))]
                        meta_out["note"] = "kept_top1_from_generic_pairwise"
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

                        best_penalized = max((max(0.0, float(prob) - penalty) for (_p, prob, _r) in ranked_pairs), default=0.0)
                        eff_threshold = min(eff_threshold, max(0.05, best_penalized - 1e-3))
                        meta_out["applied_threshold"] = eff_threshold

                        penalized = [(p, max(0.0, float(prob) - penalty), raw) for p, prob, raw in ranked_pairs]
                        out = [(p, s) for (p, s, _raw) in penalized if s >= eff_threshold][: max(1, top_n)]
                        meta_out["scores"] = [{"payload": p, "raw": float(raw), "prob": float(prob)} for p, prob, raw in ranked_pairs]
                        meta_out["penalty_applied"] = penalty
                        if not out and ranked_pairs:
                            bp, bprob, _ = ranked_pairs[0]
                            out = [(bp, max(0.0, float(bprob) - penalty))]
                            meta_out["note"] = "kept_top1_from_generic_single"
                        if out:
                            meta_out["ranker_score"] = float(out[0][1])
                            meta_out["top_payload"] = out[0][0]
                            return out, meta_out
            except Exception as e:
                log.exception("Generic model scoring failed, falling back: %s", e)

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
