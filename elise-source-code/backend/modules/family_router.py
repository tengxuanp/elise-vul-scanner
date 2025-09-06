# backend/modules/family_router.py
from __future__ import annotations
"""
Lightweight, deterministic chooser for which payload *family* to attempt
against a target parameter — with an optional ML classifier that outputs a
calibrated distribution over families for Stage-A routing.

Inputs (target dict) — best-effort (missing keys are tolerated):
{
  "url": "https://site/path?q=foo",
  "method": "GET" | "POST" | ...,
  "in": "query" | "form" | "json",
  "target_param": "q",
  "content_type": "application/json; charset=utf-8",
  "headers": {...} | None,
  "control_value": "123" | "" | None
}

Rule APIs (deterministic fallback kept for clarity/audits):
  choose_family(t) -> {family, confidence, reason, rules_matched, scores}
  rank_families(t) -> [ {family, raw_score, confidence, reason, rules_matched}, ... ]

ML API (preferred for Stage-A when a model exists):
  FamilyClassifier().predict_proba(t) -> {"sqli":0.6,"xss":0.3,"redirect":0.1,"base":0.01}

Decision helper for Stage-A→Stage-B:
  decide_family(t, min_prob=0.55, explore_topk=2) -> {
      "family_top": "redirect",
      "family_probs": {...},
      "threshold_passed": True/False,
      "families_to_try": ["redirect"] or ["redirect","xss"] when exploring,
      "decision_reason": "ml_argmax|rule_argmax|below_threshold_explore"
  }

Also exposes canonical curated payload pools used in training & fallback:
  payload_pool_for("sqli"|"xss"|"redirect", context=None) -> List[str]
    - `context` may include: {"content_type": "...", "injection_mode": "json|headers|path|..."}
      to apply light filtering; filtering will NEVER return an empty list (falls back to original).

Notes:
- Recognizes the alias "open_redirect" and normalizes it to "redirect".
- ENHANCED: Now integrates with enhanced ML system when available.
"""

from typing import Dict, Any, List, Tuple, Optional
from urllib.parse import urlparse
from pathlib import Path
import re
import math
import os
import logging

# ------------------------------- logging/debug --------------------------------

log = logging.getLogger(__name__)
_DEBUG = str(os.getenv("ELISE_ML_DEBUG", "")).lower() in ("1", "true", "yes")
log.setLevel(logging.DEBUG if _DEBUG else logging.INFO)

# Optional dependency for loading models
try:
    import joblib  # type: ignore
except Exception:
    joblib = None  # type: ignore

# Enhanced ML integration - DISABLED FOR CVSS-BASED FUZZER
# try:
#     from .ml.enhanced_inference import EnhancedInferenceEngine
#     _ENHANCED_ML_AVAILABLE = True
#     log.info("✅ Enhanced ML system available for family routing")
# except Exception as e:
_ENHANCED_ML_AVAILABLE = False
log.info("❌ Enhanced ML system disabled - using CVSS-based fuzzer")

# ============================ Canonical payload pools =========================

CANONICAL_PAYLOADS: Dict[str, List[str]] = {
    "sqli": [
        "' OR 1=1--",
        "' OR 'a'='a' -- ",
        "\" OR \"a\"=\"a\" -- ",
        "1 OR 1=1 -- ",
        ") OR (1=1) -- ",
        "' UNION SELECT NULL-- ",
        "'; WAITFOR DELAY '0:0:3'--",
        "1)); SELECT pg_sleep(3)--",
    ],
    "xss": [
        '"/><script>alert(1)</script>',
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "<a href=javascript:alert(1)>x</a>",
        "<details open ontoggle=alert(1)>",
    ],
    "redirect": [
        "https://example.org/",
        "//evil.tld",
        "https:%2F%2Fevil.tld",
        "/\\evil",
        "///evil.tld",
        "http://evil.com@allowed.com",
    ],
    # keep base empty (placeholder)
    "base": [],
}
# Alias so trainers can import a stable name
TRAINING_POOL: Dict[str, List[str]] = CANONICAL_PAYLOADS


def _filter_pool_by_context(pool: List[str], family: str, context: Optional[Dict[str, Any]]) -> List[str]:
    """
    Light filtering to avoid obviously-wrong payloads for a context.
    Non-destructive: if filtering would empty the pool, return the original pool.
    Mirrors the recommender’s filtering rules to keep Stage-A/B consistent.
    """
    if not pool or not isinstance(context, dict):
        return pool

    ct = str((context.get("content_type") or "")).lower()
    mode = str((context.get("injection_mode") or context.get("mode") or "")).lower()

    out = list(pool)
    try:
        if family == "xss":
            # For JSON body injection, avoid heavy tag payloads that break JSON prematurely
            if mode == "json":
                filtered = [p for p in out if "<script" not in p.lower() and "<svg" not in p.lower() and "<img" not in p.lower()]
                if filtered:
                    out = filtered
            # For headers mode, prefer javascript: or event attributes
            if mode == "headers":
                filtered = [p for p in out if ("javascript:" in p.lower()) or ("onerror=" in p.lower()) or ("onload=" in p.lower())]
                if filtered:
                    out = filtered
            # Pure JSON responses also de-emphasize tag-based payloads
            if "application/json" in ct:
                filtered = [p for p in out if ("javascript:" in p.lower()) or ("onerror=" in p.lower()) or ("onload=" in p.lower())] or out
                out = filtered

        elif family == "sqli":
            # Path injections: prefer short booleans over UNION
            if mode == "path":
                filtered = [p for p in out if "union select" not in p.lower()] or out
                out = filtered

        # redirect rarely needs filtering
    except Exception:
        return pool

    return out or pool


def payload_pool_for(family: str, context: Optional[Dict[str, Any]] = None) -> List[str]:
    """
    Return curated canonical payloads for a family (empty list if unknown).
    Optionally filter based on `context` (content_type / injection_mode).
    Never returns an empty list due to filtering.
    """
    fam = (family or "").lower().strip()
    if fam == "open_redirect":
        fam = "redirect"  # normalize alias

    base = list(CANONICAL_PAYLOADS.get(fam, []))
    if not base:
        return base
    filtered = _filter_pool_by_context(base, fam, context)
    if _DEBUG and context:
        log.debug(
            "payload_pool_for(%s) context=%s -> %d/%d candidates",
            fam,
            {k: context.get(k) for k in ("content_type", "injection_mode", "mode")},
            len(filtered),
            len(base),
        )
    return filtered


# ================================ Heuristics =================================

XSS_PARAM_HINTS = {
    "q", "query", "search", "s", "term", "keyword",
    "comment", "message", "msg", "content", "body", "desc", "description",
    "text", "title", "name", "nick", "username"
}
XSS_PATH_HINTS = {"search", "comment", "feedback", "review", "post", "message"}

SQLI_PARAM_HINTS = {
    "id", "uid", "pid", "gid", "cid",
    "user_id", "product_id", "item_id", "post_id", "article_id",
    "order_id", "invoice_id", "page", "page_id", "cat", "category_id"
}
SQLI_PATH_HINTS = {"product", "item", "article", "post", "order", "invoice", "detail"}

REDIRECT_PARAM_HINTS = {
    "next", "return", "return_to", "redirect", "redirect_uri",
    "callback", "url", "to", "continue", "dest", "destination", "goto"
}
REDIRECT_PATH_HINTS = {"redirect", "return", "callback", "oauth", "sso"}

LOGIN_PATH_HINTS = {"login", "signin", "sign-in", "authenticate", "auth"}
ID_SUFFIX_RE = re.compile(r"(?:^|[_\-\.\[\{])id(?:$|[_\-\.\]\}])", re.I)
URLISH_RE = re.compile(r"^(https?:)?//", re.I)

RuleResult = Tuple[str, str, float, str]  # (family, rule_id, score, detail)


def _norm(s: Any) -> str:
    return (s or "").strip().lower()


def _path_parts(url: str) -> List[str]:
    try:
        p = urlparse(url).path or ""
    except Exception:
        p = ""
    parts = [seg for seg in p.split("/") if seg]
    return [seg.lower() for seg in parts]


def _is_numeric(s: str) -> bool:
    return bool(re.fullmatch(r"\d+", _norm(s)))


def _looks_url(s: str) -> bool:
    return bool(URLISH_RE.match(_norm(s)))


def _is_htmlish(ct: str) -> bool:
    ct = _norm(ct.split(";")[0])
    return ct in ("", "text/html", "application/xhtml+xml")


def _rules_xss(t: Dict[str, Any]) -> List[RuleResult]:
    out: List[RuleResult] = []
    param = _norm(t.get("target_param"))
    method = _norm(t.get("method"))
    parts = set(_path_parts(t.get("url") or ""))
    ctype = _norm((t.get("content_type") or "").split(";")[0])
    loc = _norm(t.get("in"))

    if param in XSS_PARAM_HINTS:
        out.append(("xss", "R001", 0.35, f"param '{param}' suggests reflective surface"))

    if parts & XSS_PATH_HINTS:
        hit = next(iter(parts & XSS_PATH_HINTS))
        out.append(("xss", "R002", 0.25, f"path contains '{hit}'"))

    # Static HTML GETs are often reflective; JSON lowers XSS likelihood
    if method == "get" and (_is_htmlish(ctype) or loc == "query"):
        out.append(("xss", "R003", 0.10, "GET + HTML/query increases XSS surface"))
    if "json" in ctype:
        out.append(("xss", "R004", -0.06, "JSON response less likely to reflect as HTML"))

    # Attribute-like param names are slightly more XSS-y
    if any(k in param for k in ("href", "src", "title", "value")):
        out.append(("xss", "R005", 0.08, "attribute-like param name"))

    return out


def _rules_sqli(t: Dict[str, Any]) -> List[RuleResult]:
    out: List[RuleResult] = []
    param = _norm(t.get("target_param"))
    parts = set(_path_parts(t.get("url") or ""))
    ctype = _norm((t.get("content_type") or "").split(";")[0])
    loc = _norm(t.get("in"))
    ctrl = t.get("control_value")
    method = _norm(t.get("method"))

    if param in SQLI_PARAM_HINTS:
        out.append(("sqli", "R010", 0.35, f"param '{param}' is id-like"))

    if ID_SUFFIX_RE.search(param):
        out.append(("sqli", "R011", 0.20, f"param '{param}' ends/contains 'id'"))

    if parts & SQLI_PATH_HINTS:
        hit = next(iter(parts & SQLI_PATH_HINTS))
        out.append(("sqli", "R012", 0.15, f"path contains '{hit}'"))

    if _is_numeric(str(ctrl or "")):
        out.append(("sqli", "R013", 0.25, "control value is numeric (typical id)"))

    # JSON body id-like keys lean SQLi
    if ctype == "application/json" and loc != "query" and (param in SQLI_PARAM_HINTS or ID_SUFFIX_RE.search(param)):
        out.append(("sqli", "R014", 0.20, "JSON body id-like key"))

    # Login/admin/search paths slightly nudge SQLi due to auth/report queries
    if parts & LOGIN_PATH_HINTS:
        out.append(("sqli", "R015", 0.25, "login/auth path heuristic"))
    if any(k in parts for k in ("admin", "report")):
        out.append(("sqli", "R016", 0.10, "admin/report path heuristic"))

    # Non-GET writes usually back a DB operation
    if method in ("post", "put", "patch"):
        out.append(("sqli", "R017", 0.06, "non-GET write"))

    return out


def _rules_redirect(t: Dict[str, Any]) -> List[RuleResult]:
    out: List[RuleResult] = []
    param = _norm(t.get("target_param"))
    parts = set(_path_parts(t.get("url") or ""))
    ctrl = t.get("control_value")
    loc = _norm(t.get("in"))

    if param in REDIRECT_PARAM_HINTS:
        out.append(("redirect", "R020", 0.50, "redirect param name (next/return/url/...)"))

    if parts & REDIRECT_PATH_HINTS:
        hit = next(iter(parts & REDIRECT_PATH_HINTS))
        out.append(("redirect", "R021", 0.20, f"path contains '{hit}'"))

    if _looks_url(str(ctrl or "")):
        out.append(("redirect", "R022", 0.30, "control value looks like URL"))

    # Query-location redirect params tend to be wired into 302 flows
    if loc == "query":
        out.append(("redirect", "R023", 0.05, "query-param redirect pattern"))

    return out


def _rules_base(_: Dict[str, Any]) -> List[RuleResult]:
    # Default catch-all with tiny prior to avoid zero score ties
    return [("base", "R000", 0.01, "no strong hints")]


def _aggregate_rules(t: Dict[str, Any]) -> Tuple[Dict[str, float], List[Dict[str, Any]]]:
    """
    Run all rule sets and aggregate per-family scores.
    Returns:
      scores = {"xss": 0.6, "sqli": 0.4, "redirect": 0.1, "base": 0.01}
      matches = [{"rule":"R010","family":"sqli","score":0.35,"detail":"..."}...]
    """
    families = ("xss", "sqli", "redirect", "base")
    scores = {f: 0.0 for f in families}
    matches: List[Dict[str, Any]] = []

    for fam, rule_id, weight, detail in (
        _rules_xss(t) + _rules_sqli(t) + _rules_redirect(t) + _rules_base(t)
    ):
        scores[fam] += weight
        matches.append({"rule": rule_id, "family": fam, "score": round(weight, 3), "detail": detail})

    # Clamp negatives to zero
    for fam in scores:
        if scores[fam] < 0:
            scores[fam] = 0.0

    return scores, matches


def _normalize_confidence(raw_score: float) -> float:
    """
    Map an unbounded positive score to [0,1].
    Our rule weights were designed so ~0.65+ is a strong signal.
    """
    k = 1.2  # squashing factor: 1 - exp(-k*x)
    return max(0.0, min(1.0, 1.0 - math.exp(-k * max(0.0, raw_score))))


# =============================== Rule-based API ===============================

def choose_family(t: Dict[str, Any]) -> Dict[str, Any]:
    """
    Return a single best family with reason & confidence.
    If no score exceeds a minimal threshold, fall back to 'base'.
    """
    scores, matches = _aggregate_rules(t)
    ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
    top_family, top_score = ranked[0]

    threshold = 0.25  # minimal threshold to avoid over-eager classification
    family = top_family if top_score >= threshold else "base"
    confidence = _normalize_confidence(top_score if family != "base" else 0.05)

    fam_matches = [m for m in matches if m["family"] == family]
    reason = "no strong hints"
    if fam_matches:
        fam_matches_sorted = sorted(fam_matches, key=lambda m: m["score"], reverse=True)
        m0 = fam_matches_sorted[0]
        reason = f"{m0['rule']} {m0['detail']}"

    return {
        "family": family,
        "confidence": round(confidence, 3),
        "reason": reason,
        "rules_matched": matches,
        "scores": {k: round(v, 3) for k, v in scores.items()},
    }


def rank_families(t: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Return all families scored & normalized, sorted by score, each with reasons.
    Useful if you want to try top-2 families for a param.
    """
    scores, matches = _aggregate_rules(t)
    out: List[Dict[str, Any]] = []
    for fam, raw in sorted(scores.items(), key=lambda kv: kv[1], reverse=True):
        fam_matches = [m for m in matches if m["family"] == fam]
        fam_matches_sorted = sorted(fam_matches, key=lambda m: m["score"], reverse=True)
        reason = (f"{fam_matches_sorted[0]['rule']} {fam_matches_sorted[0]['detail']}"
                  if fam_matches_sorted else "no strong hints")
        out.append({
            "family": fam,
            "confidence": round(_normalize_confidence(raw), 3),
            "raw_score": round(raw, 3),
            "reason": reason,
            "rules_matched": fam_matches_sorted,
        })
    return out


# ================================ ML Stage-A =================================

MODEL_DIR = Path(__file__).resolve().parent / "ml"
FAMILY_MODEL = MODEL_DIR / "family_model.joblib"   # optional (LightGBM/XGB/Sklearn)
CALIBRATOR = MODEL_DIR / "family_platt.joblib"     # optional (per-class or isotonic)

class FamilyClassifier:
    """
    Optional multiclass family classifier with probability output.
    - ENHANCED: Now integrates with enhanced ML system when available
    - If enhanced ML is missing, falls back to legacy models
    - If model/calibrator are missing, falls back to normalized rule scores.
    - Features are cheap, payload-agnostic, and stable across versions.
    """

    def __init__(self) -> None:
        self.model = None
        self.cal = None
        self.enhanced_engine = None
        
        # Try enhanced ML first
        if _ENHANCED_ML_AVAILABLE:
            try:
                self.enhanced_engine = EnhancedInferenceEngine()
                log.info("✅ Enhanced ML engine loaded for family classification")
            except Exception as e:
                log.warning(f"⚠️ Failed to load enhanced ML engine: {e}")
                self.enhanced_engine = None
        
        # Fallback to legacy models
        if joblib is not None:
            try:
                if FAMILY_MODEL.exists():
                    self.model = joblib.load(FAMILY_MODEL)
            except Exception:
                self.model = None
            try:
                if CALIBRATOR.exists():
                    self.cal = joblib.load(CALIBRATOR)
            except Exception:
                self.cal = None

    # ---------- public ----------

    def predict_proba(self, t: Dict[str, Any]) -> Dict[str, float]:
        """
        Return calibrated P(family) over {'sqli','xss','redirect','base'}.
        Enhanced ML path: Uses EnhancedInferenceEngine for better accuracy
        Fallback to legacy ML model when enhanced ML is unavailable
        Fallback to rule normalization when all models are unavailable
        """
        fams = ["sqli", "xss", "redirect", "base"]

        # Enhanced ML path (preferred)
        if self.enhanced_engine is not None:
            try:
                # Extract endpoint and parameter info
                endpoint = {
                    "url": t.get("url", ""),
                    "method": t.get("method", "GET"),
                    "content_type": t.get("content_type", "")
                }
                
                param = {
                    "name": t.get("target_param", ""),
                    "value": t.get("control_value", ""),
                    "loc": t.get("in", "query")
                }
                
                # Get predictions for each family
                family_probs = {}
                for family in ["sqli", "xss", "redirect"]:
                    try:
                        result = self.enhanced_engine.predict_with_confidence(endpoint, param, family)
                        # Use calibrated probability if available, otherwise raw
                        prob = result.get("calibrated_probability", result.get("raw_probability", 0.0))
                        family_probs[family] = float(prob)
                    except Exception as e:
                        log.debug(f"Enhanced ML prediction failed for {family}: {e}")
                        family_probs[family] = 0.0
                
                # Add base family with minimal probability
                family_probs["base"] = 0.01
                
                # Normalize probabilities
                s = sum(family_probs.values()) or 1.0
                prob = {k: v / s for k, v in family_probs.items()}
                
                if _DEBUG:
                    log.debug(f"Enhanced ML family probs: {prob}")
                
                return prob
                
            except Exception as e:
                log.debug(f"Enhanced ML family classification failed: {e}, falling back to legacy")
                # fall through to legacy ML

        # Legacy ML path
        if self.model is not None:
            try:
                x = self._featurize_target(t)
                raw = self._predict_model([x])  # -> 4 probs or scores
                # Ensure 4-dim; if not, use a sane prior (XSS/SQLi/Redirect with tiny 'base')
                if not isinstance(raw, (list, tuple)) or len(raw) != 4:
                    raw = [1.0, 1.0, 1.0, 0.1]
                p = self._softmax(list(raw))
                # Optional per-class calibration
                if self.cal is not None:
                    try:
                        p = self.cal.transform([p])[0]  # type: ignore
                    except Exception:
                        pass
                prob = {f: float(p[i]) for i, f in enumerate(fams)}
                # ensure base floor & renormalize
                prob["base"] = max(prob.get("base", 0.0), 1e-3)
                s = sum(prob.values()) or 1.0
                return {k: v / s for k, v in prob.items()}
            except Exception:
                # fall through to rules
                pass

        # Fallback: normalize rule scores
        ranked = rank_families(t)
        rs = {r["family"]: float(r.get("raw_score", 0.0)) for r in ranked}
        rs["base"] = max(rs.get("base", 0.0), 1e-3)
        s = sum(max(0.0, v) for v in rs.values()) or 1.0
        return {k: max(0.0, v) / s for k, v in rs.items()}

    # ---------- internals ----------

    def _predict_model(self, X: List[List[float]]) -> List[float]:
        """
        Try common scikit/GBM interfaces to get class probabilities or scores.
        Expect 4 outputs ordered as [sqli, xss, redirect, base] if proba.
        """
        m = self.model
        if m is None:
            return []
        # predict_proba preferred
        if hasattr(m, "predict_proba"):
            proba = m.predict_proba(X)  # type: ignore
            # Shape may be (n_samples, n_classes)
            try:
                row = proba[0]  # type: ignore[index]
                return [float(v) for v in row]
            except Exception:
                pass
        # decision_function/logits
        if hasattr(m, "decision_function"):
            df = m.decision_function(X)  # type: ignore
            row = df[0] if isinstance(df, (list, tuple)) else df
            try:
                return [float(x) for x in row]  # type: ignore[call-overload]
            except Exception:
                try:
                    return [float(row)]  # type: ignore[arg-type]
                except Exception:
                    return []
        # fallback to predict → one-hot guess
        if hasattr(m, "predict"):
            y = m.predict(X)  # type: ignore
            row = y[0] if isinstance(y, (list, tuple)) else y
            out = [0.0, 0.0, 0.0, 0.0]
            idx = {"sqli": 0, "xss": 1, "redirect": 2, "base": 3}.get(str(row).lower(), 3)
            out[idx] = 1.0
            return out
        return []

    def _featurize_target(self, t: Dict[str, Any]) -> List[float]:
        """
        Cheap, payload-agnostic endpoint vector.
        Stable order; keep in sync with trainer.
        """
        method = (t.get("method") or "GET").upper()
        loc = (t.get("in") or "query").lower()
        ct = (t.get("content_type") or "").split(";")[0].lower()
        param = (t.get("target_param") or "").lower()
        url = t.get("url") or ""

        def bucket(s: str, m: int = 64) -> int:
            import hashlib
            return int(hashlib.sha1(s.encode("utf-8", "ignore")).hexdigest()[:8], 16) % m

        def depth(u: str) -> int:
            try:
                return sum(1 for seg in (urlparse(u).path or "").split("/") if seg)
            except Exception:
                return 0

        onehot_method = [1.0 if method == x else 0.0 for x in ("GET", "POST", "PUT", "DELETE")]
        onehot_loc = [1.0 if loc == x else 0.0 for x in ("query", "form", "json")]
        ct_hint = [
            1.0 if "json" in ct else 0.0,
            1.0 if "html" in ct else 0.0,
            1.0 if "x-www-form-urlencoded" in ct else 0.0,
        ]
        return onehot_method + onehot_loc + ct_hint + [float(depth(url)), float(bucket(param, 64))]

    @staticmethod
    def _softmax(xs: List[float]) -> List[float]:
        if not xs:
            return [0.25, 0.25, 0.25, 0.25]
        m = max(xs)
        exps = [math.exp(x - m) for x in xs]
        s = sum(exps) or 1.0
        return [x / s for x in exps]


# ========================== Stage-A Decision Helper ===========================

# Defaults (overridable via env)
def _env_float(name: str, default: float) -> float:
    try:
        v = os.getenv(name, "")
        return float(v) if v not in (None, "") else default
    except Exception:
        return default

def _env_int(name: str, default: int) -> int:
    try:
        v = os.getenv(name, "")
        return int(v) if v not in (None, "") else default
    except Exception:
        return default

def _env_bool(name: str, default: bool) -> bool:
    v = str(os.getenv(name, "")).strip().lower()
    if v in ("1", "true", "yes", "y", "on"):
        return True
    if v in ("0", "false", "no", "n", "off"):
        return False
    return default

DEFAULT_MIN_PROB = _env_float("ELISE_STAGEA_MIN_PROB", 0.55)   # arg-max family must exceed this to be authoritative
DEFAULT_EXPLORE_TOPK = _env_int("ELISE_STAGEA_EXPLORE_TOPK", 2)  # when below threshold, explore top-k families (budgeted)
DEFAULT_INCLUDE_BASE = _env_bool("ELISE_STAGEA_INCLUDE_BASE", False)  # typically we don't explore 'base'

_classifier_singleton: FamilyClassifier | None = None

def _clf() -> FamilyClassifier:
    global _classifier_singleton
    if _classifier_singleton is None:
        _classifier_singleton = FamilyClassifier()
    return _classifier_singleton

def decide_family(
    t: Dict[str, Any],
    min_prob: float = DEFAULT_MIN_PROB,
    explore_topk: int = DEFAULT_EXPLORE_TOPK,
    include_base: bool = DEFAULT_INCLUDE_BASE,
) -> Dict[str, Any]:
    """
    Authoritative Stage-A decision with thresholding and *explicit* exploration plan.
    This eliminates the mismatch where Stage-B was ranking the wrong family.
    """
    # 1) Get probabilities (ML if available, else rules)
    clf = _clf()
    probs = clf.predict_proba(t)

    # Defensive normalization
    fams = ["sqli", "xss", "redirect", "base"]
    probs = {f: float(max(0.0, probs.get(f, 0.0))) for f in fams}
    s = sum(probs.values()) or 1.0
    probs = {k: v / s for k, v in probs.items()}

    # 2) Arg-max + threshold
    ranked = sorted(((f, p) for f, p in probs.items()), key=lambda kv: kv[1], reverse=True)
    top_family, top_prob = ranked[0]
    threshold_passed = bool(top_prob >= float(min_prob))

    # 3) Exploration plan if below threshold
    if threshold_passed:
        families_to_try = [top_family]
        decision_reason = "ml_argmax" if clf.model is not None else "rule_argmax"
    else:
        families = [f for f, _ in ranked if include_base or f != "base"]
        families_to_try = families[: max(1, int(explore_topk))]
        decision_reason = "below_threshold_explore"

    if _DEBUG:
        log.debug(
            "decide_family: top=%s p=%.3f passed=%s plan=%s probs=%s",
            top_family,
            top_prob,
            threshold_passed,
            families_to_try,
            {k: round(v, 3) for k, v in probs.items()},
        )

    return {
        "family_top": top_family,
        "family_probs": probs,
        "threshold_passed": threshold_passed,
        "families_to_try": families_to_try,
        "decision_reason": decision_reason,
        "min_prob": float(min_prob),
    }


__all__ = [
    "payload_pool_for",
    "CANONICAL_PAYLOADS",
    "TRAINING_POOL",
    "choose_family",
    "rank_families",
    "FamilyClassifier",
    "decide_family",
    "DEFAULT_MIN_PROB",
    "DEFAULT_EXPLORE_TOPK",
    "DEFAULT_INCLUDE_BASE",
]
