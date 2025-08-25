# backend/modules/family_router.py
from __future__ import annotations

"""
Lightweight, deterministic chooser for which payload *family* to attempt
against a target parameter.

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

Outputs:
choose_family(t) -> {
  "family": "xss" | "sqli" | "redirect" | "base",
  "confidence": float in [0,1],
  "reason": "R020 redirect param name (next, return, ...)",
  "rules_matched": [
     {"rule":"R020","family":"redirect","score":0.50,"detail":"param 'next' indicates redirect"},
     ...
  ]
}

Also available:
rank_families(t) -> list of the above objects for each family, sorted by score desc.
"""

import re
from typing import Dict, Any, List, Tuple
from urllib.parse import urlparse

# ------------------------------- heuristics ----------------------------------

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
    "callback", "url", "to", "continue", "dest", "destination"
}

REDIRECT_PATH_HINTS = {"redirect", "return"}

LOGIN_PATH_HINTS = {"login", "signin", "sign-in", "authenticate", "auth"}
ID_SUFFIX_RE = re.compile(r"(?:^|[_\-\.\[\{])id(?:$|[_\-\.\]\}])", re.I)

# ------------------------------ rule runner ----------------------------------

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
    s = _norm(s)
    return s.startswith("http://") or s.startswith("https://") or s.startswith("//")


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
    if method == "get" and (ctype in ("", "text/html", "application/xhtml+xml") or loc == "query"):
        out.append(("xss", "R003", 0.10, "GET + HTML/query increases XSS surface"))
    if ctype == "application/json":
        out.append(("xss", "R004", -0.05, "JSON response less likely to reflect as HTML"))

    return out


def _rules_sqli(t: Dict[str, Any]) -> List[RuleResult]:
    out: List[RuleResult] = []
    param = _norm(t.get("target_param"))
    parts = set(_path_parts(t.get("url") or ""))
    ctype = _norm((t.get("content_type") or "").split(";")[0])
    loc = _norm(t.get("in"))
    ctrl = t.get("control_value")

    if param in SQLI_PARAM_HINTS:
        out.append(("sqli", "R010", 0.35, f"param '{param}' is id-like"))

    if ID_SUFFIX_RE.search(param):
        out.append(("sqli", "R011", 0.20, f"param '{param}' ends/contains 'id'"))

    if parts & SQLI_PATH_HINTS:
        hit = next(iter(parts & SQLI_PATH_HINTS))
        out.append(("sqli", "R012", 0.15, f"path contains '{hit}'"))

    if _is_numeric(str(ctrl or "")):
        out.append(("sqli", "R013", 0.25, "control value is numeric (typical id)"))

    if ctype == "application/json" and loc != "query" and (param in SQLI_PARAM_HINTS or ID_SUFFIX_RE.search(param)):
        out.append(("sqli", "R014", 0.20, "JSON body id-like key"))

    # Login-ish endpoints: nudges toward SQLi (auth bypass)
    parts_lower = parts
    if parts_lower & LOGIN_PATH_HINTS:
        out.append(("sqli", "R015", 0.25, "login/auth path heuristic"))

    return out


def _rules_redirect(t: Dict[str, Any]) -> List[RuleResult]:
    out: List[RuleResult] = []
    param = _norm(t.get("target_param"))
    parts = set(_path_parts(t.get("url") or ""))
    ctrl = t.get("control_value")

    if param in REDIRECT_PARAM_HINTS:
        out.append(("redirect", "R020", 0.50, "redirect param name (next/return/url/...)"))

    if parts & REDIRECT_PATH_HINTS:
        hit = next(iter(parts & REDIRECT_PATH_HINTS))
        out.append(("redirect", "R021", 0.20, f"path contains '{hit}'"))

    if _looks_url(str(ctrl or "")):
        out.append(("redirect", "R022", 0.30, "control value looks like URL"))

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

    for fam, rule_id, score, detail in (
        _rules_xss(t) + _rules_sqli(t) + _rules_redirect(t) + _rules_base(t)
    ):
        scores[fam] += score
        matches.append({"rule": rule_id, "family": fam, "score": round(score, 3), "detail": detail})

    # Clamp negatives and sum floor at 0
    for fam in scores:
        if scores[fam] < 0:
            scores[fam] = max(0.0, scores[fam])

    return scores, matches


def _normalize_confidence(raw_score: float) -> float:
    """
    Map an unbounded positive score to [0,1].
    Our rule weights were designed so 0.65+ is a strong signal.
    """
    # Simple squashing: 1 - exp(-k*x)
    # Choose k so that ~1.0 at ~1.5 score
    import math
    k = 1.2
    return max(0.0, min(1.0, 1.0 - math.exp(-k * max(0.0, raw_score))))


# ------------------------------ public API -----------------------------------

def choose_family(t: Dict[str, Any]) -> Dict[str, Any]:
    """
    Return a single best family with reason & confidence.
    If no score exceeds a minimal threshold, fall back to 'base'.
    """
    scores, matches = _aggregate_rules(t)
    # Sort families by score
    ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
    top_family, top_score = ranked[0]

    # Minimal threshold to avoid over-eager classification
    threshold = 0.25
    family = top_family if top_score >= threshold else "base"
    confidence = _normalize_confidence(top_score if family != "base" else 0.05)

    # Pick a representative reason among matches of that family (max per-rule score)
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
