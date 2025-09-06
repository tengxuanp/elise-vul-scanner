# backend/modules/detectors.py
from __future__ import annotations

import re
import statistics
from html import escape, unescape
from typing import Dict, Any, Iterable, Optional, List, Tuple

# =============================================================================
# SQL ERROR SIGNALS
# =============================================================================

# Cross-DB error patterns (MySQL/MariaDB, Postgres, SQLite, Oracle, MSSQL, DB2, Informix, etc.)
SQL_ERRORS = [
    # MySQL / MariaDB
    r"SQL syntax.*MySQL",
    r"you have an error in your sql syntax",
    r"Warning.*mysql_",
    r"check the manual that corresponds to your MySQL server version",
    r"MariaDB server version for the right syntax",
    r"MySQL server version for the right syntax",
    r"mysqli?_error",
    # PostgreSQL
    r"PG::(?:SyntaxError|UndefinedTable|InvalidTextRepresentation|UndefinedFunction)",
    r"org\.postgresql\.util\.PSQLException",
    r"syntax error at or near",
    r"unterminated quoted string at or near",
    r"null value in column .* violates not-null constraint",
    r"invalid input syntax for (?:type|integer|uuid|numeric)",
    # SQLite
    r"SQLite3::SQLException",
    r"sqlite3\.OperationalError",
    r"SQLITE_ERROR",
    r"incomplete input",
    r"unrecognized token:",
    r"near\s+\"[^\"]+\"\s*:\s*syntax error",
    # Oracle
    r"ORA-\d{5}",
    r"quoted string not properly terminated",
    r"missing right parenthesis",
    r"ORA-00933: SQL command not properly ended",
    # Microsoft SQL Server / Sybase
    r"Unclosed quotation mark after the character string",
    r"\[Microsoft\]\[ODBC SQL Server Driver\]",
    r"ODBC Driver 1[1-9] for SQL Server",
    r"SQL Server Native Client",
    r"SQLSTATE\[\w+\]:.*\[Microsoft\].*SQL Server",
    r"Adaptive Server Enterprise",
    # DB2 / Informix / Other
    r"CLI Driver.*DB2",
    r"DB2 SQL error",
    r"Dynamic SQL Error",
    r"Ambiguous column name",
]
SQL_RE = re.compile("|".join(SQL_ERRORS), re.I | re.S)


def sql_error_signal(body_text: str) -> bool:
    """
    Return True if the response body contains a recognizable SQL error message.
    """
    if not body_text:
        return False
    return bool(SQL_RE.search(body_text))


# =============================================================================
# CONTENT KIND CLASSIFICATION (sniff + hint)
# =============================================================================

def _infer_content_kind(body_text: str, content_type_hint: Optional[str]) -> str:
    """
    Very small heuristic to tag content as 'html' | 'json' | 'xml' | 'text' | 'unknown'.
    We prefer content_type_hint if present; otherwise sniff body_text.
    """
    ct = (content_type_hint or "").lower().strip()
    if ct:
        if "html" in ct:
            return "html"
        if "json" in ct:
            return "json"
        if "xml" in ct:
            return "xml"
        if "text/plain" in ct or ct.startswith("text/"):
            return "text"

    # Lightweight sniff
    s = (body_text or "").lstrip()
    if s[:200].lower().startswith("<!doctype html") or "<html" in s[:2048].lower():
        return "html"
    if (s.startswith("{") and s.endswith("}")) or (s.startswith("[") and s.endswith("]")):
        return "json"
    if s.lstrip().startswith("<?xml"):
        return "xml"
    if s:
        return "text"
    return "unknown"


# =============================================================================
# XSS / REFLECTION SIGNALS
# =============================================================================

def _html_escaped_variants(s: str) -> Iterable[str]:
    """
    Generate a compact set of common HTML-escaped variants for the probe.
    """
    if not s:
        return []
    e1 = escape(s, quote=True)   # &, <, >, ", '
    e2 = escape(s, quote=False)  # &, <, >
    e3 = e1.replace("&#x27;", "&#39;")  # numeric apostrophe variant
    out = {e1, e2, e3}
    if "'" in s or '"' in s:
        out.add(s.replace('"', "&quot;").replace("'", "&#x27;"))
        out.add(s.replace('"', "&#34;").replace("'", "&#39;"))
    return out


def _contains_any(haystack: str, needles: Iterable[str]) -> bool:
    for n in needles:
        if n and n in haystack:
            return True
    return False


def reflection_signals(
    body_text: str,
    probe: str,
    content_type_hint: Optional[str] = None
) -> Dict[str, Any]:
    """
    Heuristics to detect reflection and rough context without executing anything.
    Returns booleans your pipeline can reason about, plus content_kind:
      - raw: exact probe appears verbatim
      - html_escaped: common escaped forms or decoded-HTML contains the probe
      - js_context: inside <script>...</script> or inline JS handler value
      - attr_context: inside an element attribute value (quoted or unquoted)
      - tag_text_context: appears in visible tag text (not trivially reliable)
      - content_kind: 'html' | 'json' | 'xml' | 'text' | 'unknown'

    NOTES:
    - If content_kind != 'html', JS/attribute contexts are unlikely to be exploitable;
      we still compute them (bad servers mislabel), but UI/scoring can downweight.
    """
    if not body_text or not probe:
        return {
            "raw": False,
            "html_escaped": False,
            "js_context": False,
            "attr_context": False,
            "tag_text_context": False,
            "content_kind": _infer_content_kind(body_text or "", content_type_hint),
        }

    content_kind = _infer_content_kind(body_text, content_type_hint)

    # Fast checks
    raw = probe in body_text

    # Escaped forms + decoded-HTML pass
    esc_variants = list(_html_escaped_variants(probe))
    html_esc_direct = _contains_any(body_text, esc_variants)
    try:
        decoded = unescape(body_text)
    except Exception:
        decoded = body_text
    html_esc_decoded = (probe in decoded)
    html_esc = bool(html_esc_direct or html_esc_decoded)

    # Prepare regex-safe probe
    p = re.escape(probe)

    # --- JS context ---
    js_in_script = bool(re.search(rf"<script[^>]*>.*?{p}.*?</script>", body_text, re.I | re.S))
    js_in_attr = bool(re.search(rf"on[a-zA-Z]+\s*=\s*(['\"]).*?{p}.*?\1", body_text, re.I | re.S))
    # also catch javascript: URLs
    js_href = bool(re.search(rf"\bhref\s*=\s*(['\"])javascript:[^\"']*{p}[^\"']*\1", body_text, re.I | re.S))
    js_context = js_in_script or js_in_attr or js_href

    # --- Attribute contexts (quoted / unquoted) ---
    attr_name = r"[a-zA-Z0-9:_-]+"
    attr_dq = re.compile(rf"\b{attr_name}\s*=\s*\"[^\"]*{p}[^\"]*\"", re.I | re.S)
    attr_sq = re.compile(rf"\b{attr_name}\s*=\s*'[^']*{p}[^']*'", re.I | re.S)
    attr_uq = re.compile(rf"\b{attr_name}\s*=\s*[^>\s\"']*{p}[^>\s\"']*", re.I)
    esc_union = "|".join(re.escape(v) for v in esc_variants if v)
    attr_dq_esc = re.compile(rf"\b{attr_name}\s*=\s*\"[^\"]*(?:{esc_union})[^\"]*\"", re.I | re.S) if esc_union else None
    attr_sq_esc = re.compile(rf"\b{attr_name}\s*=\s*'[^']*(?:{esc_union})[^']*'", re.I | re.S) if esc_union else None
    attr_uq_esc = re.compile(rf"\b{attr_name}\s*=\s*[^>\s\"']*(?:{esc_union})[^>\s\"']*", re.I) if esc_union else None

    attr_context = (
        bool(attr_dq.search(body_text)) or
        bool(attr_sq.search(body_text)) or
        bool(attr_uq.search(body_text)) or
        (attr_dq_esc.search(body_text) if attr_dq_esc else False) or
        (attr_sq_esc.search(body_text) if attr_sq_esc else False) or
        (attr_uq_esc.search(body_text) if attr_uq_esc else False)
    )

    # --- Tag text context (exclude script/style blocks) ---
    stripped = re.sub(r"<script[^>]*>.*?</script>", "", body_text, flags=re.I | re.S)
    stripped = re.sub(r"<style[^>]*>.*?</style>", "", stripped, flags=re.I | re.S)
    tag_text_context = bool(re.search(rf">[^<]*{p}[^<]*<", stripped, re.I))

    return {
        "raw": raw,
        "html_escaped": html_esc,
        "js_context": js_context,
        "attr_context": attr_context,
        "tag_text_context": tag_text_context,
        "content_kind": content_kind,
    }


# =============================================================================
# OPEN REDIRECT SIGNALS
# =============================================================================

_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")

def open_redirect_signal(location_value: Optional[str], origin_host: Optional[str]) -> bool:
    """
    Legacy check: Return True if Location header clearly points off-origin.
    Does NOT verify status code; prefer open_redirect_from_response for stricter checks.
    """
    if not location_value:
        return False
    v = location_value.strip()

    # Scheme-relative: //host/path
    if v.startswith("//"):
        return True  # clearly external host

    # Absolute URL: scheme://host/...
    if _SCHEME_RE.match(v):
        try:
            host_match = re.search(r"^[a-zA-Z][a-zA-Z0-9+.-]*://([^/:?#]+)", v)
            if host_match:
                loc_host = host_match.group(1).lower()
                if origin_host and loc_host != origin_host.lower():
                    return True
                if not origin_host:
                    return True
        except Exception:
            return True

    return False  # relative path → likely fine


def open_redirect_from_response(
    status_code: Optional[int],
    headers: Dict[str, str],
    origin_host: Optional[str]
) -> bool:
    """
    Stricter redirect oracle: only flag if HTTP status is 3xx AND Location is off-origin.
    """
    if not isinstance(status_code, int) or not (300 <= status_code <= 399):
        return False
    loc = headers.get("location") or headers.get("Location")
    return open_redirect_signal(loc, origin_host)


# =============================================================================
# TIME-DELAY (BLIND) SIGNALS
# =============================================================================

def time_delay_signal(
    baseline_ms: float,
    attempt_ms: float,
    min_delta_ms: float = 1500.0,
    jitter_ms: float = 150.0
) -> bool:
    """
    Return True if attempt latency exceeds baseline by a meaningful margin.
    - min_delta_ms: target delay used by payloads (e.g., SLEEP(2s) ~ 2000ms)
    - jitter_ms: cushion for network variance
    """
    if baseline_ms is None or attempt_ms is None:
        return False
    return (attempt_ms - baseline_ms) >= (min_delta_ms - jitter_ms)


def time_delay_signal_stats(
    baseline_samples_ms: List[float],
    attempt_samples_ms: List[float],
    min_delta_ms: float = 1500.0,
    zscore: float = 2.0
) -> Tuple[bool, Dict[str, float]]:
    """
    Statistical variant using multiple samples. True if:
      mean(attempt) - mean(base) >= min_delta_ms  AND
      (mean gap) >= zscore * pooled_std / sqrt(n_effective)
    Returns (decision, metrics)
    """
    b = [x for x in (baseline_samples_ms or []) if isinstance(x, (int, float))]
    a = [x for x in (attempt_samples_ms or []) if isinstance(x, (int, float))]
    if len(b) < 2 or len(a) < 2:
        # fallback to simple check on means
        mb = statistics.mean(b) if b else None
        ma = statistics.mean(a) if a else None
        return time_delay_signal(mb or 0, ma or 0, min_delta_ms), {
            "mean_base": mb or 0.0, "mean_attempt": ma or 0.0, "gap": (ma or 0.0) - (mb or 0.0),
            "std_base": float(statistics.pstdev(b)) if len(b) > 1 else 0.0,
            "std_attempt": float(statistics.pstdev(a)) if len(a) > 1 else 0.0,
        }

    mb = statistics.mean(b)
    ma = statistics.mean(a)
    sb = statistics.pstdev(b)  # population stdev (we typically sample same env)
    sa = statistics.pstdev(a)
    gap = ma - mb

    # Pooled std (conservative)
    pooled = (sb + sa) / 2.0
    # crude effective n (harmonic mean)
    n_eff = 2.0 / ((1.0 / len(b)) + (1.0 / len(a)))
    threshold = max(min_delta_ms, zscore * (pooled / max(n_eff, 1.0) ** 0.5))

    return (gap >= threshold), {
        "mean_base": float(mb), "mean_attempt": float(ma), "gap": float(gap),
        "std_base": float(sb), "std_attempt": float(sa), "pooled": float(pooled),
        "n_base": float(len(b)), "n_attempt": float(len(a)), "threshold": float(threshold),
    }


# =============================================================================
# BOOLEAN-PAIR (BLIND) SQLi SIGNALS
# =============================================================================

def boolean_divergence_signal(
    metrics_true: Dict[str, Any],
    metrics_false: Dict[str, Any],
    min_len_delta: int = 50,
    status_mismatch_ok: bool = True,
    require_hash_change: bool = False,
) -> bool:
    """
    Return True if a 'true' vs 'false' boolean pair produces a clear divergence.
    metrics_{true,false} can include:
      { "status": int, "len": int, "hash": str }
    """
    if not metrics_true or not metrics_false:
        return False

    # Length divergence
    len_t, len_f = metrics_true.get("len"), metrics_false.get("len")
    if isinstance(len_t, int) and isinstance(len_f, int):
        if abs(len_t - len_f) >= min_len_delta:
            return True

    # Status divergence
    if status_mismatch_ok:
        st_t, st_f = metrics_true.get("status"), metrics_false.get("status")
        if isinstance(st_t, int) and isinstance(st_f, int) and st_t != st_f:
            return True

    # Hash divergence (optional)
    if require_hash_change:
        h_t, h_f = metrics_true.get("hash"), metrics_false.get("hash")
        if h_t and h_f and h_t != h_f:
            return True

    return False


def boolean_divergence_signal_stats(
    true_samples: List[Dict[str, Any]],
    false_samples: List[Dict[str, Any]],
    min_len_delta: int = 50,
    require_hash_change: bool = False
) -> Tuple[bool, Dict[str, Any]]:
    """
    Multi-sample variant. Aggregates status and len; considers hash diversity if required.
    Returns (decision, diagnostics).
    """
    if not true_samples or not false_samples:
        return False, {"reason": "insufficient_samples"}

    def agg(samples: List[Dict[str, Any]]) -> Dict[str, Any]:
        lens = [s.get("len") for s in samples if isinstance(s.get("len"), int)]
        stats_ = [s.get("status") for s in samples if isinstance(s.get("status"), int)]
        hashes = [s.get("hash") for s in samples if isinstance(s.get("hash"), str)]
        return {
            "len_mean": float(statistics.mean(lens)) if lens else None,
            "len_min": min(lens) if lens else None,
            "len_max": max(lens) if lens else None,
            "status_mode": max(set(stats_), key=stats_.count) if stats_ else None,
            "hash_unique": len(set(hashes)) if hashes else 0,
        }

    ta, fa = agg(true_samples), agg(false_samples)
    decision = False

    if ta["len_mean"] is not None and fa["len_mean"] is not None:
        if abs(ta["len_mean"] - fa["len_mean"]) >= min_len_delta:
            decision = True

    if not decision and ta["status_mode"] is not None and fa["status_mode"] is not None:
        if ta["status_mode"] != fa["status_mode"]:
            decision = True

    if require_hash_change and not decision:
        # if both sides have internal hash variance and the sets don't fully overlap, signal
        t_hashes = set([s.get("hash") for s in true_samples if isinstance(s.get("hash"), str)])
        f_hashes = set([s.get("hash") for s in false_samples if isinstance(s.get("hash"), str)])
        if t_hashes and f_hashes and not t_hashes.intersection(f_hashes):
            decision = True

    return decision, {"true": ta, "false": fa}


# =============================================================================
# RESPONSE FINGERPRINT (utility for callers)
# =============================================================================

def response_fingerprint(status: Optional[int], body: Optional[str]) -> Dict[str, Any]:
    """
    Tiny helper to compute a fingerprint for boolean/time oracles.
    Callers can add their own hash to this dict.
    """
    body = body or ""
    return {
        "status": status if isinstance(status, int) else None,
        "len": len(body),
    }


# =============================================================================
# SCORING
# =============================================================================

def score(findings: Dict[str, Any], status_delta: int, len_delta: int, ms_delta: float) -> float:
    """
    Coarse confidence score in [0,1].

    Inputs:
      findings: {
        "reflection": {
            "raw": bool,
            "html_escaped": bool,
            "js_context": bool,
            "attr_context": bool,
            "tag_text_context": bool,
            "content_kind": "html|json|xml|text|unknown"
        },
        "sql_error": bool,
        "open_redirect": bool,
        "boolean_sqli": bool,   # set by your boolean-pair oracle
        "time_sqli": bool,      # set by your time-delay oracle
        "hash_changed": bool,   # whether response hash != baseline
        "repeat_consistent": bool,  # repeated attempts consistent (less noise)
      }
      status_delta: int
      len_delta: int
      ms_delta: float

    Weighting philosophy:
      - JS-context reflection is highest among XSS signals.
      - SQLi oracles (boolean/time) and SQL error strings are strong.
      - Open redirect is medium-high (depends on app context).
      - Deltas and hash changes nudge confidence; repeat consistency bumps slightly.
      - Reflection in non-HTML content is downweighted implicitly by callers (not here).
    """
    s = 0.0
    refl = findings.get("reflection", {}) or {}

    # Reflection: strongest single context
    refl_strengths = [
        (0.75, bool(refl.get("js_context"))),          # Inside <script>/inline JS
        (0.45, bool(refl.get("raw"))),                 # Raw reflection
        (0.25, bool(refl.get("html_escaped"))),        # Escaped reflection (usually safe)
        (0.18, bool(refl.get("attr_context"))),        # Attribute context (depends on quoting)
        (0.12, bool(refl.get("tag_text_context"))),    # Visible text only (weak)
    ]
    s += max((w for w, hit in refl_strengths if hit), default=0.0)

    # SQLi oracles (blind and error-based)
    if findings.get("boolean_sqli"):
        s += 0.55
    if findings.get("time_sqli"):
        s += 0.55
    if findings.get("sql_error"):
        s += 0.50

    # Open redirect
    if findings.get("open_redirect"):
        s += 0.55

    # Hash/delta nudges
    if findings.get("hash_changed"):
        s += 0.10
    if status_delta >= 100:
        s += 0.12
    if abs(len_delta) > 1500:
        s += 0.10
    if ms_delta > 1500:
        s += 0.10
    if findings.get("repeat_consistent"):
        s += 0.05

    return min(s, 1.0)
