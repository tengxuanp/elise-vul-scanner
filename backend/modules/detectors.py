# backend/modules/detectors.py
from __future__ import annotations
import re
from html import escape, unescape
from typing import Dict, Any, Iterable, Optional

# =============================================================================
# SQL ERROR SIGNALS
# =============================================================================

# Broader cross-DB error patterns (MySQL/MariaDB, Postgres, SQLite, Oracle, MSSQL, DB2, Informix, etc.)
SQL_ERRORS = [
    # MySQL / MariaDB
    r"SQL syntax.*MySQL",
    r"you have an error in your sql syntax",
    r"Warning.*mysql_",
    r"check the manual that corresponds to your MySQL server version",
    r"MariaDB server version for the right syntax",
    # PostgreSQL
    r"PG::(?:SyntaxError|UndefinedTable|InvalidTextRepresentation)",
    r"org\.postgresql\.util\.PSQLException",
    r"syntax error at or near",
    r"unterminated quoted string at or near",
    # SQLite
    r"SQLite3::SQLException",
    r"sqlite3\.OperationalError",
    r"SQLITE_ERROR",               # classic SQLite error token (e.g., "SQLITE_ERROR: incomplete input")
    r"incomplete input",           # common SQLite parser message
    r"unrecognized token:",
    r"near\s+\"[^\"]+\"\s*:\s*syntax error",
    # Oracle
    r"ORA-\d{5}",
    r"quoted string not properly terminated",
    r"missing right parenthesis",
    # Microsoft SQL Server / Sybase
    r"Unclosed quotation mark after the character string",
    r"\[Microsoft\]\[ODBC SQL Server Driver\]",
    r"SQL Server Native Client",
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
# XSS / REFLECTION SIGNALS
# =============================================================================

def _html_escaped_variants(s: str) -> Iterable[str]:
    """
    Generate a small set of common HTML-escaped variants for the probe.
    We keep the set compact to avoid performance issues.
    """
    if not s:
        return []
    e1 = escape(s, quote=True)   # &, <, >, ", '
    e2 = escape(s, quote=False)  # &, <, >
    # Numeric apostrophe variant (common)
    e3 = e1.replace("&#x27;", "&#39;")
    out = {e1, e2, e3}
    # If quotes are present, include quote-only escapes
    if "'" in s or '"' in s:
        out.add(s.replace('"', "&quot;").replace("'", "&#x27;"))
        out.add(s.replace('"', "&#34;").replace("'", "&#39;"))
    return out


def _contains_any(haystack: str, needles: Iterable[str]) -> bool:
    for n in needles:
        if n and n in haystack:
            return True
    return False


def reflection_signals(body_text: str, probe: str) -> Dict[str, bool]:
    """
    Heuristics to detect reflection and rough context without executing anything.
    Returns booleans your pipeline can reason about:
      - raw: exact probe appears verbatim
      - html_escaped: common escaped forms or decoded-HTML contains the probe
      - js_context: inside <script>...</script> or inline JS handler value
      - attr_context: inside an element attribute value (quoted or unquoted)
      - tag_text_context: appears in visible tag text (not trivially reliable)

    Notes:
    - We also look for the probe in html-unescaped(body_text) to catch cases
      where the server encoded characters; this complements explicit variants.
    - Regexes are intentionally simple/cheap; this is a detector, not a parser.
    """
    if not body_text or not probe:
        return {
            "raw": False,
            "html_escaped": False,
            "js_context": False,
            "attr_context": False,
            "tag_text_context": False,
        }

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
    # 1) Inside <script> ... PROBE ... </script>
    js_in_script = bool(re.search(rf"<script[^>]*>.*?{p}.*?</script>", body_text, re.I | re.S))
    # 2) Inside inline event handlers: onX="...PROBE..." or onX='...PROBE...'
    js_in_attr = bool(re.search(rf"on[a-zA-Z]+\s*=\s*(['\"]).*?{p}.*?\1", body_text, re.I | re.S))
    js_context = js_in_script or js_in_attr

    # --- Attribute contexts (quoted / unquoted) ---
    # Allow common attribute names, but keep a generic fallback.
    attr_name = r"[a-zA-Z0-9:_-]+"
    attr_dq = re.compile(rf"\b{attr_name}\s*=\s*\"[^\"]*{p}[^\"]*\"", re.I | re.S)
    attr_sq = re.compile(rf"\b{attr_name}\s*=\s*'[^']*{p}[^']*'", re.I | re.S)
    attr_uq = re.compile(rf"\b{attr_name}\s*=\s*[^>\s\"']*{p}[^>\s\"']*", re.I)
    # Escaped-in-attribute second pass
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
    }


# =============================================================================
# OPEN REDIRECT SIGNAL
# =============================================================================

_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")

def open_redirect_signal(location_value: Optional[str], origin_host: Optional[str]) -> bool:
    """
    Return True if Location header clearly points off-origin (scheme-relative
    or absolute URL with a different host). Assumes you DID NOT follow redirects.

    Examples considered open:
      - Location: //evil.com/path
      - Location: https://evil.com/x
    Examples considered safe:
      - Location: /relative/path
      - Location: https://same-origin.tld/somewhere (same host)
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
            # Lazy host extraction to avoid importing urlparse here
            # Accept forms like "https://host:port/..."
            host_match = re.search(r"^[a-zA-Z][a-zA-Z0-9+.-]*://([^/:?#]+)", v)
            if host_match:
                loc_host = host_match.group(1).lower()
                if origin_host and loc_host != origin_host.lower():
                    return True
                # If origin_host unknown, still consider absolute URL suspicious
                if not origin_host:
                    return True
        except Exception:
            # Conservative: treat absolute-URL Location as potentially open
            return True

    # Relative path → likely fine
    return False


# =============================================================================
# TIME-DELAY (BLIND) SIGNAL
# =============================================================================

def time_delay_signal(baseline_ms: float, attempt_ms: float, min_delta_ms: float = 1500.0, jitter_ms: float = 150.0) -> bool:
    """
    Return True if attempt latency exceeds baseline by a meaningful margin.
    - min_delta_ms: target delay used by payloads (e.g., SLEEP(2s) ~ 2000ms)
    - jitter_ms: cushion for network variance
    """
    if baseline_ms is None or attempt_ms is None:
        return False
    return (attempt_ms - baseline_ms) >= (min_delta_ms - jitter_ms)


# =============================================================================
# BOOLEAN-PAIR (BLIND) SQLi SIGNAL
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
            "tag_text_context": bool
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
    """
    s = 0.0
    refl = findings.get("reflection", {}) or {}

    # Reflection: pick the strongest single context (do not sum to avoid double-counting)
    refl_strengths = [
        (0.75, bool(refl.get("js_context"))),          # Inside JS → dangerous
        (0.45, bool(refl.get("raw"))),                 # Raw reflection
        (0.25, bool(refl.get("html_escaped"))),        # Escaped reflection
        (0.18, bool(refl.get("attr_context"))),        # Attribute context (may or may not be exploitable)
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

    # Clamp
    if s > 1.0:
        s = 1.0
    return s
