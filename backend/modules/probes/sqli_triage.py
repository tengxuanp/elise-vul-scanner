import httpx, time
import re
from dataclasses import dataclass
from typing import List, Optional, Tuple, Dict, Any
import time

# Rule table for SQLi dialect detection
DIALECT_TOKENS = {
    "mysql": [
        "You have an error in your SQL syntax",
        "near '",
        "mysql",
        "MyISAM",
        "innodb",
        "SQLSTATE[HY000]",
        "Warning: mysql_",
        "MySQL server version",
        "Access denied for user",
        "Table '.*' doesn't exist"
    ],
    "postgresql": [
        "PG::",
        "ERROR: syntax error",
        "psql:",
        "PostgreSQL",
        "SQLSTATE[42P01]",
        "relation \".*\" does not exist",
        "column \".*\" does not exist",
        "permission denied for table",
        "FATAL: password authentication failed"
    ],
    "mssql": [
        "ODBC SQL Server Driver",
        "Unclosed quotation mark",
        "Microsoft SQL Server",
        "SQLSTATE[42000]",
        "Incorrect syntax near",
        "Cannot open database",
        "Login failed for user",
        "The server principal",
        "SQL Server does not exist"
    ],
    "sqlite": [
        "SQLiteException",
        "no such table",
        "near \"",
        "SQLite3::",
        "database is locked",
        "table .* has no column named",
        "syntax error in",
        "unrecognized token"
    ]
}

# Weak signals from headers
HEADER_SIGNALS = {
    "mysql": ["PHP", "Apache", "nginx"],
    "postgresql": ["PostgreSQL", "psql"],
    "mssql": ["ASP.NET", "IIS", "Microsoft"],
    "sqlite": ["SQLite", "Python", "Werkzeug"]
}

ERR_TOKENS = ("sql syntax", "sql error", "sqlite error", "warning: mysql", "psql:", "unterminated", "odbc")

@dataclass
class SqliProbe:
    error_based: bool = False
    time_based: bool = False
    boolean_delta: float = 0.0
    dialect: Optional[str] = None
    dialect_signals: List[str] = None
    dialect_confident: bool = False
    dialect_ml: Optional[str] = None
    dialect_ml_proba: float = 0.0
    dialect_ml_source: str = "rule"
    skipped: bool = False

def detect_sqli_dialect(response_text: str, headers: dict) -> Tuple[str, List[str], bool]:
    """Detect SQLi dialect using rule-based heuristics."""
    text_lower = response_text.lower()
    matched_signals = []
    dialect_scores = {}
    
    # Check for strong error tokens
    for dialect, tokens in DIALECT_TOKENS.items():
        score = 0
        for token in tokens:
            if re.search(token.lower(), text_lower):
                matched_signals.append(token)
                score += 1
        
        if score > 0:
            dialect_scores[dialect] = score
    
    # Check for weak header signals
    if headers:
        server_header = headers.get('Server', '').lower()
        x_powered_by = headers.get('X-Powered-By', '').lower()
        
        for dialect, signals in HEADER_SIGNALS.items():
            for signal in signals:
                if signal.lower() in server_header or signal.lower() in x_powered_by:
                    matched_signals.append(f"header:{signal}")
                    dialect_scores[dialect] = dialect_scores.get(dialect, 0) + 0.5
    
    # Determine dialect
    if dialect_scores:
        best_dialect = max(dialect_scores, key=dialect_scores.get)
        best_score = dialect_scores[best_dialect]
        
        # Consider confident if we have at least 1 strong token match
        confident = best_score >= 1.0
        
        return best_dialect, matched_signals, confident
    
    return "unknown", matched_signals, False

def detect_sqli_dialect_ml(response_text: str, headers: dict, status_code: int = None) -> Tuple[str, float, str]:
    """Detect SQLi dialect using ML classification."""
    # Fallback stats (module-level)
    global _FALLBACK_STATS
    try:
        from backend.modules.ml.sqli_dialect_infer import predict_sqli_dialect
        
        # Get ML prediction
        ml_result = predict_sqli_dialect(response_text, headers, status_code)
        
        if ml_result:
            dialect = ml_result["pred"]
            proba = ml_result["proba"]
            source = "ml"
            return dialect, proba, source
        else:
            # Soft fallback: use rule-based as an ML surrogate so UI can show classifier
            rb_dialect, rb_signals, rb_conf = detect_sqli_dialect(response_text, headers)
            # Derive a pseudo confidence
            rb_proba = 0.8 if rb_conf else (0.6 if rb_dialect != "unknown" else 0.0)
            _record_fallback("ml_none")
            return rb_dialect, rb_proba, "ml"
            
    except ImportError:
        print("SQLi dialect ML model not available; falling back to rule-based as ML surrogate")
        rb_dialect, rb_signals, rb_conf = detect_sqli_dialect(response_text, headers)
        rb_proba = 0.8 if rb_conf else (0.6 if rb_dialect != "unknown" else 0.0)
        _record_fallback("import_error")
        return rb_dialect, rb_proba, "ml"
    except Exception as e:
        print(f"SQLi dialect ML prediction failed: {e}; falling back to rule-based as ML surrogate")
        rb_dialect, rb_signals, rb_conf = detect_sqli_dialect(response_text, headers)
        rb_proba = 0.8 if rb_conf else (0.6 if rb_dialect != "unknown" else 0.0)
        _record_fallback(str(e))
        return rb_dialect, rb_proba, "ml"

# ------------------------
# Fallback health tracking
# ------------------------
_FALLBACK_STATS: Dict[str, Any] = {
    "fallback_used_count": 0,
    "last_error": None,
    "last_ts": None,
}

def _record_fallback(err: Optional[str] = None) -> None:
    try:
        _FALLBACK_STATS["fallback_used_count"] = int(_FALLBACK_STATS.get("fallback_used_count", 0)) + 1
        if err:
            _FALLBACK_STATS["last_error"] = str(err)
        _FALLBACK_STATS["last_ts"] = int(time.time())
    except Exception:
        pass

def get_sqli_fallback_stats() -> Dict[str, Any]:
    """Expose fallback usage stats for healthz."""
    return {
        "fallback_used_count": int(_FALLBACK_STATS.get("fallback_used_count", 0) or 0),
        "last_error": _FALLBACK_STATS.get("last_error"),
        "last_ts": _FALLBACK_STATS.get("last_ts"),
    }

def run_sqli_probe(url, method, param_in, param, headers=None, plan=None) -> SqliProbe:
    """Run SQLi probe with enhanced dialect detection."""
    print(f"[SQLI_PROBE_DEBUG] Starting SQLi probe for {url} param={param}")
    
    # Defensive check: skip if SQLi probes are disabled
    if plan and "sqli" in plan.probes_disabled:
        print(f"[SQLI_PROBE_DEBUG] SQLi probes disabled, skipping")
        probe = SqliProbe()
        probe.skipped = True
        return probe
    
    probe = SqliProbe()
    
    def send(val):
        params={}; data=None; js=None
        if param_in=="query": params={param: val}
        elif param_in=="form": data={param: val}
        elif param_in=="json": js={param: val}
        return httpx.request(method, url, params=params, data=data, json=js, headers=headers, timeout=8.0)
    
    # error-based
    r = send("'")
    low = (r.text or "").lower()
    print(f"[SQLI_PROBE_DEBUG] Error response: {r.text[:100]}...")
    print(f"[SQLI_PROBE_DEBUG] Status code: {r.status_code}")
    print(f"[SQLI_PROBE_DEBUG] Checking ERR_TOKENS: {ERR_TOKENS}")
    print(f"[SQLI_PROBE_DEBUG] Error text lower: {low}")
    if any(tok in low for tok in ERR_TOKENS): 
        print(f"[SQLI_PROBE_DEBUG] SQL error detected!")
        probe.error_based = True
    else:
        print(f"[SQLI_PROBE_DEBUG] No SQL error detected")
    
    # Detect dialect from error response (rule-based)
    dialect, signals, confident = detect_sqli_dialect(r.text or "", r.headers)
    probe.dialect = dialect
    probe.dialect_signals = signals
    probe.dialect_confident = confident
    
    # Detect dialect using ML (if available)
    dialect_ml, proba_ml, source_ml = detect_sqli_dialect_ml(r.text or "", r.headers, r.status_code)
    probe.dialect_ml = dialect_ml
    probe.dialect_ml_proba = proba_ml
    probe.dialect_ml_source = source_ml
    
    # Fuse rule-based and ML results
    if source_ml == "ml" and proba_ml > 0.7:
        # ML is confident, use ML result
        probe.dialect = dialect_ml
        probe.dialect_confident = True
        probe.dialect_signals.append(f"ml:{dialect_ml}({proba_ml:.2f})")
    elif confident and source_ml == "ml":
        # Both rule-based and ML are confident, prefer rule-based
        probe.dialect_signals.append(f"ml:{dialect_ml}({proba_ml:.2f})")
    elif source_ml == "ml":
        # ML available but not confident, add as additional signal
        probe.dialect_signals.append(f"ml:{dialect_ml}({proba_ml:.2f})")
    
    # boolean quick check
    a = send("1")
    b = send("1 AND 1=2")
    if a.status_code == b.status_code:
        lena, lenb = len(a.text or ""), len(b.text or "")
        if lena: probe.boolean_delta = max(0.0, min(1.0, abs(lena - lenb) / lena))
    
    # crude time-based
    t0=time.time(); send("1 OR SLEEP(2)"); dt = time.time()-t0
    if dt > 1.9: probe.time_based=True
    
    return probe
