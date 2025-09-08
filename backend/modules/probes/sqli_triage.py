import httpx, time
import re
from dataclasses import dataclass
from typing import List, Optional

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

ERR_TOKENS = ("sql syntax", "sqlite error", "warning: mysql", "psql:", "unterminated", "odbc")

@dataclass
class SqliProbe:
    error_based: bool = False
    time_based: bool = False
    boolean_delta: float = 0.0
    dialect: Optional[str] = None
    dialect_signals: List[str] = None
    dialect_confident: bool = False

def detect_sqli_dialect(response_text: str, headers: dict) -> tuple[str, List[str], bool]:
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

def run_sqli_probe(url, method, param_in, param, headers=None) -> SqliProbe:
    """Run SQLi probe with enhanced dialect detection."""
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
    if any(tok in low for tok in ERR_TOKENS): 
        probe.error_based = True
    
    # Detect dialect from error response
    dialect, signals, confident = detect_sqli_dialect(r.text or "", r.headers)
    probe.dialect = dialect
    probe.dialect_signals = signals
    probe.dialect_confident = confident
    
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