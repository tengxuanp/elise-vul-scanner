"""
SQLi Dialect Inference Rules

Rule-based dialect detection from error text and response headers.
"""

from typing import Tuple, List, Dict, Optional

# Database-specific error tokens
TOKENS = {
    "mysql": [
        "you have an error in your sql syntax",
        "mysql server version",
        "mariadb", 
        "near '", 
        "at line",
        "warning: mysql",
        "mysql_fetch_array",
        "mysql_num_rows"
    ],
    "postgres": [
        "syntax error at or near",
        "psqlexception", 
        "org.postgresql", 
        "postgresql",
        "postgresql error",
        "pg_",
        "postgresql server"
    ],
    "mssql": [
        "unclosed quotation mark after the character string",
        "incorrect syntax near", 
        "odbc sql server", 
        "microsoft ole db provider for sql server",
        "sql server",
        "microsoft sql server",
        "sqlcmd",
        "sql server error"
    ],
    "sqlite": [
        "sqlite_error", 
        "sqlite3::", 
        "no such column", 
        "near \"\" : syntax error", 
        "sqlite",
        "sqlite3",
        "sqlite database"
    ],
}

def infer_sqli_dialect_from_text(text: str, headers: Dict[str, str]) -> Tuple[Optional[str], List[str], bool]:
    """
    Infer SQL database dialect from error text and headers.
    
    Args:
        text: Response text content
        headers: Response headers dictionary
        
    Returns:
        Tuple of (dialect, signals, confident)
        - dialect: Detected dialect ("mysql", "postgres", "mssql", "sqlite", or None)
        - signals: List of matched signals/tokens
        - confident: Whether the detection is confident (>= 2 token matches)
    """
    t = (text or "").lower()
    signals: List[str] = []
    best = None
    best_hits = 0
    
    # Check for database-specific tokens in error text
    for dialect, toks in TOKENS.items():
        hits = [tok for tok in toks if tok in t]
        if len(hits) > best_hits:
            best = dialect
            best_hits = len(hits)
            signals = hits
    
    # Weak header hints (rarely decisive)
    h = {k.lower(): v.lower() for k, v in (headers or {}).items()}
    if h.get("x-powered-by", "").find("asp.net") >= 0 and best in (None, "mssql"):
        best = best or "mssql"
        signals = signals + ["hdr:x-powered-by=asp.net"]
    
    # Check for server header hints
    server_header = h.get("server", "")
    if "mysql" in server_header and best in (None, "mysql"):
        best = best or "mysql"
        signals = signals + ["hdr:server=mysql"]
    elif "postgresql" in server_header and best in (None, "postgres"):
        best = best or "postgres"
        signals = signals + ["hdr:server=postgresql"]
    elif "microsoft" in server_header and best in (None, "mssql"):
        best = best or "mssql"
        signals = signals + ["hdr:server=microsoft"]
    
    # Confidence threshold: need at least 2 token matches for confidence
    confident = best_hits >= 2
    
    return best, signals, confident

def get_dialect_confidence_score(text: str, headers: Dict[str, str]) -> float:
    """
    Get confidence score for dialect detection.
    
    Args:
        text: Response text content
        headers: Response headers dictionary
        
    Returns:
        Confidence score between 0.0 and 1.0
    """
    dialect, signals, confident = infer_sqli_dialect_from_text(text, headers)
    
    if not dialect:
        return 0.0
    
    # Base score from token matches
    base_score = min(len(signals) / 3.0, 1.0)  # Normalize to 0-1
    
    # Bonus for confidence
    if confident:
        base_score = min(base_score + 0.3, 1.0)
    
    return base_score
