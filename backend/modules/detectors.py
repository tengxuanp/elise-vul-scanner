# backend/modules/detectors.py
from __future__ import annotations
import re
from html import escape
from typing import Dict, Any

SQL_ERRORS = [
    r"SQL syntax.*MySQL", r"Warning.*mysql_", r"Unclosed quotation mark after the character string",
    r"quoted string not properly terminated", r"ORA-\d{5}", r"PG::SyntaxError", r"SQLite3::SQLException",
    r"you have an error in your sql syntax", r"unterminated quoted string", r"syntax error at or near",
]
SQL_RE = re.compile("|".join(SQL_ERRORS), re.I)

def reflection_signals(body_text: str, probe: str) -> Dict[str, bool]:
    if body_text is None:
        return {"raw": False, "html_escaped": False, "js_context": False}
    raw = probe in body_text
    esc = escape(probe) in body_text
    # crude JS-context hint: probe inside <script> or event handler attribute
    js = False
    if raw:
        # in <script>...</script> or on<event>="...PROBE..."
        js = bool(re.search(r"<script[^>]*>[^<]*" + re.escape(probe), body_text, re.I)) or \
             bool(re.search(r"on\w+\s*=\s*['\"][^'\"]*" + re.escape(probe), body_text, re.I))
    return {"raw": raw, "html_escaped": esc, "js_context": js}

def sql_error_signal(body_text: str) -> bool:
    if not body_text:
        return False
    return bool(SQL_RE.search(body_text))

def score(findings: Dict[str, Any], status_delta: int, len_delta: int, ms_delta: float) -> float:
    """
    Very simple heuristic: return 0..1 confidence.
    """
    s = 0.0
    refl = findings.get("reflection", {})
    if refl.get("js_context"): s += 0.6
    elif refl.get("raw"): s += 0.4
    elif refl.get("html_escaped"): s += 0.15
    if findings.get("sql_error"): s += 0.5
    # deltas
    if status_delta >= 100: s += 0.15
    if abs(len_delta) > 1500: s += 0.1
    if ms_delta > 1500: s += 0.1
    return min(1.0, s)
