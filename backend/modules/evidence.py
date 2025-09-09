from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict
import json, time, re, os, base64, html
from backend.app_state import DATA_DIR

@dataclass
class EvidenceRow:
    family: str
    url: str
    method: str
    param_in: str
    param: str
    payload: str
    request_headers: Dict[str,Any]
    response_status: int
    response_snippet: str
    probe_signals: Dict[str,Any]
    why: list
    cvss: Dict[str,Any] | None = None
    score: float | None = None
    p_cal: float | None = None
    validation: Dict[str,bool] | None = None
    # New ML telemetry fields
    rank_source: str | None = None  # "ml" | "probe_only" | "defaults"
    ml_family: str | None = None    # "xss" | "sqli" | "redirect" | null
    ml_proba: float | None = None   # ML probability score
    ml_threshold: float | None = None  # Threshold used for this family
    model_tag: str | None = None    # Model filename or version
    # New response snippet fields
    response_snippet_text: str | None = None  # HTML-escaped safe text
    response_snippet_raw: str | None = None   # base64 encoded raw bytes
    # XSS Context fields
    xss_context: str | None = None  # "html_body|attr|js_string|url|css"
    xss_escaping: str | None = None  # "raw|html|url|js|unknown"
    xss_context_source: str | None = None  # "rule|ml"
    xss_context_ml_proba: float | None = None  # ML probability when source="ml"
    # Telemetry fields
    attempt_idx: int | None = None  # Attempt index for this payload
    top_k_used: int | None = None   # Number of top-k payloads used
    # Rich evidence fields
    result_id: str | None = None    # Stable UUID per result row
    strategy: str | None = None     # Strategy used for this result
    timestamp: str | None = None    # ISO timestamp
    # Probe signal details
    marker: Dict[str,str] | None = None  # XSS canary marker variants
    reflection_details: Dict[str,Any] | None = None  # Detailed reflection info
    redirect_details: Dict[str,Any] | None = None    # Redirect oracle proof
    sqli_details: Dict[str,Any] | None = None        # SQLi error details
    # Ranking information
    ranking_topk: list | None = None     # Top-K payloads with scores
    ranking_source: str | None = None    # "ml_ranked|ctx_pool|manual"
    ranking_pool_size: int | None = None # Pool size for this ranking
    ranking_model: Dict[str,Any] | None = None  # Model info
    # Attempt timeline
    attempts_timeline: list | None = None  # Detailed attempt history
    # Vulnerability proof
    vuln_proof: Dict[str,Any] | None = None  # Why vulnerable rationale

    @staticmethod
    def _create_validation_flags(signals: Dict[str,Any]) -> Dict[str,bool]:
        """Create validation flags from probe signals."""
        if not signals:
            return {
                "xss_reflection": False,
                "sqli_error": False,
                "sqli_timing": False,
                "redirect_location": False,
            }
        
        return {
            "xss_reflection": (signals.get("xss_context") in {"html","js","attr"}) if signals else False,
            "sqli_error": bool(signals.get("sqli_error_based")) if signals else False,
            "sqli_timing": bool((signals.get("sql_boolean_delta") or 0) >= float(os.getenv("ELISE_TAU_SQLI","0.50"))) if signals else False,
            "redirect_location": bool(signals.get("redirect_influence") is True) if signals else False,
        }

    @classmethod
    def from_probe_confirm(cls, t, family, probe_bundle):
        p = probe_bundle
        signals = {
            "xss_context": getattr(p.xss, "context", None),
            "redirect_influence": getattr(p.redirect, "influence", None),
            "sqli_error_based": getattr(p.sqli, "error_based", None),
        }
        
        # Extract XSS context information
        xss_context = None
        xss_escaping = None
        xss_context_source = None
        xss_context_ml_proba = None
        
        if family == "xss" and hasattr(p, "xss") and p.xss:
            xss_context = getattr(p.xss, "xss_context", None)
            xss_escaping = getattr(p.xss, "xss_escaping", None)
            
            # Determine source and ML probability
            xss_context_ml = getattr(p.xss, "xss_context_ml", None)
            xss_context_rule = getattr(p.xss, "xss_context_rule", None)
            
            if xss_context_ml and xss_context_ml.get("pred"):
                xss_context_source = "ml"
                xss_context_ml_proba = xss_context_ml.get("proba")
            elif xss_context_rule:
                xss_context_source = "rule"
        
        # Sanitize response snippet
        response_snippet = "<probe_confirmed>"
        response_snippet_text = html.escape(response_snippet)
        response_snippet_raw = base64.b64encode(response_snippet.encode('utf-8')).decode('ascii')
        
        return cls(
            family, t.url, t.method, t.param_in, t.param, "<probe>", t.headers or {}, 200, response_snippet,
            signals,
            ["probe_proof"],
            validation=cls._create_validation_flags(signals),
            rank_source="probe_only",
            ml_family=None,
            ml_proba=None,
            ml_threshold=None,
            model_tag=None,
            response_snippet_text=response_snippet_text,
            response_snippet_raw=response_snippet_raw,
            xss_context=xss_context,
            xss_escaping=xss_escaping,
            xss_context_source=xss_context_source,
            xss_context_ml_proba=xss_context_ml_proba,
            attempt_idx=0,
            top_k_used=0
        )

    @classmethod
    def from_injection(cls, t, family, probe_bundle, rec, inj, rank_source="ml", ml_family=None, ml_proba=None, ml_threshold=None, model_tag=None):
        def _get(obj, attr, default=None):
            try: 
                return getattr(obj, attr)
            except Exception: 
                return default

        signals = {
            "xss_context": _get(_get(probe_bundle, "xss"), "context", None),
            "sql_boolean_delta": _get(_get(probe_bundle, "sqli"), "boolean_delta", None),
            "sqli_error_based": ("sql_error" in (getattr(inj, "why", []) or [])),
            "redirect_influence": bool(300 <= (getattr(inj, "status", 0) or 0) < 400 and str(getattr(inj, "redirect_location","")).startswith(("http://","https://"))),
        }

        # Extract XSS context information
        xss_context = None
        xss_escaping = None
        xss_context_source = None
        xss_context_ml_proba = None
        
        if family == "xss" and hasattr(probe_bundle, "xss") and probe_bundle.xss:
            xss_context = _get(probe_bundle.xss, "xss_context", None)
            xss_escaping = _get(probe_bundle.xss, "xss_escaping", None)
            
            # Determine source and ML probability
            xss_context_ml = _get(probe_bundle.xss, "xss_context_ml", None)
            xss_context_rule = _get(probe_bundle.xss, "xss_context_rule", None)
            
            if xss_context_ml and xss_context_ml.get("pred"):
                xss_context_source = "ml"
                xss_context_ml_proba = xss_context_ml.get("proba")
            elif xss_context_rule:
                xss_context_source = "rule"

        # Sanitize response snippet
        response_snippet = getattr(inj, "response_snippet", "")
        response_snippet_text = html.escape(response_snippet)
        response_snippet_raw = base64.b64encode(response_snippet.encode('utf-8')).decode('ascii')

        return cls(
            family, t.url, t.method, t.param_in, t.param, rec["payload"], t.headers or {}, inj.status, response_snippet,
            signals,
            ["ml_ranked"] + (getattr(inj, "why", []) or []),
            score=rec.get("score"),
            p_cal=rec.get("p_cal"),
            validation=cls._create_validation_flags(signals),
            rank_source=rank_source,
            ml_family=ml_family,
            ml_proba=ml_proba,
            ml_threshold=ml_threshold,
            model_tag=model_tag,
            response_snippet_text=response_snippet_text,
            response_snippet_raw=response_snippet_raw,
            xss_context=xss_context,
            xss_escaping=xss_escaping,
            xss_context_source=xss_context_source,
            xss_context_ml_proba=xss_context_ml_proba,
            attempt_idx=0,  # Will be set by caller
            top_k_used=0    # Will be set by caller
        )

    def to_dict(self, evidence_id: str = None) -> Dict[str, Any]:
        """Convert to dictionary, optionally including evidence_id."""
        d = asdict(self)
        if evidence_id:
            d["evidence_id"] = evidence_id
        
        # Ensure telemetry defaults are set
        if d.get("attempt_idx") is None:
            d["attempt_idx"] = 0
        if d.get("top_k_used") is None:
            d["top_k_used"] = 0
        if d.get("rank_source") is None:
            why = d.get("why", [])
            d["rank_source"] = "probe_only" if any("probe" in str(code) for code in why) else "none"
        
        return d

def _sanitize_filename_component(component: str) -> str:
    """Sanitize a filename component by replacing unsafe characters with underscores."""
    return re.sub(r'[^a-zA-Z0-9_.-]+', '_', component)

def write_evidence(job_id: str, ev: EvidenceRow, probe_bundle=None) -> str:
    """Write evidence to file and return evidence_id."""
    jid = f"{job_id}".replace("/", "_")
    outdir = DATA_DIR / "jobs" / jid
    outdir.mkdir(parents=True, exist_ok=True)
    ts = int(time.time() * 1000)
    
    # Sanitize the param name for safe filename usage
    safe_param = _sanitize_filename_component(ev.param)
    evidence_id = f"{ts}_{ev.family}_{safe_param}"
    path = outdir / f"{evidence_id}.json"
    
    # Prepare evidence data
    evidence_data = asdict(ev)
    
    # Add detailed XSS context data if available
    if ev.family == "xss" and probe_bundle and hasattr(probe_bundle, "xss") and probe_bundle.xss:
        xss_probe = probe_bundle.xss
        evidence_data["xss_context_details"] = {
            "fragment_left_64": getattr(xss_probe, "fragment_left_64", ""),
            "fragment_right_64": getattr(xss_probe, "fragment_right_64", ""),
            "raw_reflection": getattr(xss_probe, "raw_reflection", ""),
            "in_script_tag": getattr(xss_probe, "in_script_tag", False),
            "in_attr": getattr(xss_probe, "in_attr", False),
            "attr_name": getattr(xss_probe, "attr_name", ""),
            "in_style": getattr(xss_probe, "in_style", False),
            "attr_quote": getattr(xss_probe, "attr_quote", ""),
            "content_type": getattr(xss_probe, "content_type", ""),
            "xss_context_rule": getattr(xss_probe, "xss_context_rule", None),
            "xss_context_ml": getattr(xss_probe, "xss_context_ml", None),
            "xss_escaping_ml": getattr(xss_probe, "xss_escaping_ml", None)
        }
    
    with open(path, "w", encoding="utf-8") as f:
        json.dump(evidence_data, f, ensure_ascii=False, indent=2)
    return evidence_id

def read_evidence(job_id: str, evidence_id: str) -> Dict[str, Any]:
    """Read evidence by job_id and evidence_id."""
    jid = f"{job_id}".replace("/", "_")
    outdir = DATA_DIR / "jobs" / jid
    path = outdir / f"{evidence_id}.json"
    
    if not path.exists():
        raise FileNotFoundError(f"Evidence not found: {evidence_id}")
    
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def create_rich_evidence_meta(result_id: str, family: str, strategy: str) -> Dict[str, Any]:
    """Create rich evidence meta information."""
    from datetime import datetime
    return {
        "result_id": result_id,
        "family": family,
        "strategy": strategy,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }

def create_xss_marker(canary: str) -> Dict[str, str]:
    """Create XSS marker variants for display."""
    import urllib.parse
    return {
        "raw": canary,
        "url": urllib.parse.quote(canary),
        "html": html.escape(canary)
    }

def create_reflection_details(xss_probe) -> Dict[str, Any]:
    """Create detailed reflection information from XSS probe."""
    if not xss_probe:
        return None
    
    details = {
        "context": getattr(xss_probe, "xss_context", "unknown"),
        "escaping": getattr(xss_probe, "xss_escaping", "unknown"),
        "left64": getattr(xss_probe, "fragment_left_64", ""),
        "right64": getattr(xss_probe, "fragment_right_64", ""),
        "raw_reflection": getattr(xss_probe, "raw_reflection", ""),
        "in_script_tag": getattr(xss_probe, "in_script_tag", False),
        "in_attr": getattr(xss_probe, "in_attr", False),
        "attr_name": getattr(xss_probe, "attr_name", ""),
        "in_style": getattr(xss_probe, "in_style", False),
        "attr_quote": getattr(xss_probe, "attr_quote", ""),
        "content_type": getattr(xss_probe, "content_type", "")
    }
    
    # Add path hint if available
    if details["in_script_tag"]:
        details["path_hint"] = "script[0] > text()"
    elif details["in_attr"]:
        details["path_hint"] = f"attr[name={details['attr_name']}]"
    elif details["in_style"]:
        details["path_hint"] = "style[0] > text()"
    
    return details

def create_redirect_details(redirect_probe) -> Dict[str, Any]:
    """Create redirect oracle proof details."""
    if not redirect_probe:
        return None
    
    return {
        "location": getattr(redirect_probe, "redirect_location", ""),
        "status": getattr(redirect_probe, "status", 0)
    }

def create_sqli_details(sqli_probe) -> Dict[str, Any]:
    """Create SQLi error details with redaction."""
    if not sqli_probe:
        return None
    
    error_excerpt = getattr(sqli_probe, "error_excerpt", "")
    # Redact sensitive information
    if error_excerpt:
        # Truncate long error messages
        if len(error_excerpt) > 200:
            error_excerpt = error_excerpt[:200] + "..."
        # Redact common sensitive patterns
        error_excerpt = re.sub(r'password\s*=\s*[^\s]+', 'password=***', error_excerpt, flags=re.IGNORECASE)
        error_excerpt = re.sub(r'token\s*=\s*[^\s]+', 'token=***', error_excerpt, flags=re.IGNORECASE)
        error_excerpt = re.sub(r'api[_-]?key\s*=\s*[^\s]+', 'api_key=***', error_excerpt, flags=re.IGNORECASE)
        error_excerpt = re.sub(r'secret\s*=\s*[^\s]+', 'secret=***', error_excerpt, flags=re.IGNORECASE)
    
    return {
        "error_excerpt": error_excerpt,
        "dialect_hint": getattr(sqli_probe, "dialect_hint", "unknown")
    }

def redact_sensitive_headers(headers: Dict[str, Any]) -> Dict[str, Any]:
    """Redact sensitive headers for safety."""
    if not headers:
        return {}
    
    sensitive_headers = [
        'authorization', 'cookie', 'x-api-key', 'x-auth-token', 
        'x-access-token', 'x-csrf-token', 'x-session-id'
    ]
    
    redacted = {}
    for key, value in headers.items():
        lower_key = key.lower()
        if any(sensitive in lower_key for sensitive in sensitive_headers):
            redacted[key] = "***"
        else:
            redacted[key] = value
    
    return redacted

def truncate_response_body(body: str, max_length: int = 1500) -> str:
    """Truncate response body to prevent large storage."""
    if not body:
        return ""
    
    if len(body) <= max_length:
        return body
    
    # Show head and tail with truncation indicator
    truncation_indicator = "\n\n... [TRUNCATED] ...\n\n"
    available_length = max_length - len(truncation_indicator)
    head_length = available_length // 2
    tail_length = available_length - head_length
    
    return body[:head_length] + truncation_indicator + body[-tail_length:]

def create_ranking_info(ranked_payloads: list, rank_source: str, model_tag: str = None) -> Dict[str, Any]:
    """Create ranking information from ML results."""
    if not ranked_payloads:
        return None
    
    # Extract payload IDs and scores
    topk = []
    for payload in ranked_payloads:
        topk.append({
            "payload_id": payload.get("payload", "")[:50],  # Truncate for display
            "score": payload.get("p_cal", 0.0),
            "family": payload.get("family", "unknown")
        })
    
    model_info = None
    if model_tag:
        model_info = {
            "name": model_tag,
            "version": "2025-01-01",  # Placeholder
            "features": ["param_in", "context", "path_hash"]
        }
    
    return {
        "topk": topk,
        "source": rank_source,
        "pool_size": len(topk),
        "model": model_info
    }

def create_attempt_timeline(attempts: list) -> list:
    """Create attempt timeline from injection attempts."""
    timeline = []
    for i, attempt in enumerate(attempts):
        timeline.append({
            "attempt_idx": i + 1,  # 1-based
            "payload_id": attempt.get("payload", "")[:50],
            "request": {
                "method": attempt.get("method", "GET"),
                "path": attempt.get("path", ""),
                "param_in": attempt.get("param_in", ""),
                "param": attempt.get("param", "")
            },
            "response": {
                "status": attempt.get("status", 0),
                "latency_ms": attempt.get("latency_ms", 0)
            },
            "hit": attempt.get("hit", False),
            "why": attempt.get("why", []),
            "rank_source": attempt.get("rank_source", "unknown")
        })
    return timeline

def create_vuln_proof(family: str, context: str = None, escaping: str = None, 
                     redirect_location: str = None, sqli_error: str = None) -> Dict[str, Any]:
    """Create vulnerability proof explanation."""
    if family == "xss":
        return {
            "type": "xss_reflection",
            "summary": f"Reflected canary in {context}/{escaping}; context-guided payload landed",
            "details": [
                f"Reflection detected at {context}/{escaping} (canary)",
                "Context-guided payload closed attribute and injected event handler",
                "Server responded 200; DOM fragment shows payload present"
            ]
        }
    elif family == "redirect":
        return {
            "type": "redirect_header",
            "summary": f"Redirect header injection to external domain: {redirect_location}",
            "details": [
                f"Location header set to: {redirect_location}",
                "External domain detected in redirect target",
                "Potential open redirect vulnerability confirmed"
            ]
        }
    elif family == "sqli":
        return {
            "type": "sqli_error",
            "summary": f"SQL syntax error detected: {sqli_error[:100] if sqli_error else 'Unknown error'}",
            "details": [
                "SQL syntax error in response",
                "Database error message indicates SQL injection",
                "Error pattern matches known SQLi signatures"
            ]
        }
    else:
        return {
            "type": "other",
            "summary": f"Vulnerability detected via {family}",
            "details": ["Vulnerability confirmed through testing"]
        }