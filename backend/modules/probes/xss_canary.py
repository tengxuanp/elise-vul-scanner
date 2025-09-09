import httpx
import html
import urllib.parse
import re
import json
import time
import os
from dataclasses import dataclass
from typing import List, Optional, Dict, Any
from pathlib import Path
from backend.app_state import DATA_DIR

CANARY = "EliseXSSCanary123"

@dataclass
class XssProbe:
    context: str = "none"  # none|html_body|attr|js_string|url|css|unknown
    escaping: str = "unknown"  # raw|html|url|js|unknown
    reflected: bool = False
    xss_context: Optional[str] = None
    xss_escaping: Optional[str] = None
    # New ML fields
    xss_context_rule: Optional[Dict[str, Any]] = None
    xss_context_ml: Optional[Dict[str, Any]] = None
    xss_escaping_ml: Optional[Dict[str, Any]] = None
    # Additional fields for evidence
    fragment_left_64: str = ""
    fragment_right_64: str = ""
    raw_reflection: str = ""
    in_script_tag: bool = False
    in_attr: bool = False
    attr_name: str = ""
    in_style: bool = False
    attr_quote: str = ""
    content_type: str = ""
    # Param information for UI display
    param_in: str = ""
    param: str = ""
    # Strategy enforcement
    skipped: bool = False

def detect_xss_context_with_confidence(text: str, canary_pos: int) -> Dict[str, Any]:
    """Detect XSS context using rule-based heuristics with confidence scoring."""
    if canary_pos == -1:
        return {"pred": "unknown", "conf": 0.0}
    
    # Get context window around the canary
    window_start = max(0, canary_pos - 50)
    window_end = min(len(text), canary_pos + len(CANARY) + 50)
    window = text[window_start:window_end]
    
    # Check for script tag context
    script_start = text.rfind('<script', 0, canary_pos)
    script_end = text.find('</script>', canary_pos)
    
    if script_start != -1 and script_end != -1 and script_start < canary_pos < script_end:
        # Inside script tag - check for string context
        script_content = text[script_start:script_end]
        canary_in_script = script_content.find(CANARY)
        
        # Look for quotes around the canary
        before_canary = script_content[max(0, canary_in_script - 10):canary_in_script]
        after_canary = script_content[canary_in_script + len(CANARY):canary_in_script + len(CANARY) + 10]
        
        if ('"' in before_canary and '"' in after_canary) or ("'" in before_canary and "'" in after_canary):
            return {"pred": "js_string", "conf": 0.95}  # High confidence
        else:
            return {"pred": "html_body", "conf": 0.85}  # High confidence
    
    # Check for CSS context
    style_start = text.rfind('<style', 0, canary_pos)
    style_end = text.find('</style>', canary_pos)
    if style_start != -1 and style_end != -1 and style_start < canary_pos < style_end:
        return {"pred": "css", "conf": 0.95}  # High confidence
    
    # Check for inline style attribute
    if 'style=' in window:
        return {"pred": "css", "conf": 0.90}  # High confidence
    
    # Check for URL context (href, src, action attributes)
    url_attrs = ['href=', 'src=', 'action=', 'formaction=']
    for attr in url_attrs:
        if attr in window:
            return {"pred": "url", "conf": 0.90}  # High confidence
    
    # Check for HTML attribute context
    if ('"' in window or "'" in window) and ('=' in window):
        return {"pred": "attr", "conf": 0.80}  # Medium-high confidence
    
    # Check for HTML body context
    if '<' in window and '>' in window:
        return {"pred": "html_body", "conf": 0.70}  # Medium confidence
    
    return {"pred": "unknown", "conf": 0.30}  # Low confidence

def detect_xss_context(text: str, canary_pos: int) -> str:
    """Legacy function for backward compatibility."""
    result = detect_xss_context_with_confidence(text, canary_pos)
    return result["pred"]

def detect_xss_escaping(text: str, canary_pos: int) -> str:
    """Detect XSS escaping using rule-based heuristics."""
    if canary_pos == -1:
        return "unknown"
    
    # Get the actual reflected canary
    canary_end = canary_pos + len(CANARY)
    reflected_canary = text[canary_pos:canary_end]
    
    # Check for raw reflection first
    if reflected_canary == CANARY:
        return "raw"
    
    # Check for HTML escaping
    html_escaped = html.escape(CANARY)
    if reflected_canary == html_escaped:
        return "html"
    
    # Check for URL encoding
    url_encoded = urllib.parse.quote(CANARY)
    if reflected_canary == url_encoded:
        return "url"
    
    # Check for JavaScript string escaping
    js_escaped = CANARY.replace('\\', '\\\\').replace('"', '\\"').replace("'", "\\'")
    if reflected_canary == js_escaped:
        return "js"
    
    return "unknown"

def capture_xss_reflection_data(job_id: str, url: str, method: str, param_in: str, param: str, 
                               text: str, canary_pos: int, headers: Dict[str, str] = None) -> None:
    """Capture XSS reflection data for ML training."""
    if canary_pos == -1:
        return
    
    # Extract context window
    window_start = max(0, canary_pos - 64)
    window_end = min(len(text), canary_pos + len(CANARY) + 64)
    fragment_left_64 = text[window_start:canary_pos]
    fragment_right_64 = text[canary_pos + len(CANARY):window_end]
    
    # Detect context features
    context_result = detect_xss_context_with_confidence(text, canary_pos)
    
    # Extract additional features
    in_script_tag = '<script' in text[max(0, canary_pos - 200):canary_pos]
    in_style = '<style' in text[max(0, canary_pos - 200):canary_pos] or 'style=' in text[max(0, canary_pos - 50):canary_pos + 50]
    
    # Detect attribute context
    in_attr = False
    attr_name = ""
    attr_quote = ""
    
    # Look for attribute patterns around the canary
    attr_window = text[max(0, canary_pos - 100):canary_pos + 100]
    attr_match = re.search(r'(\w+)=["\']([^"\']*' + re.escape(CANARY) + r'[^"\']*)["\']', attr_window)
    if attr_match:
        in_attr = True
        attr_name = attr_match.group(1)
        # Safely extract quote character
        start_pos = attr_match.start(2) - 1
        if start_pos >= 0 and start_pos < len(attr_match.group(0)):
            attr_quote = attr_match.group(0)[start_pos]
        else:
            attr_quote = ""
    
    # Get raw reflection
    raw_reflection = text[canary_pos:canary_pos + len(CANARY)]
    
    # Create event data
    event_data = {
        "timestamp": str(int(time.time() * 1000)),
        "job_id": job_id,
        "url": url,
        "method": method,
        "param_in": param_in,
        "param": param,
        "fragment_left_64": fragment_left_64,
        "fragment_right_64": fragment_right_64,
        "in_script_tag": in_script_tag,
        "in_attr": in_attr,
        "attr_name": attr_name,
        "in_style": in_style,
        "attr_quote": attr_quote,
        "content_type": headers.get("content-type", "") if headers else "",
        "raw_reflection": raw_reflection,
        "rule_context": context_result["pred"],
        "rule_escaping": detect_xss_escaping(text, canary_pos),
        "rule_conf": context_result["conf"]
    }
    
    # Write to NDJSON file
    job_dir = DATA_DIR / "jobs" / job_id
    job_dir.mkdir(parents=True, exist_ok=True)
    
    events_file = job_dir / "xss_context_events.ndjson"
    with open(events_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(event_data) + "\n")

def run_xss_probe(url: str, method: str, param_in: str, param: str, headers=None, job_id: str = None, plan=None, ctx_mode: str = "auto", meta: dict = None):
    """Run XSS probe with enhanced context and escaping detection."""
    # Check if XSS probes are disabled by the current plan
    if plan and "xss" in plan.probes_disabled:
        probe = XssProbe()
        probe.skipped = True
        return probe
    
    params = {}; data=None; js=None
    if param_in=="query": params={param: CANARY}
    elif param_in=="form": data={param: CANARY}
    elif param_in=="json": js={param: CANARY}
    
    r = httpx.request(method, url, params=params, data=data, json=js, headers=headers, timeout=8.0, follow_redirects=True)
    text = r.text or ""
    
    if CANARY in text:
        canary_pos = text.find(CANARY)
        
        # Capture data for ML training if job_id provided
        if job_id:
            capture_xss_reflection_data(job_id, url, method, param_in, param, text, canary_pos, headers)
        
        # Get rule-based predictions with confidence
        context_result = detect_xss_context_with_confidence(text, canary_pos)
        xss_escaping = detect_xss_escaping(text, canary_pos)
        
        # Implement proper context resolution logic according to patch
        RULE_CONF_GATE = float(os.getenv("ELISE_RULE_CONF_GATE", "0.85"))
        ML_OVERRIDE_GATE = float(os.getenv("ELISE_ML_OVERRIDE_GATE", "0.80"))
        
        # 1) Get rule-based predictions
        r_ctx = context_result["pred"]
        r_esc = xss_escaping
        r_conf = context_result["conf"]
        
        # 2) Decide to call ML
        call_ml = (ctx_mode in {"always", "force_ml"}) or (ctx_mode == "auto" and r_conf < RULE_CONF_GATE)
        m_ctx = m_esc = None
        m_p = 0.0
        context_ml = escaping_ml = None
        
        if call_ml:
            try:
                from backend.modules.ml.xss_context_infer import predict_xss_context, predict_xss_escaping
                
                # Prepare features for ML
                window_start = max(0, canary_pos - 64)
                window_end = min(len(text), canary_pos + len(CANARY) + 64)
                text_window = text[window_start:window_end]
                
                # Get ML predictions
                context_ml = predict_xss_context(text_window, canary_pos - window_start)
                escaping_ml = predict_xss_escaping(text_window, canary_pos - window_start)
                
                if context_ml:
                    m_ctx = context_ml.get("pred")
                    m_p = context_ml.get("conf", 0.0)
                if escaping_ml:
                    m_esc = escaping_ml.get("pred")
                
                # Count ML invocation
                if meta is not None:
                    meta["xss.ml_invoked"] = meta.get("xss.ml_invoked", 0) + 1
                    
            except ImportError:
                # ML models not available, use rules
                pass
        
        # 3) Fuse decisions
        chose_ml = False
        if ctx_mode == "force_ml" and m_ctx:
            f_ctx, f_esc, src, conf = m_ctx, m_esc, "ml", m_p
            chose_ml = True
        elif m_ctx and (m_p >= ML_OVERRIDE_GATE) and (r_conf < RULE_CONF_GATE):
            f_ctx, f_esc, src, conf = m_ctx, m_esc, "ml", m_p
            chose_ml = True
        else:
            f_ctx, f_esc, src, conf = r_ctx, r_esc, ("rule_high_conf" if r_conf >= RULE_CONF_GATE else "rule_low_conf"), r_conf
        
        # Count final ML decisions
        if chose_ml and meta is not None:
            meta["xss.final_from_ml"] = meta.get("xss.final_from_ml", 0) + 1
        
        # Set final values
        final_context = f_ctx
        final_escaping = f_esc or "unknown"
        context_rule = context_result
        escaping_ml = escaping_ml
        
        # Legacy context for backwards compatibility
        ctx = "none"
        if final_context in ["html_body", "attr", "js_string"]:
            ctx = final_context.replace("html_body", "html")
        
        # Extract additional fields for evidence
        window_start = max(0, canary_pos - 64)
        window_end = min(len(text), canary_pos + len(CANARY) + 64)
        fragment_left_64 = text[window_start:canary_pos]
        fragment_right_64 = text[canary_pos + len(CANARY):window_end]
        raw_reflection = text[canary_pos:canary_pos + len(CANARY)]
        
        # Extract feature flags
        in_script_tag = '<script' in text[max(0, canary_pos - 200):canary_pos]
        in_style = '<style' in text[max(0, canary_pos - 200):canary_pos] or 'style=' in text[max(0, canary_pos - 50):canary_pos + 50]
        
        # Detect attribute context
        in_attr = False
        attr_name = ""
        attr_quote = ""
        
        # Look for attribute patterns around the canary
        attr_window = text[max(0, canary_pos - 100):canary_pos + 100]
        attr_match = re.search(r'(\w+)=["\']([^"\']*' + re.escape(CANARY) + r'[^"\']*)["\']', attr_window)
        if attr_match:
            in_attr = True
            attr_name = attr_match.group(1)
            # Safely extract quote character
            start_pos = attr_match.start(2) - 1
            if start_pos >= 0 and start_pos < len(attr_match.group(0)):
                attr_quote = attr_match.group(0)[start_pos]
            else:
                attr_quote = ""
        
        # Get content type from headers
        content_type = headers.get("content-type", "") if headers else ""
        
        return XssProbe(
            context=ctx,
            reflected=True,
            xss_context=final_context,
            xss_escaping=final_escaping,
            xss_context_rule=context_rule,
            xss_context_ml=context_ml,
            xss_escaping_ml=escaping_ml,
            fragment_left_64=fragment_left_64,
            fragment_right_64=fragment_right_64,
            raw_reflection=raw_reflection,
            in_script_tag=in_script_tag,
            in_attr=in_attr,
            attr_name=attr_name,
            in_style=in_style,
            attr_quote=attr_quote,
            content_type=content_type,
            param_in=param_in or "unknown",
            param=param or "<reflected>"
        )
    
    return XssProbe()