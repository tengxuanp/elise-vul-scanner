import httpx
import html
import urllib.parse
import re
from dataclasses import dataclass
from typing import List, Optional

CANARY = "EliseXSSCanary123"

@dataclass
class XssProbe:
    context: str = "none"  # none|html_body|attr|js_string|url|css|unknown
    escaping: str = "unknown"  # raw|html|url|js|unknown
    reflected: bool = False
    xss_context: Optional[str] = None
    xss_escaping: Optional[str] = None

def detect_xss_context(text: str, canary_pos: int) -> str:
    """Detect XSS context using rule-based heuristics."""
    if canary_pos == -1:
        return "unknown"
    
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
            return "js_string"
        else:
            return "html_body"  # In script but not in string
    
    # Check for CSS context
    style_start = text.rfind('<style', 0, canary_pos)
    style_end = text.find('</style>', canary_pos)
    if style_start != -1 and style_end != -1 and style_start < canary_pos < style_end:
        return "css"
    
    # Check for inline style attribute
    if 'style=' in window:
        return "css"
    
    # Check for URL context (href, src, action attributes)
    url_attrs = ['href=', 'src=', 'action=', 'formaction=']
    for attr in url_attrs:
        if attr in window:
            return "url"
    
    # Check for HTML attribute context
    if ('"' in window or "'" in window) and ('=' in window):
        return "attr"
    
    # Check for HTML body context
    if '<' in window and '>' in window:
        return "html_body"
    
    return "unknown"

def detect_xss_escaping(text: str, canary_pos: int) -> str:
    """Detect XSS escaping using rule-based heuristics."""
    if canary_pos == -1:
        return "unknown"
    
    # Get the actual reflected canary
    canary_end = canary_pos + len(CANARY)
    reflected_canary = text[canary_pos:canary_end]
    
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
    
    # Check for raw reflection
    if reflected_canary == CANARY:
        return "raw"
    
    return "unknown"

def run_xss_probe(url: str, method: str, param_in: str, param: str, headers=None):
    """Run XSS probe with enhanced context and escaping detection."""
    params = {}; data=None; js=None
    if param_in=="query": params={param: CANARY}
    elif param_in=="form": data={param: CANARY}
    elif param_in=="json": js={param: CANARY}
    
    r = httpx.request(method, url, params=params, data=data, json=js, headers=headers, timeout=8.0, follow_redirects=True)
    text = r.text or ""
    
    if CANARY in text:
        canary_pos = text.find(CANARY)
        
        # Detect context and escaping
        xss_context = detect_xss_context(text, canary_pos)
        xss_escaping = detect_xss_escaping(text, canary_pos)
        
        # Legacy context for backwards compatibility
        ctx = "none"
        if xss_context in ["html_body", "attr", "js_string"]:
            ctx = xss_context.replace("html_body", "html")
        
        return XssProbe(
            context=ctx,
            reflected=True,
            xss_context=xss_context,
            xss_escaping=xss_escaping
        )
    
    return XssProbe()