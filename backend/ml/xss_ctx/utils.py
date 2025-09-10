import html

CANARY = "EliseXSSCanary123"

def escape(s: str, mode: str) -> str:
    if mode == "raw":
        return s
    if mode == "html":
        return html.escape(s).replace('"',"&quot;")
    if mode == "url":
        return (s.replace("<","%3C").replace(">","%3E")
                 .replace('"',"%22").replace("'","%27").replace(" ","+"))
    if mode == "js":
        s = s.replace("\\","\\\\").replace('"','\\"').replace("'","\\'")
        s = s.replace("<","\\x3c").replace(">","\\x3e")
        return s
    raise ValueError(mode)

def window(text: str, marker: str = CANARY, pad: int = 120) -> str:
    i = text.find(marker)
    if i < 0:
        return text[: 2*pad]
    return text[max(0, i - pad): i + len(marker) + pad]
