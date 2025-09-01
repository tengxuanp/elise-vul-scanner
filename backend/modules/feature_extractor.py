# backend/modules/feature_extractor.py
from __future__ import annotations

from urllib.parse import urlparse, urlencode
from bs4 import BeautifulSoup
from html import escape as html_escape
import hashlib
import logging
import math
import os
import re
from typing import Any, Dict, List, Tuple, Optional

# Playwright is optional. If unavailable at import/runtime, we degrade cleanly.
try:
    from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
    _PLAYWRIGHT_AVAILABLE = True
except Exception:
    sync_playwright = None  # type: ignore
    PlaywrightTimeoutError = Exception  # type: ignore
    _PLAYWRIGHT_AVAILABLE = False

# Prefer your detectors; soft-fallback keeps module importable
try:
    from .detectors import reflection_signals
except Exception:
    def reflection_signals(body_text: str, probe: str) -> Dict[str, bool]:
        if not body_text or not probe:
            return {
                "raw": False,
                "html_escaped": False,
                "js_context": False,
                "attr_context": False,
                "tag_text_context": False,
            }
        raw = probe in body_text
        esc = html_escape(probe) in body_text
        js = False
        if raw:
            try:
                js = bool(re.search(r"<script[^>]*>[^<]*" + re.escape(probe), body_text, re.I | re.S))
            except Exception:
                js = False
        # naive attribute probe
        attr = False
        try:
            attr = bool(re.search(r"<[^>]+\b[\w:-]+\s*=\s*(['\"]).*?" + re.escape(probe) + r".*?\1", body_text, re.I | re.S))
        except Exception:
            attr = False
        return {
            "raw": raw,
            "html_escaped": esc,
            "js_context": js,
            "attr_context": attr,
            "tag_text_context": raw and not (js or attr),
        }

log = logging.getLogger(__name__)

# honor global ML debug toggle to keep parity with recommender
def _is_debug() -> bool:
    return str(os.getenv("ELISE_ML_DEBUG", "")).lower() in ("1", "true", "yes")

log.setLevel(logging.DEBUG if _is_debug() else logging.INFO)

# ------------------------------ helpers --------------------------------------

_XSS_PARAM_HINTS = {
    "q", "query", "search", "s", "term", "keyword",
    "comment", "message", "msg", "content", "body", "desc", "description",
    "text", "title", "name", "nick", "username"
}
_LOGIN_PATH_HINTS = {"login", "signin", "sign-in", "authenticate", "auth"}
_ID_LIKE_RE = re.compile(r"(?:^|[_\-\.\[\{])id(?:$|[_\-\.\]\}])", re.I)


def _sha_bucket(s: str, mod: int = 10) -> int:
    if s is None:
        return 0
    h = hashlib.sha1((s or "").encode("utf-8", "ignore")).hexdigest()
    return int(h[:8], 16) % max(1, mod)


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    # Shannon entropy over bytes
    freq: Dict[int, int] = {}
    b = s.encode("utf-8", "ignore")
    for ch in b:
        freq[ch] = freq.get(ch, 0) + 1
    n = float(len(b))
    return -sum((c / n) * math.log2((c / n)) for c in freq.values()) if n > 0 else 0.0


def _special_ratio(s: str) -> float:
    if not s:
        return 0.0
    specials = sum(1 for ch in s if not ch.isalnum())
    return specials / max(1, len(s))


def _content_type_hint(ct: Optional[str]) -> int:
    ct = (ct or "").split(";")[0].strip().lower()
    if ct in ("text/html", "application/xhtml+xml", ""):
        return 1  # HTML-ish or unknown
    if ct == "application/json":
        return 2
    if ct == "application/x-www-form-urlencoded" or "form" in ct:
        return 3
    return 0


def _infer_content_type_param(ct: Optional[str], headers: Optional[Dict[str, str]]) -> Optional[str]:
    if ct:
        return ct
    if headers:
        # try common casings
        for k in ("content-type", "Content-Type", "CONTENT-TYPE"):
            if k in headers and headers[k]:
                return headers[k]
    return None


def _path_depth(url: str) -> int:
    try:
        parts = [p for p in (urlparse(url).path or "").split("/") if p]
        return min(9, len(parts))
    except Exception:
        return 0


def _first_reflection_tag(html: str, payload: str) -> Tuple[str, str, int]:
    """
    Returns (tag_name, attr_name_or_empty, quote_feature)
      - quote_feature: 0 none, 1 double, 2 single, 3 both
    """
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        return "", "", 0

    enc = html_escape(payload)
    for tag in soup.find_all():
        tag_str = str(tag)
        if (payload and (payload in tag_str)) or (enc and (enc in tag_str)):
            # attribute hit?
            for attr, val in (tag.attrs or {}).items():
                if isinstance(val, list):
                    val_str = " ".join(v for v in val if v is not None)
                else:
                    val_str = val if val is not None else ""
                if (payload and payload in val_str) or (enc and enc in val_str):
                    dq = '"' in val_str
                    sq = "'" in val_str
                    qf = 3 if dq and sq else (1 if dq else (2 if sq else 0))
                    return (tag.name or "", str(attr), qf)
            # otherwise, reflection is inside tag text or other parts
            return (tag.name or "", "", 0)
    return "", "", 0


def _classify_reflection(body: str, payload: str) -> Tuple[str, str]:
    """
    Returns (reflection_type, reflection_context)
      - reflection_type: raw | encoded | partial | none
      - reflection_context: html | attribute | js
    """
    sig = reflection_signals(body, payload)
    if sig.get("raw"):
        rtype = "raw"
    elif sig.get("html_escaped"):
        rtype = "encoded"
    elif payload and (payload[:6] in body or payload[-6:] in body):
        rtype = "partial"
    else:
        rtype = "none"

    if sig.get("js_context"):
        ctx = "js"
    elif sig.get("attr_context"):
        ctx = "attribute"
    else:
        ctx = "html"

    return rtype, ctx


def _sanitize_headers(headers: Optional[Dict[str, Any]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in (headers or {}).items():
        if v is None:
            continue
        try:
            out[str(k)] = str(v)
        except Exception:
            pass
    return out


def _infer_injection_mode(method: str, content_type: Optional[str]) -> str:
    m = (method or "GET").upper()
    ct = (content_type or "").split(";")[0].strip().lower()
    if m == "GET":
        return "query"
    if m in ("PUT", "PATCH", "POST"):
        if ct == "application/json":
            return "json"
        if ct in ("application/x-www-form-urlencoded", "multipart/form-data") or "form" in ct:
            return "form" if "urlencoded" in ct else "multipart"
        return "json" if "json" in ct else "form"
    return "headers"


# ------------------------------ extractor ------------------------------------

class FeatureExtractor:
    """
    Returns a fixed-size 17-dim feature vector:
      0  tag_feature            (stable hash bucket of reflected tag name or 0)
      1  attr_feature           (stable hash bucket of reflected attr name or 0)
      2  domain_feature         (stable hash bucket of netloc)
      3  path_feature           (stable hash bucket of path)
      4  quote_feature          (0 none, 1 double, 2 single, 3 both) if attr reflection
      5  type_flag              (raw=1, encoded=2, partial=3, none=0)
      6  context_flag           (html=1, attribute=2, js=3; else 0)
      7  execution_flag         (Playwright dialog triggered)
      8  len(param) % 10
      9  len(payload) % 10
     10  id_like_param          (1 if param looks like id; else 0)
     11  path_depth             (0..9)
     12  login_hint             (1 if login-ish path; else 0)
     13  content_type_hint      (1 html, 2 json, 3 form, 0 unknown)
     14  xss_param_hint         (1 if param in xss-ish names; else 0)
     15  payload_entropy_bucket (0..9)
     16  payload_special_bucket (0..9)

    Notes:
    - We keep returning a flat list[int] to match the trained rankers (feature_dim=17).
    - Contextual hints like content_type/injection_mode are stored in self.last_meta
      for logging/diagnostics, but NOT injected into the numeric vector (to preserve ABI).
    """

    def __init__(self, wait_until: str = "domcontentloaded", nav_timeout_ms: int = 10000, headless: bool = True):
        self.wait_until = wait_until
        self.nav_timeout_ms = nav_timeout_ms
        self.headless = headless
        self.last_meta: Dict[str, Any] = {}

    # ---------- payload-agnostic endpoint vector (no browser) ----------
    def extract_endpoint_features(
        self,
        url: str,
        param: str,
        method: str = "GET",
        content_type: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> List[int]:
        """
        Cheap, payload-agnostic 17-dim vector. Does NOT open a browser.
        Use this for Stage-A routing or when you only need endpoint context.
        """
        parsed = urlparse(url or "")
        domain_feature = _sha_bucket(parsed.netloc or "", 20)
        path_feature = _sha_bucket(parsed.path or "", 20)
        param_norm = (param or "").lower()
        parts = [p for p in (parsed.path or "").split("/") if p]

        # derive effective content-type (explicit arg wins over headers)
        eff_ct = _infer_content_type_param(content_type, headers)
        ct_hint = _content_type_hint(eff_ct)
        inj_mode = _infer_injection_mode(method, eff_ct)

        login_hint = 1 if any(seg.lower() in _LOGIN_PATH_HINTS for seg in parts) else 0
        id_like_param = 1 if (_ID_LIKE_RE.search(param_norm) or param_norm in ("id", "uid", "user_id", "product_id")) else 0
        xss_param_hint = 1 if param_norm in _XSS_PARAM_HINTS else 0

        vec: List[int] = [
            0,                          # tag
            0,                          # attr
            domain_feature,             # domain
            path_feature,               # path
            0,                          # quote
            0,                          # type_flag
            0,                          # context
            0,                          # js_exec
            len(param) % 10,            # param len
            0,                          # payload len (none)
            id_like_param,              # id-like
            min(9, _path_depth(url)),   # depth
            login_hint,                 # login hint
            ct_hint,                    # content type hint
            xss_param_hint,             # xss param hint
            0,                          # entropy bucket
            0,                          # special-char bucket
        ]
        self.last_meta = {
            "endpoint_only": True,
            "content_type": eff_ct,
            "content_type_hint": ct_hint,
            "injection_mode": inj_mode,
            "login_hint": login_hint,
            "id_like_param": id_like_param,
            "xss_param_hint": xss_param_hint,
        }
        if _is_debug():
            log.debug("extract_endpoint_features -> vec=%s meta=%s", vec, self.last_meta)
        return vec

    def extract_features(
        self,
        url: str,
        param: str,
        payload: str,
        method: str = "GET",
        content_type: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        use_browser: bool = True,
        injection_mode: Optional[str] = None,
    ) -> List[int]:
        """
        Heavy extractor (may open a browser) that tries to observe reflection/JS execution.
        Set use_browser=False to force the cheap path.
        """
        eff_ct = _infer_content_type_param(content_type, headers)
        if not use_browser or not _PLAYWRIGHT_AVAILABLE:
            return self.extract_endpoint_features(url, param, method=method, content_type=eff_ct, headers=headers)

        # === Parse Target Info ===
        parsed = urlparse(url or "")
        domain_feature = _sha_bucket(parsed.netloc or "", 20)
        path_feature = _sha_bucket(parsed.path or "", 20)

        html = ""
        executed_flag = {"value": False}  # Mutable for JS dialog hook
        ctx_headers = _sanitize_headers(headers)

        # === Playwright Session ===
        try:
            assert sync_playwright is not None  # type: ignore
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=self.headless)
                context = browser.new_context(ignore_https_errors=True, extra_http_headers=ctx_headers or None)
                page = context.new_page()

                # Hook: JS Execution Detection
                def on_dialog(dialog):
                    executed_flag["value"] = True
                    try:
                        dialog.dismiss()
                    except Exception:
                        pass

                page.on("dialog", on_dialog)

                # Optional: catch console log that echoes payload (weak signal; do not set execution_flag)
                def on_console(msg):
                    if payload and payload in (msg.text() or ""):
                        self.last_meta["console_reflection"] = True
                page.on("console", on_console)

                try:
                    if method.upper() == "POST":
                        base_url = url.split("?")[0]
                        ct_slim = (eff_ct or "").split(";")[0].strip().lower()

                        resp_text = None
                        try:
                            # Best-effort server-side fetch to avoid form filling for simple cases
                            api_ctx = p.request.new_context(extra_http_headers=ctx_headers or None)
                            if ct_slim == "application/json":
                                resp = api_ctx.post(base_url, data=None, json={param: payload}, timeout=self.nav_timeout_ms)
                            else:
                                resp = api_ctx.post(base_url, data={param: payload}, timeout=self.nav_timeout_ms)
                            if resp and resp.ok:
                                resp_text = resp.text()
                            try:
                                api_ctx.dispose()
                            except Exception:
                                pass
                        except Exception:
                            resp_text = None

                        if resp_text:
                            try:
                                page.set_content(resp_text, wait_until=self.wait_until, timeout=self.nav_timeout_ms)
                                html = page.content()
                            except Exception:
                                html = resp_text
                        else:
                            page.goto(base_url, wait_until=self.wait_until, timeout=self.nav_timeout_ms)
                            html = page.content()

                    else:
                        glue = "&" if "?" in url else "?"
                        target = f"{url}{glue}{urlencode({param: payload})}"
                        page.goto(target, wait_until=self.wait_until, timeout=self.nav_timeout_ms)
                        html = page.content()

                except PlaywrightTimeoutError:  # type: ignore
                    log.warning(f"[Timeout] {url}")
                except Exception as e:
                    log.error(f"[Navigation Error] {url} — {e}")
                finally:
                    try:
                        context.close()
                    except Exception:
                        pass
                    try:
                        browser.close()
                    except Exception:
                        pass

        except Exception as e:
            log.error(f"[Playwright Setup/Error] {e}")
            return self._default_vector(url, param, payload, domain_feature, path_feature, eff_ct, headers)

        if not html:
            log.warning(f"[Empty HTML] Could not extract content from {url}")
            return self._default_vector(url, param, payload, domain_feature, path_feature, eff_ct, headers)

        # === Reflection & Context ===
        reflection_type, reflection_context = _classify_reflection(html, payload)

        # Tag / attribute features + quoting
        tag_name, attr_name, quote_feature = _first_reflection_tag(html, payload)
        # If detector didn't mark attribute, but we found an attribute container, nudge context
        if reflection_type != "none" and reflection_context == "html" and attr_name:
            reflection_context = "attribute"

        tag_feature = _sha_bucket(tag_name, 10) if tag_name else 0
        attr_feature = _sha_bucket(attr_name, 10) if attr_name else 0

        # === Secondary semantic hints ===
        param_norm = (param or "").lower()
        parts = [p for p in (parsed.path or "").split("/") if p]
        login_hint = 1 if any(seg.lower() in _LOGIN_PATH_HINTS for seg in parts) else 0
        id_like_param = 1 if (_ID_LIKE_RE.search(param_norm) or param_norm in ("id", "uid", "user_id", "product_id")) else 0
        xss_param_hint = 1 if param_norm in _XSS_PARAM_HINTS else 0
        ct_hint = _content_type_hint(eff_ct)
        inj_mode = (injection_mode or _infer_injection_mode(method, eff_ct)).lower()

        # === Numeric encodings ===
        type_flag = {"raw": 1, "encoded": 2, "partial": 3, "none": 0}[reflection_type]
        context_flag = {"html": 1, "attribute": 2, "js": 3}.get(reflection_context, 0)
        execution_flag = 1 if executed_flag["value"] else 0

        # Entropy & special-char buckets for payload
        H = _entropy(payload)
        S = _special_ratio(payload)
        entropy_bucket = min(9, int(round(H)))  # 0..9 (rough)
        special_bucket = min(9, int(S * 10))    # 0..9

        # === Feature Vector (length 17) ===
        vec: List[int] = [
            tag_feature,                # 0
            attr_feature,               # 1
            domain_feature,             # 2
            path_feature,               # 3
            quote_feature,              # 4
            type_flag,                  # 5
            context_flag,               # 6
            execution_flag,             # 7
            len(param) % 10,            # 8
            len(payload) % 10,          # 9
            id_like_param,              # 10
            min(9, _path_depth(url)),   # 11
            login_hint,                 # 12
            ct_hint,                    # 13
            xss_param_hint,             # 14
            entropy_bucket,             # 15
            special_bucket,             # 16
        ]

        # optional debug metadata (non-numeric hints for logs/UI)
        self.last_meta = {
            "endpoint_only": False,
            "reflection_type": reflection_type,
            "reflection_context": reflection_context,
            "tag": tag_name,
            "attr": attr_name,
            "executed_flag": bool(executed_flag["value"]),
            "content_type": eff_ct,
            "content_type_hint": ct_hint,
            "injection_mode": inj_mode,
            "login_hint": login_hint,
            "id_like_param": id_like_param,
            "xss_param_hint": xss_param_hint,
            "payload_entropy": H,
            "payload_special_ratio": S,
            "headers_used": bool(ctx_headers),
        }
        if _is_debug():
            log.debug("extract_features -> vec=%s meta=%s", vec, self.last_meta)

        return vec

    def _default_vector(
        self,
        url: str,
        param: str,
        payload: str,
        domain_feature: int,
        path_feature: int,
        content_type: Optional[str],
        headers: Optional[Dict[str, str]] = None,
    ) -> List[int]:
        # conservative defaults preserving shape
        eff_ct = _infer_content_type_param(content_type, headers)
        param_norm = (param or "").lower()
        vec = [
            0,                          # tag
            0,                          # attr
            domain_feature,             # domain
            path_feature,               # path
            0,                          # quote
            0,                          # type_flag
            0,                          # context
            0,                          # js_exec
            len(param) % 10,            # param len
            len(payload) % 10,          # payload len
            1 if _ID_LIKE_RE.search(param_norm) or param_norm in ("id", "uid", "user_id", "product_id") else 0,
            min(9, _path_depth(url)),   # depth
            1 if any(seg.lower() in _LOGIN_PATH_HINTS for seg in (urlparse(url).path or "").split("/") if seg) else 0,
            _content_type_hint(eff_ct),  # content-type hint
            1 if param_norm in _XSS_PARAM_HINTS else 0,  # xss param hint
            0,                          # entropy bucket
            0,                          # special-char bucket
        ]
        self.last_meta = {
            "endpoint_only": True,
            "fallback": True,
            "content_type": eff_ct,
            "injection_mode": _infer_injection_mode("GET", eff_ct),  # best guess
        }
        if _is_debug():
            log.debug("_default_vector -> vec=%s meta=%s", vec, self.last_meta)
        return vec

    # Convenience for callers that want the latest hints (non-breaking)
    def get_last_meta(self) -> Dict[str, Any]:
        return dict(self.last_meta or {})
