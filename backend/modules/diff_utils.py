# backend/modules/diff_utils.py
from __future__ import annotations

"""
Lightweight, dependency-free diff helpers used across the pipeline.

Goals
-----
- Provide stable hashing for bodies (bytes/str) after optional normalization.
- Produce quick similarity metrics (SequenceMatcher ratio, Jaccard over tokens).
- Generate human-readable unified diffs and a short "first-change" snippet.
- Offer JSON-aware and HTML-aware normalization/diffing (no heavy parsers).
- Summarize response→response deltas (status/length/hash/snippet), without I/O.

This module never performs network operations and is safe to import anywhere.
"""

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union
import difflib
import hashlib
import html
import json
import re

# ----------------------------- public exports --------------------------------

__all__ = [
    "ensure_str",
    "normalize_text",
    "strip_html_to_text",
    "stable_hash",
    "tokenize",
    "diff_stats",
    "text_diff",
    "json_diff",
    "response_diff",
    "DiffResult",
]

# ----------------------------- primitives ------------------------------------


def ensure_str(data: Union[str, bytes, bytearray, None], encoding: str = "utf-8") -> str:
    """
    Best-effort convert arbitrary body into a str. Bytes are decoded with
    errors='ignore' to avoid raising on binary blobs.
    """
    if data is None:
        return ""
    if isinstance(data, str):
        return data
    try:
        return bytes(data).decode(encoding, errors="ignore")
    except Exception:
        # Last-ditch: repr for truly opaque objects
        return repr(data)


def normalize_text(
    s: Union[str, bytes, bytearray, None],
    *,
    lower: bool = False,
    strip_ws: bool = True,
    collapse_ws: bool = True,
    unescape_html: bool = False,
) -> str:
    """
    Cheap, composable text normalization.
    """
    t = ensure_str(s)
    if unescape_html:
        try:
            t = html.unescape(t)
        except Exception:
            pass
    if lower:
        t = t.lower()
    if collapse_ws:
        t = re.sub(r"\s+", " ", t)
    if strip_ws:
        t = t.strip()
    return t


def strip_html_to_text(s: Union[str, bytes, bytearray, None]) -> str:
    """
    Remove script/style blocks and tags, unescape entities, and collapse whitespace.
    Not a full HTML parser — intentionally simple and fast for diffs/similarity.
    """
    t = ensure_str(s)
    # Drop scripts/styles
    t = re.sub(r"(?is)<script[^>]*>.*?</script>", " ", t)
    t = re.sub(r"(?is)<style[^>]*>.*?</style>", " ", t)
    # Remove all remaining tags
    t = re.sub(r"(?s)<[^>]+>", " ", t)
    # Unescape & collapse
    t = html.unescape(t)
    t = re.sub(r"\s+", " ", t).strip()
    return t


def stable_hash(
    data: Union[str, bytes, bytearray, Dict[str, Any], List[Any], None],
    *,
    algo: str = "sha1",
    normalize: bool = True,
    html_visible_only: bool = False,
    json_canonical: bool = False,
) -> str:
    """
    Stable, short hash for strings/bytes or JSON-like objects.

    - If `json_canonical`, we json.dumps(..., sort_keys=True, separators=(",",":"))
      first (ignores key order/whitespace differences).
    - If `html_visible_only`, we strip HTML to visible text before hashing.
    - If `normalize`, we apply normalize_text() to the final string.
    """
    if isinstance(data, (dict, list, tuple)):
        try:
            # Canonical JSON string
            payload = json.dumps(data, sort_keys=True, separators=(",", ":"))
        except Exception:
            payload = ensure_str(repr(data))
    else:
        payload = ensure_str(data)

    if html_visible_only:
        payload = strip_html_to_text(payload)

    if normalize:
        payload = normalize_text(payload, lower=False, strip_ws=True, collapse_ws=True, unescape_html=False)

    try:
        h = hashlib.new(algo)
    except Exception:
        h = hashlib.sha1()
    h.update(payload.encode("utf-8", errors="ignore"))
    return h.hexdigest()


def tokenize(s: Union[str, bytes, bytearray, None]) -> List[str]:
    """
    Basic alnum tokenization for Jaccard/word-level signals.
    """
    t = normalize_text(s, lower=True, collapse_ws=True)
    return re.findall(r"[a-z0-9]+", t)


# ----------------------------- diff building ---------------------------------

@dataclass
class DiffResult:
    equal: bool
    ratio: float                 # difflib.SequenceMatcher ratio
    jaccard: float               # token set similarity
    lcs_equal_chars: int         # number of 'equal' chars across opcodes
    added_chars: int             # total inserted chars
    removed_chars: int           # total deleted chars
    first_change_at: Optional[int]
    snippet: Optional[str]
    unified: Optional[str]


def _sequence_metrics(a: str, b: str) -> Tuple[float, int, int, int, Optional[int]]:
    """
    Compute SequenceMatcher metrics:
      - ratio
      - lcs_equal_chars, added_chars, removed_chars
      - first_change index in 'a' (approximate)
    """
    sm = difflib.SequenceMatcher(a=a, b=b, autojunk=False)
    ratio = sm.ratio()
    lcs_equal = 0
    ins = 0
    dele = 0
    first_change_at: Optional[int] = None

    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            lcs_equal += (i2 - i1)
        elif tag == "insert":
            ins += (j2 - j1)
            if first_change_at is None:
                first_change_at = i1
        elif tag == "delete":
            dele += (i2 - i1)
            if first_change_at is None:
                first_change_at = i1
        elif tag == "replace":
            ins += (j2 - j1)
            dele += (i2 - i1)
            if first_change_at is None:
                first_change_at = i1

    return ratio, lcs_equal, ins, dele, first_change_at


def _jaccard(a: str, b: str) -> float:
    sa = set(tokenize(a))
    sb = set(tokenize(b))
    if not sa and not sb:
        return 1.0
    inter = len(sa & sb)
    union = len(sa | sb) or 1
    return inter / union


def _snippet_around(s: str, idx: int, radius: int = 80) -> str:
    """
    Return a short snippet around the first change index with ellipses.
    """
    idx = max(0, min(len(s), idx))
    start = max(0, idx - radius)
    end = min(len(s), idx + radius)
    prefix = "…" if start > 0 else ""
    suffix = "…" if end < len(s) else ""
    return f"{prefix}{s[start:end]}{suffix}"


def _unified(a: str, b: str, a_name: str = "a", b_name: str = "b", context: int = 3, max_lines: int = 5000) -> str:
    """
    Produce a unified diff. For very long inputs, we cap the number of lines
    to keep memory/cpu reasonable.
    """
    a_lines = a.splitlines()
    b_lines = b.splitlines()
    if len(a_lines) + len(b_lines) > max_lines:
        # Fallback to head/tail to avoid massive diffs
        a_lines = a_lines[: max_lines // 2]
        b_lines = b_lines[: max_lines // 2]
    d = list(
        difflib.unified_diff(
            a_lines, b_lines, fromfile=a_name, tofile=b_name, n=context, lineterm=""
        )
    )
    return "\n".join(d)


def diff_stats(
    a: Union[str, bytes, bytearray, None],
    b: Union[str, bytes, bytearray, None],
    *,
    as_html_text: bool = False,
    normalize: bool = True,
    include_unified: bool = True,
) -> DiffResult:
    """
    Compute similarity/diff statistics between two strings (or bytes).
    - If as_html_text=True, both inputs are stripped to visible text first.
    - If normalize=True, normalize_text is applied to the working copies.
    """
    a0 = ensure_str(a)
    b0 = ensure_str(b)

    if as_html_text:
        a0 = strip_html_to_text(a0)
        b0 = strip_html_to_text(b0)

    if normalize:
        a0 = normalize_text(a0, lower=False, strip_ws=True, collapse_ws=True)
        b0 = normalize_text(b0, lower=False, strip_ws=True, collapse_ws=True)

    ratio, lcs_equal, ins, dele, first = _sequence_metrics(a0, b0)
    jac = _jaccard(a0, b0)
    snippet = _snippet_around(a0, first, radius=80) if first is not None else None
    uni = _unified(a0, b0) if include_unified and a0 != b0 else None

    return DiffResult(
        equal=(a0 == b0),
        ratio=float(ratio),
        jaccard=float(jac),
        lcs_equal_chars=int(lcs_equal),
        added_chars=int(ins),
        removed_chars=int(dele),
        first_change_at=first,
        snippet=snippet,
        unified=uni,
    )


# ----------------------------- JSON diff -------------------------------------

def _json_canonical(obj: Any) -> Any:
    """
    For comparison, convert lists/tuples to lists and ensure dict keys are strings.
    """
    if isinstance(obj, dict):
        return {str(k): _json_canonical(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_json_canonical(x) for x in obj]
    return obj


def _load_maybe_json(x: Any) -> Any:
    if isinstance(x, (dict, list, tuple)):
        return _json_canonical(x)
    s = ensure_str(x).strip()
    if not s:
        return None
    if s[:1] in ("{", "["):
        try:
            return _json_canonical(json.loads(s))
        except Exception:
            return None
    return None


def _json_diff_rec(a: Any, b: Any, path: str, out: List[Dict[str, Any]]) -> None:
    if type(a) != type(b):
        out.append({"op": "replace", "path": path, "a": a, "b": b})
        return
    if isinstance(a, dict):
        keys = set(a.keys()) | set(b.keys())
        for k in sorted(keys):
            p2 = f"{path}/{k}" if path else f"/{k}"
            if k not in a:
                out.append({"op": "add", "path": p2, "value": b[k]})
            elif k not in b:
                out.append({"op": "remove", "path": p2, "value": a[k]})
            else:
                _json_diff_rec(a[k], b[k], p2, out)
    elif isinstance(a, list):
        # naive list diff: compare by index length; treat as replace if different
        if len(a) != len(b):
            out.append({"op": "replace", "path": path or "/", "a": a, "b": b})
        else:
            for i, (va, vb) in enumerate(zip(a, b)):
                _json_diff_rec(va, vb, f"{path}/{i}" if path else f"/{i}", out)
    else:
        if a != b:
            out.append({"op": "replace", "path": path or "/", "a": a, "b": b})


def json_diff(a: Any, b: Any) -> Dict[str, Any]:
    """
    Diff two JSONish objects (dict/list/str JSON). Returns a dict:
      {
        "ok": bool,
        "equal": bool,
        "changes": [ {op, path, ...}, ... ],
        "a_hash": "...",
        "b_hash": "..."
      }
    If inputs aren't JSON, ok=False and changes=[].
    """
    ja = _load_maybe_json(a)
    jb = _load_maybe_json(b)
    if ja is None or jb is None:
        return {"ok": False, "equal": False, "changes": [], "a_hash": stable_hash(a), "b_hash": stable_hash(b)}

    out: List[Dict[str, Any]] = []
    _json_diff_rec(ja, jb, path="", out=out)
    return {
        "ok": True,
        "equal": not out,
        "changes": out,
        "a_hash": stable_hash(ja, json_canonical=True),
        "b_hash": stable_hash(jb, json_canonical=True),
    }


# ----------------------------- response delta --------------------------------

def _extract_status_and_body(meta: Dict[str, Any]) -> Tuple[Optional[int], str, Optional[str]]:
    """
    Try a few common shapes:
      - {"status": 200, "text": "...", "headers": {...}}
      - {"response": {"status":200, "body":"...", "headers": {...}}}
      - {"status_code": 200, "content": b"...", ...}
    Returns (status, body_str, content_type_header_lowered)
    """
    if not isinstance(meta, dict):
        return (None, ensure_str(meta), None)

    # nested response blob preferred
    resp = meta.get("response")
    if isinstance(resp, dict):
        status = resp.get("status") or resp.get("status_code")
        headers = resp.get("headers") or {}
        ct = (headers.get("content-type") or headers.get("Content-Type"))
        body = resp.get("text") or resp.get("body") or resp.get("content") or ""
        return (int(status) if isinstance(status, int) else None, ensure_str(body), (str(ct).lower() if ct else None))

    status = meta.get("status") or meta.get("status_code")
    headers = meta.get("headers") or {}
    ct = (headers.get("content-type") or headers.get("Content-Type"))
    body = meta.get("text") or meta.get("body") or meta.get("content") or ""
    return (int(status) if isinstance(status, int) else None, ensure_str(body), (str(ct).lower() if ct else None))


def response_diff(
    baseline_meta: Optional[Dict[str, Any]],
    attempt_meta: Optional[Dict[str, Any]],
    *,
    treat_html_as_text: bool = True,
    include_unified: bool = False,
) -> Dict[str, Any]:
    """
    Summarize changes between two response-like dicts.

    Returns:
    {
      "status_changed": 0|1,
      "status_a": int|None,
      "status_b": int|None,
      "len_delta": int,
      "len_a": int,
      "len_b": int,
      "hash_equal": bool,
      "hash_a": str,
      "hash_b": str,
      "similarity": { "ratio": float, "jaccard": float },
      "snippet": "...",
      "unified": "...",   # if include_unified and changed
      "json": { "ok": bool, "equal": bool, "changes": [...] }   # if JSON-ish
    }
    """
    a_status, a_body_raw, a_ct = _extract_status_and_body(baseline_meta or {})
    b_status, b_body_raw, b_ct = _extract_status_and_body(attempt_meta or {})

    # Prefer JSON-diff if both are JSON-ish
    jd = json_diff(a_body_raw, b_body_raw)
    json_section: Optional[Dict[str, Any]] = jd if jd.get("ok") else None

    # Prepare bodies for text diff
    a_body = a_body_raw
    b_body = b_body_raw

    def _is_html(ct: Optional[str]) -> bool:
        return bool(ct and ("text/html" in ct or "application/xhtml" in ct))

    as_html_text = treat_html_as_text and (_is_html(a_ct) or _is_html(b_ct))

    dr = diff_stats(a_body, b_body, as_html_text=as_html_text, normalize=True, include_unified=include_unified)

    return {
        "status_changed": int((a_status or 0) != (b_status or 0)),
        "status_a": a_status,
        "status_b": b_status,
        "len_delta": len(ensure_str(b_body_raw)) - len(ensure_str(a_body_raw)),
        "len_a": len(ensure_str(a_body_raw)),
        "len_b": len(ensure_str(b_body_raw)),
        "hash_equal": stable_hash(a_body_raw) == stable_hash(b_body_raw),
        "hash_a": stable_hash(a_body_raw),
        "hash_b": stable_hash(b_body_raw),
        "similarity": {"ratio": dr.ratio, "jaccard": dr.jaccard},
        "snippet": dr.snippet,
        "unified": dr.unified,
        "json": json_section,
    }


# ----------------------------- CLI smoke test --------------------------------

if __name__ == "__main__":  # pragma: no cover
    A = "<html><body>Hello <b>world</b>!</body></html>"
    B = "<html><body>Hello brave <b>world</b>!!!</body></html>"

    print("== strip_html_to_text ==")
    print(strip_html_to_text(A))

    print("\n== diff_stats(html as text) ==")
    r = diff_stats(A, B, as_html_text=True)
    print(r)

    print("\n== unified diff ==")
    print(r.unified or "(equal)")

    print("\n== json_diff ==")
    j1 = {"a": 1, "b": {"x": 1, "y": 2}}
    j2 = {"a": 1, "b": {"x": 2, "z": 3}}
    print(json_diff(j1, j2))

    print("\n== response_diff ==")
    ra = {"status": 200, "headers": {"Content-Type": "text/html"}, "body": A}
    rb = {"response": {"status": 200, "headers": {"content-type": "text/html"}, "body": B}}
    print(response_diff(ra, rb, include_unified=True))
