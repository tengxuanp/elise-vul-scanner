# backend/modules/fuzzer_ffuf.py
from __future__ import annotations

import json
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Dict, Any, Optional, Any

from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

FUZZ = "FUZZ"  # ffuf placeholder


def _has_header(headers: Dict[str, str], name: str) -> bool:
    n = name.lower()
    return any(k.lower() == n for k in (headers or {}).keys())


# ---------- REPLACEMENT HELPERS (fix duplicate-param bug) ----------
def _url_with_replaced_param(url: str, param: str, value_placeholder: str = FUZZ) -> str:
    """Return URL where the single 'param' value is set to FUZZ (replace if exists; else add)."""
    p = urlparse(url)
    q = [(k, v) for (k, v) in parse_qsl(p.query, keep_blank_values=True) if k != param]
    q.append((param, value_placeholder))
    new_q = urlencode(q, doseq=True)
    return urlunparse((p.scheme, p.netloc, p.path, p.params, new_q, p.fragment))


def _form_body_with_replaced_param(raw_body: Any, param: str, value_placeholder: str = FUZZ) -> Dict[str, Any]:
    """Normalize to dict and set param -> FUZZ (replace if present; else add)."""
    body = _normalize_body_for_form(raw_body)
    body[param] = value_placeholder
    return body


def _json_body_with_replaced_param(raw_body: Any, param: str, value_placeholder: str = FUZZ) -> Dict[str, Any]:
    """Normalize to dict and set param -> FUZZ (replace if present; else add)."""
    body = _normalize_body_for_json(raw_body)
    body[param] = value_placeholder
    return body


# ---------- NORMALIZERS ----------
def _normalize_body_for_form(raw_body: Any) -> Dict[str, Any]:
    """Accept dict, 'a=1&b=2' string, or None."""
    if isinstance(raw_body, dict):
        return dict(raw_body)
    if isinstance(raw_body, str):
        parts = [p for p in raw_body.split("&") if p]
        out: Dict[str, Any] = {}
        for p in parts:
            if "=" in p:
                k, v = p.split("=", 1)
                out[k] = v
            else:
                out[p] = ""
        return out
    return {}


def _normalize_body_for_json(raw_body: Any) -> Dict[str, Any]:
    """If str, try json.loads; else {}."""
    if isinstance(raw_body, dict):
        return dict(raw_body)
    if isinstance(raw_body, str) and raw_body.strip():
        try:
            parsed = json.loads(raw_body)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}
    return {}


# ---------- MAIN ----------
def run_ffuf(
    url: str,
    param: str,
    *,
    payload_file: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    body: Optional[Any] = None,
    body_type: Optional[str] = None,  # "json" | "form" | None/other
    timeout: int = 30,
    threads: int = 25,
    match_codes: str = "200,302,400,401,403,404,500",
    output_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Execute ffuf with the given payload wordlist against a single (url,param) test case.

    Fixed behavior:
      - GET:  **replaces** existing `param` value or adds it if missing → ...?param=FUZZ (exactly once)
      - POST form: builds application/x-www-form-urlencoded with **one** `param=FUZZ`
      - POST JSON: builds application/json with top-level `"param":"FUZZ"`
    """
    headers = dict(headers or {})
    errors: list[str] = []

    # Choose output file
    odir = Path(output_dir) if output_dir else Path(tempfile.gettempdir())
    odir.mkdir(parents=True, exist_ok=True)
    outfile = odir / f"ffuf_{int(time.time() * 1000)}.json"

    # Base ffuf command
    cmd: list[str] = [
        "ffuf",
        "-w", payload_file,
        "-t", str(threads),
        "-mc", match_codes,
        "-timeout", str(timeout),
        "-ac",
        "-json",
        "-o", str(outfile),
    ]

    method = (method or "GET").upper()
    bt = (body_type or "").lower()

    # Build target + payload mode
    if method == "GET":
        target = _url_with_replaced_param(url, param, FUZZ)
        cmd += ["-u", target]

    elif method in {"POST", "PUT", "PATCH"}:
        cmd += ["-X", method]

        # Decide JSON vs FORM based on explicit body_type or Content-Type header
        is_json = (bt == "json")
        if not is_json and _has_header(headers, "Content-Type"):
            try:
                ct = next(v for k, v in headers.items() if k.lower() == "content-type")
                is_json = "json" in (ct or "").lower()
            except StopIteration:
                pass

        if is_json:
            bdict = _json_body_with_replaced_param(body, param, FUZZ)
            data = json.dumps(bdict, separators=(",", ":"))
            cmd += ["-u", url, "-d", data]
            if not _has_header(headers, "Content-Type"):
                headers["Content-Type"] = "application/json"
        else:
            bdict = _form_body_with_replaced_param(body, param, FUZZ)
            from urllib.parse import urlencode as _urlencode  # local alias
            data = _urlencode(bdict, doseq=True)
            cmd += ["-u", url, "-d", data]
            if not _has_header(headers, "Content-Type"):
                headers["Content-Type"] = "application/x-www-form-urlencoded"
    else:
        return {
            "output_file": str(outfile),
            "payload_file": payload_file,
            "elapsed_ms": 0,
            "matches": [],
            "errors": [f"Unsupported method {method}"],
            "status": 400,
            "response_length": None,
        }

    # Add headers (no duplicate Content-Type)
    for k, v in headers.items():
        cmd += ["-H", f"{k}: {v}"]

    # Execute
    start = time.time()
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,          # ffuf returns 1 on "no matches"
            timeout=timeout + 5,  # cushion
        )
    except FileNotFoundError:
        return {
            "output_file": str(outfile),
            "payload_file": payload_file,
            "elapsed_ms": int((time.time() - start) * 1000),
            "matches": [],
            "errors": ["ffuf binary not found on PATH"],
            "status": 500,
            "response_length": None,
        }
    except subprocess.TimeoutExpired:
        return {
            "output_file": str(outfile),
            "payload_file": payload_file,
            "elapsed_ms": int((time.time() - start) * 1000),
            "matches": [],
            "errors": [f"ffuf timed out after {timeout}s"],
            "status": 504,
            "response_length": None,
        }

    elapsed_ms = int((time.time() - start) * 1000)
    if proc.returncode not in (0, 1):  # 1 == no matches; treat as non-fatal
        errors.append(
            f"ffuf exited {proc.returncode}: "
            f"{proc.stderr.decode('utf-8', errors='ignore').strip()}"
        )

    # Parse ffuf JSON file
    results_json: Dict[str, Any] = {}
    try:
        if outfile.exists():
            with outfile.open("r", encoding="utf-8") as f:
                results_json = json.load(f)
    except Exception as e:
        errors.append(f"failed to parse ffuf JSON: {e}")

    matches = results_json.get("results", []) if isinstance(results_json, dict) else []

    return {
        "output_file": str(outfile),
        "payload_file": payload_file,
        "elapsed_ms": elapsed_ms,
        "matches": matches,
        "errors": errors,
        # Compatibility shims:
        "status": 200 if matches else 404,
        "response_length": None,
    }
