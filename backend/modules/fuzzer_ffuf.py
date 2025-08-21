# backend/modules/fuzzer_ffuf.py
from __future__ import annotations

import json
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Dict, Any, Optional, Tuple

def _has_header(headers: Dict[str, str], name: str) -> bool:
    n = name.lower()
    return any(k.lower() == n for k in (headers or {}).keys())

def _build_get(url: str, param: str) -> str:
    """Build GET target like: ...?param=FUZZ (append or add ?)."""
    join = "&" if "?" in url else "?"
    return f"{url}{join}{param}=FUZZ"

def _build_post_form(body: Dict[str, Any], param: str) -> str:
    """
    Turn dict into x-www-form-urlencoded with FUZZ on target param.
    NOTE: shallow only; nested keys handled in future fallback engine.
    """
    pairs = []
    for k, v in (body or {}).items():
        if k == param:
            pairs.append(f"{k}=FUZZ")
        else:
            pairs.append(f"{k}={v}")
    # In case param is missing from original body, still add it
    if param not in (body or {}):
        pairs.append(f"{param}=FUZZ")
    return "&".join(pairs)

def _build_post_json(body: Dict[str, Any], param: str) -> str:
    """
    Shallow JSON replacement: set top-level key `param` to "FUZZ".
    (Nested paths like user.email are not handled here.)
    """
    data = dict(body or {})
    data[param] = "FUZZ"
    return json.dumps(data, separators=(",", ":"))

def _normalize_body_for_form(raw_body: Any) -> Dict[str, Any]:
    """
    Normalize various shapes into a dict for form encoding.
    Accepts dict, "a=1&b=2" string, or None.
    """
    if isinstance(raw_body, dict):
        return raw_body
    if isinstance(raw_body, str):
        # best-effort parse of a=1&b=2
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
    """
    Normalize to dict for JSON encoding. If str, try json.loads; else {}.
    """
    if isinstance(raw_body, dict):
        return raw_body
    if isinstance(raw_body, str) and raw_body.strip():
        try:
            parsed = json.loads(raw_body)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}
    return {}

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

    Behavior:
      - GET:  appends ?param=FUZZ to URL
      - POST form: sends -X POST -H CT: x-www-form-urlencoded -d "a=1&param=FUZZ"
      - POST JSON: sends -X POST -H CT: application/json      -d '{"param":"FUZZ"}'

    Returns:
      {
        "output_file": str,
        "payload_file": str,
        "elapsed_ms": int,
        "matches": list,          # ffuf 'results' array (may be empty)
        "errors": list[str],
        "status": int,            # 200 if any matches else 404 (compat shim)
        "response_length": None   # kept for compatibility
      }
    """
    headers = headers or {}
    errors: list[str] = []

    # Choose output file
    odir = Path(output_dir) if output_dir else Path(tempfile.gettempdir())
    odir.mkdir(parents=True, exist_ok=True)
    outfile = odir / f"ffuf_{int(time.time() * 1000)}.json"

    # Base ffuf command (use list to avoid shell quoting issues)
    cmd: list[str] = [
        "ffuf",
        "-w", payload_file,
        "-t", str(threads),
        "-mc", match_codes,
        "-timeout", str(timeout),
        "-ac",                # auto-calibration
        "-json",              # machine-readable
        "-o", str(outfile),
    ]

    method = (method or "GET").upper()
    bt = (body_type or "").lower()

    # Build target + payload mode
    if method == "GET":
        target = _build_get(url, param)
        cmd += ["-u", target]

    elif method in {"POST", "PUT", "PATCH"}:
        cmd += ["-X", method]
        # Decide JSON vs FORM based on explicit body_type or content-type header
        ct_json = (bt == "json")
        if not ct_json and _has_header(headers, "Content-Type"):
            try:
                ct_json = "json" in headers[[k for k in headers if k.lower() == "content-type"][0]].lower()
            except Exception:
                pass

        if ct_json:
            norm = _normalize_body_for_json(body)
            data = _build_post_json(norm, param)
            cmd += ["-u", url, "-d", data]
            # Ensure JSON content-type present exactly once
            if not _has_header(headers, "Content-Type"):
                cmd += ["-H", "Content-Type: application/json"]
        else:
            norm = _normalize_body_for_form(body)
            data = _build_post_form(norm, param)
            cmd += ["-u", url, "-d", data]
            if not _has_header(headers, "Content-Type"):
                cmd += ["-H", "Content-Type: application/x-www-form-urlencoded"]
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

    # Add custom headers (keep session cookies etc.)
    for k, v in headers.items():
        # Skip adding CT if we already injected a CT above; otherwise include it
        if k.lower() == "content-type" and any(h.lower() == "content-type" for h in headers.keys()) is False:
            # handled above when needed; if user passed CT explicitly, it stays here
            pass
        cmd += ["-H", f"{k}: {v}"]

    # Execute
    start = time.time()
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,          # ffuf returns 1 on "no matches"
            timeout=timeout + 5,  # small cushion
        )
    except FileNotFoundError as e:
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
        errors.append(f"ffuf exited {proc.returncode}: {proc.stderr.decode('utf-8', errors='ignore').strip()}")

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
