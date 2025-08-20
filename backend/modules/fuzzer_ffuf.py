# backend/modules/fuzzer_ffuf.py
from __future__ import annotations

import json
import shlex
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Dict, Any, Optional

def _build_target(url: str, param: str) -> str:
    # Build a URL like: ...?q=FUZZ (append or add ?)
    join = "&" if "?" in url else "?"
    return f"{url}{join}{param}=FUZZ"

def run_ffuf(
    url: str,
    param: str,
    *,
    payload_file: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 30,
    output_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Execute ffuf with the given payload wordlist against url+param.
    Returns a dict with keys used by fuzz_routes: output_file, status, response_length, elapsed_ms, matches, errors, payload_file.
    """
    headers = headers or {}
    target = _build_target(url, param)

    # Output file (JSON) lives under /tmp or provided dir
    odir = Path(output_dir) if output_dir else Path(tempfile.gettempdir())
    odir.mkdir(parents=True, exist_ok=True)
    outfile = odir / f"ffuf_{int(time.time()*1000)}.json"

    cmd = ["ffuf", "-w", payload_file, "-u", target, "-of", "json", "-o", str(outfile)]

    # HTTP method
    method = (method or "GET").upper()
    if method != "GET":
        cmd += ["-X", method]
        # For common POST-like cases, send form body param too
        if method in {"POST", "PUT", "PATCH"}:
            cmd += ["-d", f"{param}=FUZZ"]
            # set a default content-type if not provided
            if not any(h.lower() == "content-type" for h in headers):
                headers["Content-Type"] = "application/x-www-form-urlencoded"

    # Headers
    for k, v in headers.items():
        cmd += ["-H", f"{k}: {v}"]

    start = time.time()
    try:
        proc = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout
        )
    except FileNotFoundError as e:
        raise RuntimeError("ffuf binary not found on PATH") from e
    except subprocess.TimeoutExpired as e:
        raise RuntimeError(f"ffuf timed out after {timeout}s") from e

    elapsed_ms = int((time.time() - start) * 1000)

    # ffuf writes results to outfile; stdout/stderr might still carry hints
    errors = []
    if proc.returncode not in (0, 1):  # 1 is often "no matches"
        errors.append(f"ffuf exited {proc.returncode}: {proc.stderr.decode(errors='ignore').strip()}")

    results_json: Dict[str, Any] = {}
    try:
        if outfile.exists():
            with outfile.open() as f:
                results_json = json.load(f)
    except Exception as e:
        errors.append(f"failed to parse ffuf JSON: {e}")

    matches = []
    # ffuf JSON schema has "results": [...] when matches occur
    if isinstance(results_json.get("results"), list):
        matches = results_json["results"]

    # We don’t have a single HTTP status/length (ffuf tests many requests).
    # Return summary fields; fuzz_routes treats them as optional.
    return {
        "output_file": str(outfile),
        "payload_file": payload_file,
        "elapsed_ms": elapsed_ms,
        "matches": matches,
        "errors": errors,
        # legacy-ish fields kept for compatibility (best-effort)
        "status": 200 if matches else 404,
        "response_length": None,
    }
