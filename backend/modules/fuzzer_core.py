# backend/modules/fuzzer_core.py
from __future__ import annotations
import json, time, hashlib
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional
from urllib.parse import urlparse, urlencode, urlunparse, parse_qs

import httpx
from .detectors import reflection_signals, sql_error_signal, score

TRUNCATE_BODY = 2048

def _hash(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8", "ignore")).hexdigest()

def _apply_payload_to_target(t: Dict[str, Any], payload: str, control: bool=False) -> Tuple[str, Dict[str,str], Optional[str]]:
    """
    Returns (url, headers, body)
    """
    url = t["url"]
    headers = dict(t.get("headers") or {})
    body = t.get("body")

    value = t["control_value"] if control else payload

    if t["in"] == "query":
        # replace only target param; keep others as-is
        u = urlparse(url)
        q = parse_qs(u.query, keep_blank_values=True)
        q[t["target_param"]] = [value]
        new_qs = urlencode([(k, v) for k, vs in q.items() for v in (vs if isinstance(vs, list) else [vs])])
        url = urlunparse((u.scheme, u.netloc, u.path, u.params, new_qs, u.fragment))
        body = None  # GET
    else:
        # body param
        if t.get("content_type") == "application/json":
            try:
                data = json.loads(body) if isinstance(body, str) else (body or {})
            except Exception:
                data = {}
            data[t["target_param"]] = value
            body = json.dumps(data)
            headers["Content-Type"] = "application/json"
        else:
            # form-urlencoded string
            # parse and replace
            p = parse_qs(body or "", keep_blank_values=True)
            p[t["target_param"]] = [value]
            body = urlencode([(k, v) for k, vs in p.items() for v in (vs if isinstance(vs, list) else [vs])])
            headers["Content-Type"] = "application/x-www-form-urlencoded"

    return url, headers, body

def _send(client: httpx.Client, method: str, url: str, headers: Dict[str,str], body: Optional[str], timeout: float):
    try:
        if method == "GET":
            r = client.get(url, headers=headers, timeout=timeout)
        else:
            r = client.request(method, url, headers=headers, content=body.encode("utf-8") if isinstance(body, str) else body, timeout=timeout)
        return r
    except Exception as e:
        return None

def run_fuzz(job_dir: Path, targets_path: Path, out_dir: Optional[Path] = None) -> Path:
    """
    Executes control vs injected requests for each target param.
    Writes evidence to <job_dir>/results/evidence.jsonl
    """
    targets_obj = json.loads(targets_path.read_text("utf-8"))
    targets: List[Dict[str, Any]] = targets_obj.get("targets", [])

    results_dir = (out_dir or job_dir / "results")
    results_dir.mkdir(parents=True, exist_ok=True)
    evidence_path = results_dir / "evidence.jsonl"

    with httpx.Client(follow_redirects=True) as client, evidence_path.open("w", encoding="utf-8") as fout:
        for t in targets:
            method = t["method"].upper()
            timeout = float(t.get("timeout", 12.0))

            # CONTROL
            u_ctrl, h_ctrl, b_ctrl = _apply_payload_to_target(t, t["control_value"], control=True)
            t0 = time.time(); r0 = _send(client, method, u_ctrl, h_ctrl, b_ctrl, timeout); t1 = time.time()
            if not r0:
                continue
            body0 = (r0.text or "")[:TRUNCATE_BODY]

            # TEST PAYLOADS
            for payload in t["payloads"]:
                u1, h1, b1 = _apply_payload_to_target(t, payload, control=False)
                s0, l0 = r0.status_code, len(body0)
                t2 = time.time(); r1 = _send(client, method, u1, h1, b1, timeout); t3 = time.time()
                if not r1:
                    continue
                body1_full = r1.text or ""
                body1 = body1_full[:TRUNCATE_BODY]

                # Signals
                refl = reflection_signals(body1_full, payload)
                sqlerr = sql_error_signal(body1_full)

                # Deltas
                status_delta = abs((r1.status_code or 0) - s0)
                len_delta = abs(len(body1) - l0)
                ms_delta = int((t3 - t2 - (t1 - t0)) * 1000)

                conf = score({"reflection": refl, "sql_error": sqlerr}, status_delta, len_delta, ms_delta)

                if conf >= 0.6 or sqlerr or refl.get("js_context") or refl.get("raw"):
                    ev = {
                        "job": job_dir.name,
                        "target_id": t["id"],
                        "method": method,
                        "in": t["in"],
                        "param": t["target_param"],
                        "url": t["url"],
                        "content_type": t.get("content_type"),
                        "payload": payload,
                        "control_value": t["control_value"],
                        "status": r1.status_code,
                        "status_delta": status_delta,
                        "len_delta": len_delta,
                        "latency_ms_delta": ms_delta,
                        "signals": {
                            "reflection": refl,
                            "sql_error": sqlerr,
                        },
                        "confidence": conf,
                        "response_hash": _hash(body1),
                        "response_snippet": body1,
                    }
                    fout.write(json.dumps(ev) + "\n")
    return evidence_path
