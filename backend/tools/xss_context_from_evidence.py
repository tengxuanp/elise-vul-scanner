#!/usr/bin/env python3
"""
Synthesize xss_context_events.ndjson from saved evidence files.

This is useful when XSS probes did not persist NDJSON events during runs,
but evidence JSONs contain the necessary fields under xss_context_details.

Usage:
  PYTHONPATH=. python backend/tools/xss_context_from_evidence.py [--job-id JOB]

If --job-id is omitted, processes all job directories under DATA_DIR/jobs.
"""
import argparse
import json
import os
from pathlib import Path
from typing import Dict, Any, Iterable

from backend.app_state import DATA_DIR


def iter_evidence_files(job_dir: Path) -> Iterable[Path]:
    for p in job_dir.glob("*_xss_*.json"):
        if p.name == "endpoints.json":
            continue
        yield p


def convert_evidence_to_event(evd: Dict[str, Any], job_id: str) -> Dict[str, Any]:
    d = evd
    det = (d.get("xss_context_details") or {})
    # Basic fragments and flags
    fragment_left_64 = det.get("fragment_left_64", "")
    fragment_right_64 = det.get("fragment_right_64", "")
    raw_reflection = det.get("raw_reflection", "")
    in_script_tag = bool(det.get("in_script_tag", False))
    in_attr = bool(det.get("in_attr", False))
    attr_name = det.get("attr_name", "")
    in_style = bool(det.get("in_style", False))
    attr_quote = det.get("attr_quote", "")
    content_type = det.get("content_type", "")

    # Rule outputs if available (fallback to unknown)
    rule = det.get("xss_context_rule") or {}
    rule_context = rule.get("pred", "unknown")
    rule_conf = float(rule.get("conf", 0.0) or 0.0)

    # Escaping via rule if present, else infer from reflection (simple)
    rule_escaping = det.get("xss_context_rule", {}).get("escaping")
    if not rule_escaping:
        # Minimal heuristic: if raw reflection equals canary from evidence writer
        canary = (d.get("marker") or {}).get("raw") or "EliseXSSCanary123"
        if raw_reflection == canary:
            rule_escaping = "raw"
        elif raw_reflection and ("&lt;" in raw_reflection or "&quot;" in raw_reflection or "&gt;" in raw_reflection):
            rule_escaping = "html"
        else:
            rule_escaping = "unknown"

    # Request fields
    url = d.get("url", "")
    method = d.get("method", "GET")
    param_in = d.get("param_in", "")
    param = d.get("param", "")

    event: Dict[str, Any] = {
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
        "content_type": content_type,
        "raw_reflection": raw_reflection,
        "rule_context": rule_context,
        "rule_escaping": rule_escaping,
        "rule_conf": rule_conf,
    }
    return event


def process_job(job_dir: Path) -> int:
    job_id = job_dir.name
    out_path = job_dir / "xss_context_events.ndjson"
    count = 0
    with open(out_path, "w", encoding="utf-8") as outf:
        for ev_path in iter_evidence_files(job_dir):
            try:
                with open(ev_path, "r", encoding="utf-8") as f:
                    evd = json.load(f)
                event = convert_evidence_to_event(evd, job_id)
                # Only write if we have basic fragments
                if event["fragment_left_64"] or event["fragment_right_64"]:
                    outf.write(json.dumps(event) + "\n")
                    count += 1
            except Exception as e:
                print(f"Skip {ev_path.name}: {e}")
    return count


def main():
    ap = argparse.ArgumentParser(description="Build xss_context_events.ndjson from evidence")
    ap.add_argument("--job-id", default=None, help="Specific job id to process; defaults to all jobs")
    args = ap.parse_args()

    jobs_dir = DATA_DIR / "jobs"
    if not jobs_dir.exists():
        print(f"Jobs directory not found: {jobs_dir}")
        return

    total = 0
    if args.job_id:
        d = jobs_dir / args.job_id
        if not d.exists():
            print(f"Job not found: {args.job_id}")
            return
        n = process_job(d)
        print(f"Processed {args.job_id}: {n} events")
        total += n
    else:
        for d in jobs_dir.iterdir():
            if not d.is_dir():
                continue
            n = process_job(d)
            if n:
                print(f"Processed {d.name}: {n} events")
                total += n

    print(f"Total events written: {total}")


if __name__ == "__main__":
    main()

