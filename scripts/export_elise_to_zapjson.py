#!/usr/bin/env python3
"""
Export Elise XSS positives to a minimal ZAP JSON format that the
OWASP BenchmarkUtils scorecard plugin can parse.

Usage:
  python scripts/export_elise_to_zapjson.py --job-id <JOB_ID> --out <out.json>

The generated JSON includes @version/@generated keys and a single site
with alerts having cweid 79 (XSS) and instances listing URIs that end
with BenchmarkTestNNNNN.html, which the ZAP reader uses to map to test IDs.
"""
import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--job-id', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--base', default='https://localhost:8443/benchmark')
    args = ap.parse_args()

    job_dir = Path('backend/data/jobs')/args.job_id
    if not job_dir.exists():
        raise SystemExit(f'Job not found: {job_dir}')

    # Collect unique Benchmark test IDs from XSS evidence
    tests = {}
    for p in sorted(job_dir.glob('*_xss_*.json')):
        try:
            ev = json.loads(Path(p).read_text(encoding='utf-8'))
        except Exception:
            continue
        url = ev.get('url') or ''
        m = re.search(r'(BenchmarkTest\d{5})', url)
        if not m:
            path = ev.get('path') or ''
            m = re.search(r'(BenchmarkTest\d{5})', path)
        if m:
            tests[m.group(1)] = True

    alerts = []
    for test in sorted(tests.keys()):
        # Build a plausible URL for the instance; only the file name matters to the reader
        uri = f"{args.base}/xss-00/{test}.html"
        alerts.append({
            "cweid": "79",
            "instances": [{"uri": uri}],
        })

    out = {
        "@version": "2.11.0",
        "@generated": datetime.now(timezone.utc).isoformat(),
        "site": [
            {
                "alerts": alerts
            }
        ]
    }

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2), encoding='utf-8')
    print(f"Wrote ZAP JSON with {len(alerts)} XSS alerts to {out_path}")

if __name__ == '__main__':
    main()

