#!/usr/bin/env python3
"""
Compute OWASP Benchmark XSS score (TP/FP/FN/TN, precision/recall/F1)
from Elise evidence for a given job_id by comparing against the
Benchmark expectedresults CSV (v1.2 by default).

Usage:
  python scripts/score_benchmark_xss.py --job-id <JOB_ID> [--expected /path/to/expectedresults-1.2.csv]
"""
import argparse
import json
import re
from pathlib import Path

def load_truth(expected_csv: Path):
    truth = {}
    for line in expected_csv.read_text(encoding='utf-8').splitlines():
        if not line or line.startswith('#'):
            continue
        parts = [p.strip() for p in line.split(',')]
        if len(parts) < 3:
            continue
        test, category, real = parts[:3]
        truth[test] = {'category': category, 'vuln': real.lower()=='true'}
    return truth

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--job-id', required=True)
    ap.add_argument('--expected', default=None, help='Path to expectedresults-1.2.csv')
    args = ap.parse_args()

    job_dir = Path('backend/data/jobs')/args.job_id
    if not job_dir.exists():
        raise SystemExit(f'Job directory not found: {job_dir}')

    expected = Path(args.expected) if args.expected else Path('/tmp/expectedresults-1.2.csv')
    if not expected.exists():
        raise SystemExit('Expected results CSV not found. Download it, e.g.\n'
                         'curl -fsSL https://raw.githubusercontent.com/OWASP-Benchmark/BenchmarkJava/master/expectedresults-1.2.csv -o /tmp/expectedresults-1.2.csv')
    truth = load_truth(expected)

    # Collect Elise-reported XSS positives per Benchmark test
    reported = {}
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
            reported[m.group(1)] = True

    TP=FP=FN=TN=0
    for test, info in truth.items():
        if info['category'] != 'xss':
            continue
        is_vuln = info['vuln']
        found = reported.get(test, False)
        if is_vuln and found:
            TP += 1
        elif is_vuln and not found:
            FN += 1
        elif (not is_vuln) and found:
            FP += 1
        else:
            TN += 1

    prec = TP/(TP+FP) if TP+FP>0 else 0.0
    rec = TP/(TP+FN) if TP+FN>0 else 0.0
    f1 = 2*prec*rec/(prec+rec) if (prec+rec)>0 else 0.0

    print('\nOWASP Benchmark XSS Score for', args.job_id)
    print('Using expected:', expected)
    print(f'TP={TP} FP={FP} FN={FN} TN={TN}')
    print('Precision={:.3f} Recall={:.3f} F1={:.3f}'.format(prec, rec, f1))

if __name__ == '__main__':
    main()

