#!/usr/bin/env python3
"""
Build an XSS payload ranking dataset from Elise evidence.

For each XSS evidence file, we take the ranking_topk payloads as the
candidate set and mark the payload used in attempts_timeline (hit=true)
as relevant=1, others 0. Features are computed to match the model’s
inference spec (feature_spec -> _features_to_vector).
"""
import json, argparse, hashlib
from pathlib import Path
from typing import Dict, List

def short_id(s: str) -> str:
    return hashlib.sha1((s or '').encode('utf-8','ignore')).hexdigest()[:12]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--jobs-dir', default='backend/data/jobs')
    ap.add_argument('--out', default='backend/modules/ml/data/xss_ranking.jsonl')
    args = ap.parse_args()

    jobs = Path(args.jobs_dir)
    rows = []
    for ev_path in jobs.glob('**/*_xss_*.json'):
        try:
            ev = json.loads(ev_path.read_text(encoding='utf-8'))
        except Exception:
            continue
        if ev.get('family') != 'xss':
            continue
        topk = ev.get('ranking_topk') or []
        if not topk:
            continue
        # hit payload
        hit = None
        for att in (ev.get('attempts_timeline') or []):
            if att.get('hit'):
                hit = att.get('payload_id')
                break
        hit = hit or (topk[0].get('payload_id') if topk else None)
        if not hit:
            continue

        # Build a base context from evidence
        ctx_base = {
            'family': 'xss',
            'param_in': ev.get('param_in',''),
            'param': ev.get('param',''),
            'status_class': int((ev.get('response_status') or 0)//100),
            'content_type_html': int('text/html' in (ev.get('response_headers') or {}).get('content-type','').lower()),
            'content_type_json': int('application/json' in (ev.get('response_headers') or {}).get('content-type','').lower()),
            'ctx_html': int((ev.get('xss_context') or '').lower() in {'html','html_body'}),
            'ctx_attr': int((ev.get('xss_context') or '').lower() == 'attr'),
            'ctx_js':   int((ev.get('xss_context') or '').lower() in {'js','js_string'}),
            'probe_sql_error': 0,
            'probe_timing_delta_gt2s': 0,
            'probe_reflection_html': int((ev.get('xss_context') or '').lower() in {'html','html_body'}),
            'probe_reflection_js': int((ev.get('xss_context') or '').lower() in {'js','js_string'}),
            'probe_redirect_location_reflects': 0,
        }
        group_id = f"{ev.get('method','GET')}|{ev.get('url','')}|{ev.get('param_in','')}|{ev.get('param','')}|{short_id(str(ev_path))}"
        for item in topk:
            payload = item.get('payload_id','')
            row = {
                'group': group_id,
                'x': {**ctx_base, 'payload': payload, 'param_len': len(ev.get('param','')), 'payload_len': len(payload)},
                'y': 1 if payload == hit else 0
            }
            rows.append(row)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open('w', encoding='utf-8') as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + '\n')
    print(f'Wrote {len(rows)} rows to {out}')

if __name__ == '__main__':
    main()

