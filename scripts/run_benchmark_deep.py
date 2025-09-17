#!/usr/bin/env python3
import os, json, time, sys
from pathlib import Path
sys.path.append('')
from backend.modules.playwright_crawler import crawl_site
from backend.pipeline.workflow import assess_endpoints

def main():
    job_id = f"bench-xss-deep-{int(time.time()*1000)}"
    job_dir = Path('backend/data/jobs')/job_id
    job_dir.mkdir(parents=True, exist_ok=True)

    target = 'https://localhost:8443/benchmark/'
    print('Crawling from', target)
    res = crawl_site(target_url=target, max_depth=5, max_endpoints=2000, max_seconds=900, submit_get_forms=True, submit_post_forms=True, click_buttons=True)
    endpoints = res.get('endpoints', [])
    meta = res.get('meta', {})
    print('Crawl meta:', meta)

    with (job_dir/'endpoints.json').open('w') as f:
        json.dump({
            'job_id': job_id,
            'target_url': target,
            'crawl_opts': {
                'max_depth': 5,
                'max_endpoints': 2000,
                'max_seconds': 900,
                'submit_get_forms': True,
                'submit_post_forms': True,
                'click_buttons': True,
            },
            'endpoints': endpoints
        }, f, indent=2)
    print('Endpoints persisted:', len(endpoints), '->', job_dir/'endpoints.json')

    os.environ['ELISE_TLS_INSECURE'] = '1'
    res2 = assess_endpoints(endpoints=endpoints, job_id=job_id, top_k=7, strategy='auto', ctx_mode='always', sqli_ml_mode='never')
    print('Assess summary:', res2['summary'])
    print('Job ID:', job_id)

if __name__ == '__main__':
    main()

