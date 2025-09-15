import os, json, time, sys

def _ensure_path():
    root = os.path.abspath(os.path.dirname(__file__) + '/..')
    if root not in sys.path:
        sys.path.insert(0, root)
_ensure_path()

from backend.modules.playwright_crawler import crawl_site
from backend.pipeline.workflow import assess_endpoints
from backend.app_state import DATA_DIR

def main():
    job_id = f"e2e-quick-{int(time.time())}"
    print('JOB_ID', job_id)
    os.environ.setdefault('ELISE_ENABLE_DOM_XSS', '1')
    os.environ.setdefault('ELISE_ENABLE_DATA_DIFF', '1')

    url = 'http://localhost:8082/#/'
    seeds = [
        url + '',  # base view
        'http://localhost:8082/#/search',
        'http://localhost:8082/#/contact',
        'http://localhost:8082/#/complain',
    ]
    crawl = crawl_site(
        target_url=url,
        max_depth=1,
        max_endpoints=40,
        click_buttons=True,
        max_seconds=60,
        seeds=seeds,
    )
    endpoints = crawl.get('endpoints', [])
    print('CRAWLED_ENDPOINTS', len(endpoints))

    # persist for review
    job_dir = DATA_DIR / 'jobs' / job_id
    job_dir.mkdir(parents=True, exist_ok=True)
    with open(job_dir / 'endpoints.json', 'w') as f:
        json.dump({'job_id': job_id, 'target_url': url, 'endpoints': endpoints, 'endpoints_count': len(endpoints)}, f, indent=2)

    # filter endpoints to reduce noise: focus JSON REST paths
    filtered = [e for e in endpoints if str(e.get('content_type','')).startswith('application/json') and str(e.get('path','')).startswith('/rest')]
    print('FILTERED_ENDPOINTS', len(filtered))
    with open(job_dir / 'filtered_endpoints.json', 'w') as f:
        json.dump({'job_id': job_id, 'target_url': url, 'endpoints': filtered, 'endpoints_count': len(filtered)}, f, indent=2)

    # assess
    res = assess_endpoints(endpoints=filtered or endpoints, job_id=job_id, top_k=3, strategy='auto', ctx_mode='auto', sqli_ml_mode='never')
    print('SUMMARY', json.dumps(res.get('summary', {}), indent=2))
    print('RESULTS_COUNT', len(res.get('results', [])))
    print('JOB_DIR', job_dir)

if __name__ == '__main__':
    main()
