import os, json, time, sys

def _ensure_path():
    root = os.path.abspath(os.path.dirname(__file__) + '/..')
    if root not in sys.path:
        sys.path.insert(0, root)

_ensure_path()
from backend.modules.fuzzer_core import run_job

def main():
    job_id = f"e2e-{int(time.time())}"
    print('JOB_ID', job_id)
    # Enable feature flags
    os.environ.setdefault('ELISE_ENABLE_DOM_XSS', '1')
    os.environ.setdefault('ELISE_ENABLE_DATA_DIFF', '1')
    res = run_job(
        target_url='http://localhost:8082/#/',
        job_id=job_id,
        max_depth=1,
        max_endpoints=40,
        strategy='auto',
        ctx_mode='auto',
        sqli_ml_mode='never',
    )
    print('SUMMARY', json.dumps(res.get('summary', {}), indent=2))
    print('META_KEYS', list(res.get('meta', {}).keys())[:10])
    print('RESULTS_COUNT', len(res.get('results', [])))
    print('JOB_DIR', os.path.join('backend','data','jobs', job_id))

if __name__ == '__main__':
    main()
