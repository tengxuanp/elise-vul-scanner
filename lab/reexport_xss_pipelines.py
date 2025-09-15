"""
Re-export XSS pipelines with the current venv (Python/sklearn) so they unpickle
cleanly at runtime.

This script loads the already-working model + vectorizer artifacts and creates
fresh sklearn Pipelines, then saves them back into MODEL_DIR:

  - xss_context_pipeline.joblib
  - xss_escaping_pipeline.joblib

Run from repo root with your venv active:

  source venv/bin/activate
  python lab/reexport_xss_pipelines.py

Afterwards, you can unset the skip flag and loaders will use pipelines:

  unset ELISE_SKIP_XSS_PIPELINE
"""

from __future__ import annotations

import sys
from pathlib import Path
import joblib

import os
def _ensure_path():
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    if root not in sys.path:
        sys.path.insert(0, root)
_ensure_path()

from backend.app_state import MODEL_DIR

def alias_numpy_core():
    try:
        import numpy as _np
        if 'numpy._core' not in sys.modules:
            sys.modules['numpy._core'] = _np.core
    except Exception:
        pass

def reexport_pipeline(vec_name: str, model_name: str, pipe_name: str) -> bool:
    alias_numpy_core()
    vec_path = MODEL_DIR / vec_name
    mdl_path = MODEL_DIR / model_name
    out_path = MODEL_DIR / pipe_name
    if not vec_path.exists() or not mdl_path.exists():
        print(f"[SKIP] Missing components for {pipe_name}: {vec_path.exists()=}, {mdl_path.exists()=}")
        return False
    try:
        vectorizer = joblib.load(vec_path)
        model = joblib.load(mdl_path)
        # Assemble simple pipeline: vectorizer -> classifier
        try:
            from sklearn.pipeline import Pipeline
        except Exception as e:
            print(f"[ERR] sklearn import failed: {e}")
            return False
        pipe = Pipeline([('vec', vectorizer), ('clf', model)])
        joblib.dump(pipe, out_path)
        print(f"[OK] Re-exported {pipe_name} -> {out_path}")
        return True
    except Exception as e:
        print(f"[ERR] Re-export failed for {pipe_name}: {e}")
        return False

def main():
    print(f"MODEL_DIR: {MODEL_DIR}")
    ok1 = reexport_pipeline(
        'xss_context_vectorizer.joblib',
        'xss_context_model.joblib',
        'xss_context_pipeline.joblib',
    )
    ok2 = reexport_pipeline(
        'xss_escaping_vectorizer.joblib',
        'xss_escaping_model.joblib',
        'xss_escaping_pipeline.joblib',
    )
    # Quick load check (optional; uses pipeline paths we just wrote)
    if ok1 or ok2:
        try:
            from backend.modules.ml.xss_context_infer import load_models
            # Temporarily allow pipeline load
            import os
            os.environ['ELISE_SKIP_XSS_PIPELINE'] = '0'
            print('Load models with pipelines enabled...')
            print('load:', load_models())
        except Exception as e:
            print(f"[WARN] Post-check load failed: {e}")

if __name__ == '__main__':
    main()
