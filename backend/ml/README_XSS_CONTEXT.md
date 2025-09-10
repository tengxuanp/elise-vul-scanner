# XSS Context Classifier (training suite)

Train two small scikit-learn models to detect where a canary reflected and how it was escaped.

Artifacts written to `models/`:
- `xss_context_vectorizer.joblib`
- `xss_context_model.joblib`
- `xss_escaping_vectorizer.joblib`
- `xss_escaping_model.joblib`

## Quickstart
```bash
python -m backend.ml.xss_ctx.generate_data   # -> data/xss_ctx/train.jsonl (~50k)
python -m backend.ml.xss_ctx.train           # -> models/xss_*joblib
```
