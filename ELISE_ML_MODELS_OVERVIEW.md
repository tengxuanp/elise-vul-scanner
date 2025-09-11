# Elise ML Models Overview

## Total Number of ML Models: **8 Models**

The Elise system currently contains **8 machine learning models** across different categories and purposes.

## Model Categories and Details

### 1. **Family Ranker Models** (3 models)
**Purpose**: Rank payloads by vulnerability family for optimal injection order

#### Models:
- **`family_xss.joblib`** + **`family_xss.cal.json`**
  - **Type**: Binary classifier with calibration
  - **Purpose**: Rank XSS payloads by likelihood of success
  - **Features**: 45-dimensional feature vector (param analysis, probe signals, context)
  - **Calibration**: Platt scaling for probability calibration

- **`family_sqli.joblib`** + **`family_sqli.cal.json`**
  - **Type**: Binary classifier with calibration  
  - **Purpose**: Rank SQLi payloads by likelihood of success
  - **Features**: 45-dimensional feature vector (param analysis, probe signals, context)
  - **Calibration**: Platt scaling for probability calibration

- **`family_redirect.joblib`** + **`family_redirect.cal.json`**
  - **Type**: Binary classifier with calibration
  - **Purpose**: Rank redirect payloads by likelihood of success
  - **Features**: 45-dimensional feature vector (param analysis, probe signals, context)
  - **Calibration**: Platt scaling for probability calibration

### 2. **XSS Context Classification Models** (2 models)
**Purpose**: Classify XSS context and escaping for context-aware payload selection

#### Models:
- **`xss_context_model.joblib`** + **`xss_context_vectorizer.joblib`**
  - **Type**: Multi-class classifier with TF-IDF vectorization
  - **Purpose**: Classify XSS context (html_body, attr, js_string, url, css, comment, json)
  - **Features**: Character 3-5-gram TF-IDF on ±120 character window around reflection
  - **Classes**: 7 context types
  - **Vectorizer**: Custom TF-IDF with character n-grams

- **`xss_escaping_model.joblib`** + **`xss_escaping_vectorizer.joblib`**
  - **Type**: Multi-class classifier with TF-IDF vectorization
  - **Purpose**: Classify XSS escaping type (raw, html, url, js)
  - **Features**: Character 3-5-gram TF-IDF on ±120 character window around reflection
  - **Classes**: 4 escaping types
  - **Vectorizer**: Custom TF-IDF with character n-grams

### 3. **General Purpose Models** (3 models)
**Purpose**: Various utility and enhancement functions

#### Models:
- **`payload_recommender.joblib`**
  - **Type**: General payload recommendation model
  - **Purpose**: Recommend payloads based on endpoint features
  - **Features**: 17-dimensional feature vector (endpoint + payload descriptors)
  - **Families**: Supports xss, sqli, redirect families

- **`vulnerability_predictor.joblib`**
  - **Type**: General vulnerability prediction model
  - **Purpose**: Predict vulnerability likelihood across families
  - **Features**: Multi-dimensional feature vector
  - **Usage**: General vulnerability assessment

- **`param_prioritizer`** (pickle format)
  - **Type**: Logistic regression model
  - **Purpose**: Prioritize parameters for testing order
  - **Features**: Token-based features from parameter names and URLs
  - **Usage**: Parameter prioritization for efficient scanning

## How the Models Work Together

### 1. **Assessment Pipeline Integration**

```python
# 1. Parameter Prioritization
param_prioritizer.predict_proba(method, url, param)

# 2. Family Ranking (for XSS)
if family == "xss" and ml_mode in {"auto", "force_ml"}:
    ranked = rank_payloads(fam, features, top_k, ml_mode=ctx_mode)
    # Uses: family_xss.joblib + family_xss.cal.json

# 3. XSS Context Classification (if XSS reflection detected)
if xss_reflection_detected:
    context_result = predict_xss_context(text_window, canary_pos)
    escaping_result = predict_xss_escaping(text_window, canary_pos)
    # Uses: xss_context_model.joblib + xss_context_vectorizer.joblib
    #       xss_escaping_model.joblib + xss_escaping_vectorizer.joblib
```

### 2. **Feature Engineering Pipeline**

#### For Family Rankers (45 features):
```python
features = {
    # Basic features (4)
    "param_len": len(param),
    "url_length": 0,  # Not available
    "path_depth": 0,  # Not available  
    "shannon_entropy": shannon_entropy(payload),
    
    # Family indicators (3)
    "family_xss": 1 if family == 'xss' else 0,
    "family_sqli": 1 if family == 'sqli' else 0,
    "family_redirect": 1 if family == 'redirect' else 0,
    
    # Parameter type indicators (3)
    "param_in_query": 1 if param_in == 'query' else 0,
    "param_in_form": 1 if param_in == 'form' else 0,
    "param_in_json": 1 if param_in == 'json' else 0,
    
    # Probe features (6)
    "probe_sql_error": 1 if sql_error_detected else 0,
    "probe_timing_delta_gt2s": 1 if timing_delta > 2s else 0,
    "probe_reflection_html": 1 if html_reflection else 0,
    "probe_reflection_js": 1 if js_reflection else 0,
    "probe_redirect_influence": 1 if redirect_influence else 0,
    
    # Status class indicators (5)
    "status_class_2": 1 if status_class == 2 else 0,
    "status_class_3": 1 if status_class == 3 else 0,
    "status_class_4": 1 if status_class == 4 else 0,
    "status_class_5": 1 if status_class == 5 else 0,
    "status_class_other": 1 if status_class not in [2,3,4,5] else 0,
    
    # Content type indicators (2)
    "content_type_html": 1 if content_type == 'text/html' else 0,
    "content_type_json": 1 if content_type == 'application/json' else 0,
    
    # Context indicators (3)
    "ctx_html": 1 if context == 'html' else 0,
    "ctx_attr": 1 if context == 'attr' else 0,
    "ctx_js": 1 if context == 'js_string' else 0,
    
    # Parameter analysis features (8)
    "param_len": len(param),
    "payload_len": len(payload),
    "alnum_ratio": calculate_ratio(payload, r'[a-zA-Z0-9]'),
    "digit_ratio": calculate_ratio(payload, r'[0-9]'),
    "symbol_ratio": calculate_ratio(payload, r'[^a-zA-Z0-9\s]'),
    "url_encoded_ratio": calculate_ratio(payload, r'%[0-9A-Fa-f]{2}'),
    "double_encoded_hint": 1 if '%25' in payload else 0,
    "shannon_entropy": shannon_entropy(payload),
    
    # Payload analysis features (7)
    "has_quote": 1 if ('"' in payload or "'" in payload) else 0,
    "has_angle": 1 if ('<' in payload or '>' in payload) else 0,
    "has_lt_gt": 1 if ('<' in payload and '>' in payload) else 0,
    "has_script_tag": 1 if '<script' in payload.lower() else 0,
    "has_event_handler": 1 if any(handler in payload.lower() for handler in ['onload', 'onerror', 'onclick', 'onmouseover']) else 0,
    "sql_kw_hits": count_keywords(payload, sql_keywords),
    "balanced_quotes": 1 if payload.count("'") % 2 == 0 and payload.count('"') % 2 == 0 else 0,
    
    # Additional features (4)
    "has_comment_seq": 1 if any(seq in payload for seq in ['--', '/*', '*/', '#']) else 0,
    "payload_has_script": 0,  # Not available
    "payload_has_svg": 0,     # Not available
    "payload_has_img": 0      # Not available
}
```

#### For XSS Context Classification:
```python
# Text window around reflection point (±120 characters)
text_window = response_text[max(0, canary_pos-120):canary_pos+120]

# Binary features (14 features)
binary_features = [
    has_script_tag, has_style_tag, has_quotes, has_equals,
    has_angle_brackets, has_url_attrs, has_style_attr,
    in_script_tag, in_attr, in_style,
    is_double_quote, is_single_quote,
    is_text_html, is_application_json
]

# Text features (TF-IDF vectorization)
text_features = _context_vectorizer.transform([text_window])
```

### 3. **Model Loading and Caching**

```python
# Lazy loading with caching
_model_cache = {}
_calibration_cache = {}

def _load_model(family: str) -> Optional[Any]:
    if family in _model_cache:
        return _model_cache[family]
    
    # Load from disk
    model_path = MODEL_DIR / f"family_{family}.joblib"
    model = joblib.load(model_path)
    _model_cache[family] = model
    return model
```

### 4. **Calibration and Confidence**

```python
# Platt scaling calibration
def _apply_calibration(family: str, scores: np.ndarray) -> np.ndarray:
    calibration = _load_calibration(family)
    if calibration and 'slope' in calibration and 'intercept' in calibration:
        logits = np.log(scores[:, 1] / (scores[:, 0] + 1e-8))
        slope = float(calibration['slope'])
        intercept = float(calibration['intercept'])
        calibrated = 1 / (1 + np.exp(slope * logits + intercept))
        return np.column_stack([1 - calibrated, calibrated])
    return scores
```

## Model Usage by Strategy

### Smart-XSS Strategy
- **XSS**: Uses `family_xss.joblib` + `xss_context_model.joblib` + `xss_escaping_model.joblib`
- **SQLi**: Uses rule-based ranking (no ML)
- **Redirect**: Uses rule-based ranking (no ML)

### Full-Smart Strategy  
- **XSS**: Uses `family_xss.joblib` + context models
- **SQLi**: Uses `family_sqli.joblib` (if available)
- **Redirect**: Uses `family_redirect.joblib` (if available)

### Rules-Only Strategy
- **All families**: No ML models used, rule-based only

## Model Training Data

The models are trained on:
- **Synthetic data**: Generated using `synthesize_training.py`
- **Real evidence data**: From actual vulnerability assessments
- **Cross-validation**: K-fold validation for robust evaluation
- **Feature selection**: Mutual information-based selection
- **Hyperparameter tuning**: GridSearchCV optimization

## Model Performance and Fallbacks

### Graceful Degradation
```python
# If ML model fails to load, use mock model
if model is None:
    mock_model = MockMLModel()
    _model_cache[family] = mock_model
    return mock_model

# If features can't be extracted, fall back to defaults
if feature_vector is None:
    return _get_default_payloads(fam)
```

### Honest Reporting
```python
ml_state = {
    "rank_source": "ml" if model_used else "defaults",
    "ranker_active": model_used,
    "classifier_used": model_used and p_cal is not None,
    "p_cal": p_cal if classifier_used else None,
    "skip_reason": "model_unavailable" if not model_used else None
}
```

This comprehensive ML system provides intelligent payload ranking, context-aware XSS detection, and parameter prioritization while maintaining honest reporting about when and how ML is used.
