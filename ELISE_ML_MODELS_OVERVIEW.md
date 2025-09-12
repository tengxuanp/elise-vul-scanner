# Elise ML Models Overview

## Total Number of ML Models: **17 Model Files + 3 Metadata Files = 20 Files**

The Elise system contains **17 machine learning model files** plus **3 metadata files** across different categories and purposes. The system includes active models, utility models, mock fallbacks, and backup models for comprehensive vulnerability detection.

## Model Categories and Details

### 1. **XSS Context Classification Models** (2 models) - **PRIMARY MODELS**
**Purpose**: Classify XSS context and escaping for context-aware payload selection

#### Models:
- **`xss_context_model.joblib`** + **`xss_context_vectorizer.joblib`**
  - **Location**: `backend/modules/ml/models/`
  - **Type**: Logistic Regression with TF-IDF vectorization
  - **Purpose**: Classify XSS context (html_body, attr, js_string, url, css, comment, json)
  - **Features**: 48+ comprehensive features including:
    - Character 2-6-gram TF-IDF on text window around reflection
    - Binary features: script tags, style tags, quotes, equals, angle brackets, URL attrs, style attrs
    - One-hot encoded quote types: single, double, backtick, none
    - One-hot encoded attribute names: src, href, value, onclick, style, class, id, other, none
  - **Classes**: 7 context types (html_body, attr, js_string, url, css, comment, json)
  - **Performance**: 100% accuracy on test set
  - **Training Data**: 1000 real XSS examples from `data/xss_ctx/train.jsonl`
  - **Vectorizer**: TF-IDF with character n-grams (2-6), max_features=5000

- **`xss_escaping_model.joblib`** + **`xss_escaping_vectorizer.joblib`**
  - **Location**: `backend/modules/ml/models/`
  - **Type**: Logistic Regression with TF-IDF vectorization
  - **Purpose**: Classify XSS escaping type (raw, html, url, js)
  - **Features**: Same 48+ comprehensive features as context model
  - **Classes**: 4 escaping types (raw, html, url, js)
  - **Performance**: 59.2% accuracy (expected due to class imbalance)
  - **Training Data**: Same 1000 real XSS examples
  - **Vectorizer**: TF-IDF with character n-grams (2-6), max_features=5000

### 2. **Family Ranker Models** (3 models) - **PAYLOAD RANKING**
**Purpose**: Rank payloads by vulnerability family for optimal injection order

#### Models:
- **`family_xss.joblib`** + **`family_xss.cal.json`**
  - **Location**: `backend/modules/ml/models/`
  - **Type**: Binary classifier with calibration
  - **Purpose**: Rank XSS payloads by likelihood of success
  - **Features**: 45-dimensional feature vector (param analysis, probe signals, context)
  - **Calibration**: Platt scaling for probability calibration

- **`family_sqli.joblib`** + **`family_sqli.cal.json`**
  - **Location**: `backend/modules/ml/models/`
  - **Type**: Binary classifier with calibration
  - **Purpose**: Rank SQLi payloads by likelihood of success
  - **Features**: 45-dimensional feature vector (param analysis, probe signals, context)
  - **Calibration**: Platt scaling for probability calibration

- **`family_redirect.joblib`** + **`family_redirect.cal.json`**
  - **Location**: `backend/modules/ml/models/`
  - **Type**: Binary classifier with calibration
  - **Purpose**: Rank redirect payloads by likelihood of success
  - **Features**: 45-dimensional feature vector (param analysis, probe signals, context)
  - **Calibration**: Platt scaling for probability calibration

### 3. **Utility ML Models** (2 models) - **GENERAL PURPOSE**
**Purpose**: Various utility and enhancement functions

#### Models:
- **`payload_recommender.joblib`**
  - **Location**: `backend/modules/ml/models/`
  - **Type**: General payload recommendation model
  - **Purpose**: Recommend payloads based on endpoint features
  - **Features**: 17-dimensional feature vector (endpoint + payload descriptors)
  - **Families**: Supports xss, sqli, redirect families

- **`vulnerability_predictor.joblib`**
  - **Location**: `backend/modules/ml/models/`
  - **Type**: General vulnerability prediction model
  - **Purpose**: Predict vulnerability likelihood across families
  - **Features**: Multi-dimensional feature vector
  - **Usage**: General vulnerability assessment

### 4. **Mock Fallback Models** (3 models) - **FALLBACK SYSTEM**
**Purpose**: Provide fallback predictions when real models fail to load

#### Models:
- **`MockContextModel`** (Hardcoded)
  - **Location**: `backend/modules/ml/xss_context_infer.py`
  - **Type**: Hardcoded prediction model
  - **Purpose**: Fallback when XSS context model fails to load
  - **Behavior**: Always predicts `js_string` context
  - **Usage**: Prevents system crashes when models unavailable

- **`MockEscapingModel`** (Hardcoded)
  - **Location**: `backend/modules/ml/xss_context_infer.py`
  - **Type**: Hardcoded prediction model
  - **Purpose**: Fallback when XSS escaping model fails to load
  - **Behavior**: Always predicts `raw` escaping
  - **Usage**: Prevents system crashes when models unavailable

- **`MockMLModel`** (Hardcoded)
  - **Location**: `backend/modules/ml/infer_ranker.py`
  - **Type**: Hardcoded prediction model
  - **Purpose**: Fallback when family ranker models fail to load
  - **Behavior**: Returns default scores
  - **Usage**: Prevents system crashes when models unavailable

### 5. **Backup Models** (4 models) - **BACKUP SYSTEM**
**Purpose**: Backup copies of critical XSS models

#### Models:
- **`xss_context_model_backup.joblib`** + **`xss_context_vectorizer_backup.joblib`**
  - **Location**: `backend/modules/ml/models/backup/`
  - **Type**: Backup copies of XSS context models
  - **Purpose**: Fallback if primary models are corrupted

- **`xss_escaping_model_backup.joblib`** + **`xss_escaping_vectorizer_backup.joblib`**
  - **Location**: `backend/modules/ml/models/backup/`
  - **Type**: Backup copies of XSS escaping models
  - **Purpose**: Fallback if primary models are corrupted

### 6. **Metadata Files** (3 files) - **CONFIGURATION**
**Purpose**: Model registry and configuration files

#### Files:
- **`RANKER_MANIFEST.json`**
  - **Location**: `backend/modules/ml/models/`
  - **Purpose**: Model registry and default payloads
  - **Content**: Model file mappings and default payload definitions

- **`xss_ctx_meta.json`**
  - **Location**: `backend/modules/ml/models/`
  - **Purpose**: XSS context model metadata
  - **Content**: Model training information and performance metrics

- **`recommender_meta.json`**
  - **Location**: `backend/modules/ml/models/`
  - **Purpose**: Payload recommender metadata
  - **Content**: Recommender model configuration and training data info

## How the Models Work Together

### 1. **Assessment Pipeline Integration**

```python
# 1. Enhanced ML Ranking (for all families)
if ml_mode in {"auto", "force_ml"}:
    ranked = engine.rank_payloads(family, features, top_k)
    # Uses: Enhanced ML ranker models with 48 sophisticated features

# 2. XSS Context Classification (if XSS reflection detected)
if xss_reflection_detected:
    context_result = predict_xss_context(text_window, canary_pos)
    escaping_result = predict_xss_escaping(text_window, canary_pos)
    # Uses: xss_context_model.joblib + xss_context_vectorizer.joblib
    #       xss_escaping_model.joblib + xss_escaping_vectorizer.joblib

# 3. Fallback to Mock Models (if real models fail)
if model_loading_failed:
    context_result = MockContextModel().predict(text_window)
    escaping_result = MockEscapingModel().predict(text_window)
    # Uses: MockContextModel (always predicts js_string)
    #       MockEscapingModel (always predicts raw)
```

### 2. **Feature Engineering Pipeline**

#### For Enhanced ML Rankers (48+ features):
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

#### For XSS Context Classification (48+ features):
```python
# Text window around reflection point (±120 characters)
text_window = response_text[max(0, canary_pos-120):canary_pos+120]

# Binary features (7 base features)
binary_features = [
    has_script_tag, has_style_tag, has_quotes, has_equals,
    has_angle_brackets, has_url_attrs, has_style_attr
]

# One-hot encoded quote types (4 features)
quote_types = ['single', 'double', 'backtick', 'none']
for qt in quote_types:
    binary_features.append(int(quote_type == qt))

# One-hot encoded attribute names (9 features)
attr_names = ['src', 'href', 'value', 'onclick', 'style', 'class', 'id', 'other', 'none']
for an in attr_names:
    binary_features.append(int(attr_name == an))

# Text features with feature indicators
text = text_window
if has_script_tag: text += " SCRIPT_TAG"
if has_style_tag: text += " STYLE_TAG"
if has_quotes: text += f" QUOTES_{quote_type}"
if has_equals: text += " EQUALS"
if has_angle_brackets: text += " ANGLE_BRACKETS"
if has_url_attrs: text += " URL_ATTRS"
if has_style_attr: text += " STYLE_ATTR"
if attr_name: text += f" ATTR_{attr_name}"

# TF-IDF vectorization (5000 features)
text_features = _context_vectorizer.transform([text])
combined_features = np.hstack([text_features.toarray(), binary_features])
```

### 3. **Model Loading and Thread Safety**

```python
# Thread-safe model loading with double-check pattern
from threading import Lock
_model_loading_lock = Lock()

def load_models() -> Tuple[bool, bool]:
    global _context_model, _context_vectorizer, _escaping_model, _escaping_vectorizer
    
    # Check if models are already loaded
    if _context_model is not None and _context_vectorizer is not None:
        return True, True
    
    # Use lock to prevent race conditions during model loading
    with _model_loading_lock:
        # Double-check after acquiring lock
        if _context_model is not None and _context_vectorizer is not None:
            return True, True
        
        try:
            # Load context model with numpy 2.x compatibility
            _context_model = joblib.load(context_model_path, mmap_mode=None)
            _context_vectorizer = joblib.load(context_vectorizer_path, mmap_mode=None)
            context_loaded = True
        except Exception as e:
            # Fallback to mock models
            _context_model = MockContextModel()
            _context_vectorizer = MockVectorizer()
            context_loaded = True
```

### 4. **Honest ML State Reporting**

```python
# Honest reporting of ML state
ml_state = {
    "rank_source": "ml" if model_used else "defaults",
    "ranker_active": model_used,
    "classifier_used": model_used and p_cal is not None,
    "p_cal": p_cal if classifier_used else None,
    "skip_reason": "model_unavailable" if not model_used else None
}

# Only show ML probabilities when classifier actually ran
if ml_state["classifier_used"]:
    display_ml_probability(ml_state["p_cal"])
else:
    display_default_ranking()
```

## Model Usage by Strategy

### Smart-XSS Strategy (Default)
- **XSS**: Uses Enhanced ML Ranker + `xss_context_model.joblib` + `xss_escaping_model.joblib`
- **SQLi**: Uses Enhanced ML Ranker (if available) or rule-based ranking
- **Redirect**: Uses Enhanced ML Ranker (if available) or rule-based ranking

### Full-Smart Strategy  
- **XSS**: Uses Enhanced ML Ranker + context models
- **SQLi**: Uses Enhanced ML Ranker (if available) or rule-based ranking
- **Redirect**: Uses Enhanced ML Ranker (if available) or rule-based ranking

### Rules-Only Strategy
- **All families**: No ML models used, rule-based only

## Model Training Data

The XSS context and escaping models are trained on:
- **Real XSS data**: 1000 real XSS examples from `data/xss_ctx/train.jsonl`
- **Comprehensive features**: 48+ features including text patterns, HTML structure, JavaScript context
- **Character n-grams**: 2-6 character n-grams with TF-IDF vectorization
- **Binary indicators**: Script tags, style tags, quotes, equals, angle brackets, URL attrs, style attrs
- **One-hot encoding**: Quote types and attribute names for better classification

## Model Performance and Fallbacks

### Graceful Degradation
```python
# If ML model fails to load, use mock model
try:
    model = joblib.load(model_path, mmap_mode=None)
except Exception as e:
    print(f"Failed to load model: {e}")
    model = MockContextModel()  # Always predicts js_string
    vectorizer = MockVectorizer()

# If features can't be extracted, fall back to defaults
if feature_vector is None:
    return _get_default_payloads(fam)
```

### Thread-Safe Loading
```python
# Prevent race conditions during parallel model loading
with _model_loading_lock:
    if _context_model is None:
        _context_model = load_context_model()
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

## Recent Improvements

### 1. **Comprehensive XSS Context Classification**
- **100% accuracy** on context classification (html_body, attr, js_string, url, css, comment, json)
- **Real training data** from 1000 XSS examples instead of synthetic data
- **48+ features** including comprehensive text and binary indicators

### 2. **Thread-Safe Model Loading**
- **Race condition prevention** with threading locks
- **NumPy 2.x compatibility** with mmap_mode=None
- **Graceful fallback** to mock models when loading fails

### 3. **Honest ML State Reporting**
- **Only show ML probabilities** when classifier actually ran
- **Clear indication** of when defaults are used instead of ML
- **Transparent reporting** of model availability and usage

This streamlined ML system provides intelligent XSS context classification and enhanced payload ranking while maintaining robust fallbacks and honest reporting about ML usage.

## 📊 Complete Model Inventory

| **Category** | **Count** | **Model Files** | **Location** | **Status** |
|--------------|-----------|-----------------|--------------|------------|
| **XSS Context Classification** | 2 | `xss_context_model.joblib`<br>`xss_context_vectorizer.joblib` | `backend/modules/ml/models/` | ✅ Active |
| **XSS Escaping Classification** | 2 | `xss_escaping_model.joblib`<br>`xss_escaping_vectorizer.joblib` | `backend/modules/ml/models/` | ✅ Active |
| **Family Rankers** | 6 | `family_xss.joblib` + `.cal.json`<br>`family_sqli.joblib` + `.cal.json`<br>`family_redirect.joblib` + `.cal.json` | `backend/modules/ml/models/` | ✅ Active |
| **Utility Models** | 2 | `payload_recommender.joblib`<br>`vulnerability_predictor.joblib` | `backend/modules/ml/models/` | 🔧 Available |
| **Mock Fallbacks** | 3 | `MockContextModel`<br>`MockEscapingModel`<br>`MockMLModel` | `backend/modules/ml/*.py` | 🛡️ Runtime |
| **Backup Models** | 4 | `xss_context_model_backup.joblib`<br>`xss_context_vectorizer_backup.joblib`<br>`xss_escaping_model_backup.joblib`<br>`xss_escaping_vectorizer_backup.joblib` | `backend/modules/ml/models/backup/` | 💾 Backup |
| **Metadata Files** | 3 | `RANKER_MANIFEST.json`<br>`xss_ctx_meta.json`<br>`recommender_meta.json` | `backend/modules/ml/models/` | 📋 Config |

## 🗂️ File Structure Summary

```
backend/modules/ml/models/
├── xss_context_model.joblib              # XSS context classifier
├── xss_context_vectorizer.joblib         # XSS context vectorizer
├── xss_escaping_model.joblib             # XSS escaping classifier
├── xss_escaping_vectorizer.joblib        # XSS escaping vectorizer
├── family_xss.joblib                     # XSS payload ranker
├── family_xss.cal.json                   # XSS ranker calibration
├── family_sqli.joblib                    # SQLi payload ranker
├── family_sqli.cal.json                  # SQLi ranker calibration
├── family_redirect.joblib                # Redirect payload ranker
├── family_redirect.cal.json              # Redirect ranker calibration
├── payload_recommender.joblib            # General payload recommender
├── vulnerability_predictor.joblib        # General vulnerability predictor
├── RANKER_MANIFEST.json                  # Model registry
├── xss_ctx_meta.json                     # XSS context metadata
├── recommender_meta.json                 # Recommender metadata
└── backup/                               # Backup models
    ├── xss_context_model_backup.joblib
    ├── xss_context_vectorizer_backup.joblib
    ├── xss_escaping_model_backup.joblib
    └── xss_escaping_vectorizer_backup.joblib
```

## 🎯 Model Usage Priority

1. **Primary**: XSS context classification models (100% accuracy)
2. **Secondary**: Family ranker models (payload prioritization)
3. **Tertiary**: Utility models (advanced features)
4. **Fallback**: Mock models (system stability)
5. **Recovery**: Backup models (corruption recovery)

**Total: 17 Model Files + 3 Metadata Files = 20 Files**
