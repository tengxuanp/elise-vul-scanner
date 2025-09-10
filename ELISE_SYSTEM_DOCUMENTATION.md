# Elise Vulnerability Scanner - System Documentation

## Overview

Elise is a comprehensive web application vulnerability scanner that combines traditional probing techniques with machine learning to detect Cross-Site Scripting (XSS), SQL Injection (SQLi), and Open Redirect vulnerabilities. The system features a hybrid rule-ML approach with context-aware payload selection and advanced ML-based vulnerability detection.

## Architecture

### System Components

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │   Backend       │    │   ML Models     │
│   (Next.js)     │◄──►│   (FastAPI)     │◄──►│   (scikit-learn)│
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   UI Components │    │   Core Engine   │    │   Context ML    │
│   - CrawlForm   │    │   - Fuzzer      │    │   - XSS Context │
│   - SummaryPanel│    │   - Probes      │    │   - Escaping    │
│   - FindingsTable│   │   - Injections  │    │   - Ranking     │
│   - EvidenceModal│   │   - Evidence    │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Technology Stack

**Frontend:**
- Next.js 15 (App Router)
- React 18
- Tailwind CSS
- React Query for state management

**Backend:**
- FastAPI
- Python 3.12
- Pydantic for data validation
- Playwright for web crawling
- httpx for HTTP requests

**Machine Learning:**
- scikit-learn
- XGBoost
- joblib for model persistence
- TF-IDF vectorization
- Logistic Regression with calibration

## Core Workflow

### 1. Crawling Phase

**Endpoint:** `POST /api/crawl`

The system starts by crawling the target website to discover endpoints and parameters:

```python
# Crawl configuration
{
    "job_id": "unique-job-id",
    "target_url": "http://example.com",
    "crawl_opts": {
        "max_depth": 2,
        "max_endpoints": 30,
        "submit_get_forms": true,
        "submit_post_forms": true,
        "click_buttons": true
    }
}
```

**Process:**
1. **Playwright Crawler** navigates the site using headless browser
2. **Form Discovery** finds GET/POST forms and extracts parameters
3. **Link Following** follows internal links up to max_depth
4. **Endpoint Enumeration** creates target list with method, path, parameters
5. **Persistence** saves discovered endpoints to `backend/data/jobs/{job_id}/endpoints.json`

**Output:**
```json
{
    "job_id": "unique-job-id",
    "mode": "crawl_only",
    "endpoints_count": 15,
    "endpoints": [
        {
            "method": "GET",
            "path": "http://example.com/search",
            "param_in": "query",
            "param": "q"
        }
    ],
    "persisted": true,
    "path": "/data/jobs/unique-job-id/endpoints.json"
}
```

### 2. Assessment Phase

**Endpoint:** `POST /api/assess`

The system performs vulnerability assessment using multiple strategies:

```python
# Assessment configuration
{
    "job_id": "unique-job-id",
    "strategy": "ml_with_context",
    "xss_ctx_invoke": "force_ml",
    "top_k": 3
}
```

## Scan Strategies

### Available Strategies

1. **`auto`** - Default strategy, uses probes + ML injections
2. **`probe_only`** - Only traditional probes, no injections
3. **`ml_only`** - Only ML-based injections, no probes
4. **`ml_with_context`** - ML injections with XSS context classification
5. **`hybrid`** - Probes + ML injections with context awareness

### Strategy Behavior

```python
@dataclass
class Plan:
    name: ScanStrategy
    probes_disabled: Set[str]  # {"xss", "redirect", "sqli"}
    allow_injections: bool
    force_ctx_inject_on_probe: bool
```

**Strategy Matrix:**
| Strategy | Probes | Injections | Context ML | Use Case |
|----------|--------|------------|------------|----------|
| `auto` | All families | Yes | No | General scanning |
| `probe_only` | All families | No | No | Quick reconnaissance |
| `ml_only` | None | Yes | No | ML-focused scanning |
| `ml_with_context` | XSS only | Yes | Yes | Advanced XSS detection |
| `hybrid` | All families | Yes | Yes | Comprehensive scanning |

## Vulnerability Detection

### 1. XSS (Cross-Site Scripting)

**Detection Methods:**
- **Canary Probing**: Injects unique canary strings and detects reflection
- **Context Classification**: ML-based context detection (HTML body, attributes, JS strings)
- **Escaping Analysis**: ML-based escaping detection (raw, HTML-escaped, JS-escaped)
- **Payload Ranking**: Context-aware payload selection

**XSS Context Classifier:**
```python
# ML models for XSS context detection
- xss_context_model.joblib      # Context classification
- xss_context_vectorizer.joblib # TF-IDF vectorizer
- xss_escaping_model.joblib     # Escaping classification
- xss_escaping_vectorizer.joblib # TF-IDF vectorizer
```

**Context Types:**
- `html_body` - Direct HTML content
- `attr` - HTML attribute values
- `js_string` - JavaScript string literals
- `js_comment` - JavaScript comments

**Escaping Types:**
- `raw` - No escaping applied
- `html_escaped` - HTML entities encoded
- `js_escaped` - JavaScript escaping applied

**Payload Categories:**
```python
XSS_TAG = [
    "<svg onload=alert(1)>",      # Most reliable
    "<img src=x onerror=alert(1)>", # Classic
    "<script>alert(1)</script>"    # Traditional
]

XSS_ATTR = [
    "\" onmouseover=\"alert(1)\" x=\"",  # Attribute breakout
    "' onfocus='alert(1)' x='",          # Single quote variant
]

XSS_JS = [
    "';alert(1);//",              # JS string termination
    "\";alert(1);//",             # Double quote variant
]
```

### 2. SQL Injection (SQLi)

**Detection Methods:**
- **Boolean-based**: OR conditions, tautologies
- **Union-based**: UNION SELECT statements
- **Time-based**: SLEEP/WAITFOR DELAY functions
- **Error-based**: Syntax errors and type coercion

**SQLi Payload Categories:**
```python
SQLI_BOOLEAN = [
    "' OR '1'='1' --",
    "\" OR 1=1 --",
    "') OR ('1'='1"
]

SQLI_UNION = [
    "' UNION SELECT NULL-- ",
    "' UNION SELECT NULL,NULL-- "
]

SQLI_TIME = [
    "1 AND SLEEP(3)--",           # MySQL
    "1;SELECT pg_sleep(3)--",     # PostgreSQL
    "';WAITFOR DELAY '0:0:3'--"   # SQL Server
]
```

### 3. Open Redirect

**Detection Methods:**
- **External Domain Detection**: Checks for external domain redirects
- **Protocol Validation**: Validates redirect URLs
- **Parameter Analysis**: Analyzes redirect parameters

**Redirect Payloads:**
```python
REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>"
]
```

## Machine Learning System

### Enhanced ML Architecture

The system includes both legacy and enhanced ML components:

**Legacy ML:**
- Basic feature extraction (17 features)
- Simple probability scoring
- Basic payload ranking

**Enhanced ML:**
- Advanced feature engineering (48 features)
- Confidence calibration
- Uncertainty quantification
- Context-aware ranking

### Feature Engineering

**Endpoint Features:**
```python
# Basic features (17)
- Parameter name patterns
- URL path analysis
- HTTP method
- Parameter position
- Form type detection

# Enhanced features (48)
- Semantic parameter analysis
- Business context detection
- Security pattern recognition
- Cross-parameter relationships
- Historical context
```

**XSS Context Features:**
```python
# TF-IDF vectorization of:
- Surrounding HTML context
- Parameter reflection points
- Escaping patterns
- JavaScript context
```

### Model Training

**Training Pipeline:**
1. **Data Collection**: Evidence logs and synthetic data
2. **Feature Extraction**: Endpoint + payload features
3. **Label Generation**: Hard/soft positive, negative labels
4. **Model Training**: XGBoost, Logistic Regression
5. **Calibration**: Platt scaling, isotonic regression
6. **Validation**: Cross-validation with NDCG@3, Hit@1/3/5

**Model Files:**
```
backend/modules/ml/models/
├── family_xss.joblib           # XSS family model
├── family_xss.cal.json         # XSS calibration data
├── family_sqli.joblib          # SQLi family model
├── family_sqli.cal.json        # SQLi calibration data
├── family_redirect.joblib      # Redirect family model
├── family_redirect.cal.json    # Redirect calibration data
├── xss_context_model.joblib    # XSS context classifier
├── xss_context_vectorizer.joblib
├── xss_escaping_model.joblib   # XSS escaping classifier
└── xss_escaping_vectorizer.joblib
```

## Core Engine Components

### 1. Fuzzer Core (`fuzzer_core.py`)

**Main Functions:**
- `run_job()` - Orchestrates the entire assessment process
- `_process_target()` - Processes individual targets
- Target enumeration and parallel processing
- Event aggregation and telemetry

**Key Classes:**
```python
class Target:
    url: str
    method: str
    param_in: str  # "query", "form", "json", "header"
    param: str
    headers: Dict[str, str]

class DECISION:
    POSITIVE = "positive"
    SUSPECTED = "suspected" 
    ABSTAIN = "abstain"
    NOT_APPLICABLE = "not_applicable"
```

### 2. Probe Engine (`probes/engine.py`)

**Probe Types:**
- **XSS Canary Probe** (`xss_canary.py`) - XSS detection with context analysis
- **SQLi Probe** (`sqli_probe.py`) - SQL injection detection
- **Redirect Probe** (`redirect_probe.py`) - Open redirect detection

**XSS Canary Process:**
1. Inject unique canary string
2. Analyze response for reflection
3. Classify context using ML (if available)
4. Determine escaping type
5. Select context-appropriate payloads

### 3. Injection Engine (`injector.py`)

**Injection Process:**
1. **Payload Selection**: ML-ranked or context-filtered payloads
2. **Request Injection**: Inject payload into target parameter
3. **Response Analysis**: Analyze response for vulnerability indicators
4. **Confirmation**: Confirm vulnerability using multiple signals

**Payload Ranking:**
```python
def rank_payloads(family: str, target: Target, top_k: int = 3) -> List[str]:
    # 1. Extract endpoint features
    features = extract_features(target)
    
    # 2. Get ML predictions for each payload
    predictions = ml_predict(features, family)
    
    # 3. Rank by ML probability
    ranked = sorted(predictions, key=lambda x: x.probability, reverse=True)
    
    # 4. Return top-k payloads
    return [p.payload for p in ranked[:top_k]]
```

### 4. Evidence System (`evidence.py`)

**Evidence Types:**
- **Probe Evidence**: Canary reflection, context analysis
- **Injection Evidence**: Payload injection results
- **Confirmation Evidence**: Vulnerability confirmation signals

**Evidence Structure:**
```python
@dataclass
class EvidenceRow:
    family: str
    method: str
    path: str
    param_in: str
    param: str
    decision: str
    provenance: str  # "Probe" or "Inject"
    why: List[str]   # Detection reasons
    cvss: Dict[str, Any]
    evidence_id: str
    rank_source: str  # "ml", "ctx_pool", "probe_only", "ml_ranked"
    ml_proba: Optional[float]
    attempt_idx: int
    top_k_used: int
    timing_ms: int
    xss_context: Optional[str]
    xss_escaping: Optional[str]
    xss_context_source: Optional[str]  # "ml" or "rule"
```

## Frontend Components

### 1. Crawl Form (`CrawlForm.jsx`)

**Features:**
- URL input with validation
- Max depth configuration (0-10)
- Authentication modes (none, cookie, bearer, form, manual)
- Real-time crawl progress

**Authentication Support:**
```javascript
// Cookie authentication
auth: { mode: "cookie", cookie: "sid=abc; jwt=eyJ..." }

// Bearer token
auth: { mode: "bearer", bearer_token: "eyJ..." }

// Form login
auth: { 
    mode: "form", 
    login_url: "/login",
    username_field: "username",
    password_field: "password",
    username: "admin",
    password: "password"
}
```

### 2. Summary Panel (`SummaryPanel.jsx`)

**Displays:**
- **Assessment Summary**: Total endpoints, positives, suspected, abstain
- **Strategy Information**: Current strategy, ML status, model availability
- **XSS Context Analysis**: Context distribution, ML invocation stats
- **Performance Metrics**: Processing time, attempts saved, efficiency
- **Diagnostics**: Model availability, thresholds, health status

**Key Metrics:**
```javascript
{
    "total": 15,
    "positive": 3,
    "suspected": 1,
    "abstain": 2,
    "na": 9,
    "confirmed_probe": 0,
    "confirmed_ml_inject": 3
}
```

### 3. Findings Table (`FindingsTable.jsx`)

**Features:**
- Sortable vulnerability results
- Family-based filtering (XSS, SQLi, Redirect)
- Decision-based filtering (positive, suspected, abstain)
- Evidence modal integration
- Export functionality

**Table Columns:**
- **Family**: Vulnerability type (XSS, SQLi, Redirect)
- **Method**: HTTP method (GET, POST)
- **Path**: Target URL path
- **Parameter**: Parameter name and location
- **Decision**: Assessment result
- **CVSS**: Severity score
- **Evidence**: Detailed evidence modal

### 4. Evidence Modal (`EvidenceModal.jsx`)

**Tabs:**
1. **Overview**: Basic vulnerability information
2. **Request/Response**: HTTP request and response details
3. **Why Vulnerable**: Detection method explanations
4. **Context Analysis**: XSS context and escaping details
5. **ML Details**: Machine learning predictions and confidence

**Evidence Details:**
```javascript
{
    "family": "xss",
    "method": "GET",
    "path": "http://example.com/search",
    "param_in": "query",
    "param": "q",
    "decision": "positive",
    "provenance": "Inject",
    "why": ["ctx_guided", "xss_reflection"],
    "cvss": {
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "base": 6.1
    },
    "rank_source": "ctx_pool",
    "ml_proba": 0.87,
    "xss_context": "html_body",
    "xss_escaping": "raw",
    "xss_context_source": "ml"
}
```

## Data Flow

### 1. Crawling Flow
```
User Input → CrawlForm → /api/crawl → Playwright Crawler → Endpoint Discovery → Persistence
```

### 2. Assessment Flow
```
Crawled Endpoints → /api/assess → Strategy Planning → Target Processing → Probe/Injection → Evidence Collection → Results Aggregation
```

### 3. ML Inference Flow
```
Target Features → Feature Extraction → ML Prediction → Confidence Calibration → Payload Ranking → Context Selection
```

## Configuration

### Environment Variables

```bash
# Core settings
ELISE_DEFAULT_STRATEGY=auto
ELISE_JOB_BUDGET_MS=120000
ELISE_TOP_K_DEFAULT=3

# ML settings
ELISE_USE_ML=true
ELISE_REQUIRE_RANKER=true
ELISE_XSS_TAU=0.75
ELISE_SQLI_TAU=0.5
ELISE_REDIRECT_TAU=0.6

# Data paths
ELISE_DATA_DIR=/path/to/data
ELISE_MODEL_DIR=/path/to/models
```

### Strategy Configuration

```python
# Strategy behavior configuration
STRATEGY_CONFIG = {
    "auto": {
        "probes_disabled": set(),
        "allow_injections": True,
        "force_ctx_inject_on_probe": False
    },
    "ml_with_context": {
        "probes_disabled": {"redirect", "sqli"},
        "allow_injections": True,
        "force_ctx_inject_on_probe": True
    }
}
```

## Performance Metrics

### Key Performance Indicators

1. **Detection Accuracy**: True positive rate for each vulnerability family
2. **False Positive Rate**: Incorrect positive detections
3. **Processing Speed**: Endpoints processed per minute
4. **ML Efficiency**: Context-guided payload success rate
5. **Resource Usage**: Memory and CPU utilization

### Metrics Collection

```python
# Telemetry metrics
{
    "xss_reflections_total": 5,
    "xss_ml_invoked": 5,
    "xss_final_from_ml": 5,
    "xss_context_dist": {"html_body": 3, "attr": 1, "js_string": 1},
    "xss_ctx_pool_used": 5,
    "xss_first_hit_attempts_ctx": 5,
    "xss_first_hit_attempts_baseline": 15,
    "xss_first_hit_attempts_used": 5,
    "attempts_saved": 10
}
```

## Security Considerations

### Responsible Disclosure
- All payloads are designed for authorized testing only
- System includes safeguards against accidental misuse
- Clear warnings about legal and ethical use

### Payload Safety
- Payloads are designed to be non-destructive
- No data exfiltration or system modification
- Minimal impact on target systems

### Authentication Handling
- Secure credential storage during assessment
- Automatic cleanup of sensitive data
- Support for various authentication mechanisms

## API Reference

### Crawl API
```http
POST /api/crawl
Content-Type: application/json

{
    "job_id": "string",
    "target_url": "string",
    "crawl_opts": {
        "max_depth": 2,
        "max_endpoints": 30
    }
}
```

### Assessment API
```http
POST /api/assess
Content-Type: application/json

{
    "job_id": "string",
    "strategy": "ml_with_context",
    "xss_ctx_invoke": "force_ml",
    "top_k": 3
}
```

### Health Check API
```http
GET /api/healthz
```

Returns system health, model availability, and configuration status.

## Troubleshooting

### Common Issues

1. **ML Models Not Available**
   - Check model files in `backend/modules/ml/models/`
   - Run training scripts to generate models
   - Verify model file permissions

2. **Crawling Failures**
   - Check target URL accessibility
   - Verify authentication credentials
   - Review Playwright browser configuration

3. **Assessment Timeouts**
   - Adjust `ELISE_JOB_BUDGET_MS` setting
   - Reduce `max_endpoints` in crawl options
   - Check network connectivity

4. **False Positives**
   - Adjust ML thresholds (`ELISE_XSS_TAU`, etc.)
   - Review payload selection logic
   - Validate confirmation signals

### Debug Mode

Enable debug logging:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Future Enhancements

### Planned Features
1. **Additional Vulnerability Types**: CSRF, SSRF, XXE
2. **Advanced ML Models**: Deep learning, transformer-based
3. **API Security Testing**: GraphQL, REST API specific tests
4. **Cloud Integration**: AWS, Azure, GCP deployment support
5. **CI/CD Integration**: GitHub Actions, Jenkins plugins

### Performance Optimizations
1. **Parallel Processing**: Multi-threaded target processing
2. **Caching**: Response caching for repeated requests
3. **Streaming**: Real-time result streaming
4. **Database Integration**: Persistent result storage

This documentation provides a comprehensive overview of the Elise vulnerability scanner system, covering all major components, workflows, and technical details needed for understanding and extending the system.
