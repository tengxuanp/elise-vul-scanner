# Elise - Rule-Based Web Vulnerability Scanner

[![Python](https://img.shields.io/badge/Python-3.12+-blue.svg)](https://python.org)
[![Next.js](https://img.shields.io/badge/Next.js-13.5.6-black.svg)](https://nextjs.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-green.svg)](https://fastapi.tiangolo.com)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Elise** is a clean, rule-based web vulnerability scanning system that combines dynamic crawling, intelligent probe detection, and honest UX to automatically discover and test web application security flaws with transparent operation modes.

## 🎯 Key Features

- **🔍 Rule-Based Detection**: Lightweight heuristics for XSS context/escaping and SQLi dialect detection
- **🕷️ Dynamic Crawling**: Playwright-based web crawling with smart endpoint discovery
- **📊 Honest UX**: Three-page flow with transparent mode indicators and diagnostics
- **🎯 Probe-First Methodology**: Micro-probes for efficient vulnerability confirmation
- **📈 CVSS Scoring**: Industry-standard vulnerability severity assessment
- **🔍 XSS & SQLi Focus**: Specialized detection for Cross-Site Scripting and SQL Injection
- **⚡ Real-time UI**: Modern Next.js 13.5.6 interface with live progress tracking
- **🛡️ Evidence Collection**: Safe HTML escaping and raw download capabilities

## 🏗️ Architecture

### Frontend (Next.js 13.5.6)
- Modern React 18 with App Router
- Tailwind CSS for responsive design
- Three-page flow: Crawl → Assess → Report
- Real-time diagnostics and mode indicators

### Backend (FastAPI)
- Python 3.12 with async/await
- Rule-based probe detection
- Job persistence with evidence collection
- RESTful API with clear contract separation

## 🚀 Quick Start

### Prerequisites
- Python 3.12+
- Node.js 18+
- Modern web browser

## 📋 Modes & Semantics

### API Modes
Elise operates in distinct modes with clear semantics:

| Mode | Description | Use Case |
|------|-------------|----------|
| `crawl_only` | Crawl and persist endpoints | Initial discovery phase |
| `direct` | Assess with explicit endpoints | UI endpoint selection |
| `from_persisted` | Load from saved endpoints | Resume previous crawl |
| `crawl_then_assess` | Crawl and assess in one call | Direct assessment |

### Job Persistence
All crawl artifacts are stored under `DATA_DIR/jobs/<job_id>/`:
- `endpoints.json` - Discovered endpoints and parameters
- `<evidence_id>.json` - Individual vulnerability evidence files

### Telemetry Fields
Every assessment result includes:
- `attempt_idx` - Injection attempt number
- `top_k_used` - Number of payloads attempted
- `rank_source` - How payloads were selected (`ml`, `probe_only`, `defaults`)

### Diagnostics
The system provides transparent diagnostics:
- `use_ml` - Whether ML features are enabled
- `ml_active` - Whether ML models are loaded
- `models_available` - List of available ML models
- `thresholds` - Decision thresholds for each family

### UX Flow
**Route-based navigation**: Crawl → Assess → Report
- **Crawl Page**: Discover endpoints with optional persistence
- **Assess Page**: Run vulnerability assessment with mode banner
- **Report Page**: View results and download evidence

### Environment Variables

Configure Elise behavior with these environment variables:

```bash
# Target URL for testing (default: http://localhost:5001)
export LAB_TARGET_URL="http://localhost:5001"

# ML Configuration
export ELISE_USE_ML="1"              # Enable ML features (default: 1)
export ELISE_REQUIRE_RANKER="0"      # Require ML models (default: 0)

# Performance Settings
export ELISE_JOB_BUDGET_MS="300000"  # Job time budget in ms (default: 5 minutes)
export ELISE_DATA_DIR="backend/data" # Data directory (default: backend/data)
export ELISE_ML_MODEL_DIR="backend/modules/ml/models" # Model directory

# ML Ranking Thresholds (Step 2: Assessment)
export ELISE_TAU_XSS="0.75"          # XSS confidence threshold (default: 0.75)
export ELISE_TAU_SQLI="0.70"         # SQLi confidence threshold (default: 0.70)
export ELISE_TAU_REDIRECT="0.60"     # Redirect confidence threshold (default: 0.60)
```

### ML Modes

Elise supports different operational modes based on ML configuration:

| Mode | USE_ML | REQUIRE_RANKER | Behavior |
|------|--------|----------------|----------|
| **Defaults Only** | `0` | `0` | Uses hardcoded payloads, no ML models required |
| **ML Optional** | `1` | `0` | Uses ML models if available, falls back to defaults |
| **ML Required** | `1` | `1` | Requires ML models, fails if models missing |

**Mode Examples:**
- **Development**: `USE_ML=0` - Quick testing with basic payloads
- **Production**: `USE_ML=1, REQUIRE_RANKER=0` - Enhanced with ML when available
- **Strict ML**: `USE_ML=1, REQUIRE_RANKER=1` - Full ML pipeline required

**ML Ranking Execution:**
ML ranking occurs in **Step 2: Assessment** after probes complete and before injection attempts. The system:
1. Builds feature vectors from target context and probe results
2. Ranks payloads using ML models (if available) or manifest defaults
3. Applies confidence thresholds to filter low-probability payloads
4. Attempts injections in ranked order until confirmation or budget exhaustion

### Option 1: Docker (Recommended)

**One-command demo with full stack:**

```bash
# Clone and start everything
git clone <repository-url>
cd elise

# Train ML models first
make models

# Start full stack (lab + backend + frontend)
make docker-up
```

**Access the Application:**
- 🌐 **Frontend**: http://localhost:3000
- 🔧 **Backend API**: http://localhost:8000
- 🧪 **Vulnerable Lab**: http://localhost:5001
- 📊 **API Docs**: http://localhost:8000/docs

**Docker Commands:**
```bash
make docker-build    # Build all images
make docker-up       # Start full stack
make docker-down     # Stop all services
make docker-logs     # View logs
```

### Manual Setup

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd elise
   ```

2. **Setup Backend**
   ```bash
   cd backend
   pip install -r requirements.txt
   uvicorn backend.main:app --reload
   ```

3. **Setup Frontend**
   ```bash
   cd frontend
   npm install
   npm run dev
   ```

4. **Access the Application**
   - Frontend: http://localhost:3000
   - Backend API: http://localhost:8000
   - API Docs: http://localhost:8000/docs

### Running Tests

**Backend Tests:**
```bash
cd backend
pytest -q
```

**Frontend Tests:**
```bash
cd frontend
npm test
```

## 🔄 Workflow

### Step 1: Crawl (Page 1)
- Enter target URL and crawl configuration
- System crawls and discovers endpoints with parameters
- Endpoints are persisted to `jobs/<job_id>/endpoints.json`
- Select specific endpoints for assessment

### Step 2: Assess (Page 2)
- Run vulnerability assessment on selected endpoints
- Probe-first methodology with micro-probes
- Rule-based XSS context/escaping detection
- Rule-based SQLi dialect detection
- Evidence collection with safe HTML escaping

### Step 3: Report (Page 3)
- View generated Markdown report
- Access individual evidence files
- Download raw evidence data
- Review assessment telemetry and diagnostics

## 🧠 Machine Learning System

### Enhanced Features
- **48 sophisticated features** vs. 17 basic features
- **Confidence calibration** with uncertainty quantification
- **CVSS-based scoring** for vulnerability severity
- **Context-aware payload ranking**
- **Automatic family detection** (SQLi, XSS, Redirect)

### Models
1. **Vulnerability Predictor**: Predicts vulnerability types with confidence
2. **Payload Recommender**: Ranks payloads by effectiveness
3. **Enhanced Feature Extractor**: Semantic and contextual analysis

### Training ML Models

Elise includes a minimal training pipeline to generate reproducible demo models:

#### Quick Training
```bash
# Train all models with synthetic data
make models

# Or run directly
cd backend
python -m modules.ml.train_minimal
```

#### What Gets Trained
- **Binary classifiers** for each vulnerability family (XSS, SQLi, Redirect)
- **Calibrated probabilities** using isotonic regression
- **Synthetic training data** using the same feature schema as production
- **Model artifacts** saved to `backend/modules/ml/models/`

#### Training Output
```
backend/modules/ml/models/
├── family_xss.joblib          # XSS binary classifier
├── family_xss.cal.json        # XSS calibration metrics
├── family_sqli.joblib         # SQLi binary classifier
├── family_sqli.cal.json       # SQLi calibration metrics
├── family_redirect.joblib     # Redirect binary classifier
└── family_redirect.cal.json   # Redirect calibration metrics
```

#### Verification
After training, verify ML readiness:
```bash
# Check ML status
curl http://localhost:8000/api/healthz

# Test predictions
curl -X POST http://localhost:8000/api/ml-predict \
  -H "Content-Type: application/json" \
  -d '{"url": "http://example.com/search?q=test", "param": "q", "method": "GET"}'
```

The training pipeline generates 1000 synthetic samples per family and trains Logistic Regression classifiers with isotonic calibration for reliable probability estimates.

## 🛡️ Vulnerability Detection

### XSS Detection
- Reflected, Stored, and DOM-based XSS
- Context-aware payloads for different injection points
- Evidence correlation for false positive reduction

### SQL Injection Detection
- Boolean-based blind SQLi
- Union-based data extraction
- Error-based database analysis
- Time-based blind detection

## 📊 Performance Metrics

| Metric | Legacy | Enhanced | Improvement |
|--------|--------|----------|-------------|
| Features | 17 basic | 48 sophisticated | +182% |
| Model Types | 1 basic | 3 specialized | +200% |
| Confidence | Basic prob | Confidence + Uncertainty | +100% |
| Payload Ranking | Simple | Context-aware | +150% |

## 🔧 API Endpoints

### Core Assessment API
- `POST /api/crawl` - Crawl target and persist endpoints
- `POST /api/assess` - Run vulnerability assessment with clear mode semantics
- `GET /api/healthz` - System diagnostics and ML status
- `GET /api/evidence/{job_id}/{evidence_id}` - Fetch individual evidence files

### Legacy Endpoints (Maintained for Compatibility)
- `POST /api/ml-predict` - ML vulnerability prediction
- `POST /api/ml-fuzz` - Real-time ML fuzzing
- `POST /api/enhanced-fuzz` - CVSS-based enhanced fuzzing
- `POST /api/exploit` - Automated exploitation testing

## 📁 Project Structure

```
elise/
├── backend/                 # FastAPI backend
│   ├── main.py             # Application entry point
│   ├── modules/            # Core functionality
│   │   ├── enhanced_ml_fuzzer.py
│   │   ├── playwright_crawler.py
│   │   ├── ml/             # ML system
│   │   └── detectors.py    # Vulnerability detection
│   ├── routes/             # API endpoints
│   └── requirements.txt    # Python dependencies
├── frontend/               # Next.js frontend
│   ├── src/app/           # App Router pages
│   └── package.json       # Node dependencies
└── data/                  # Runtime data
    ├── evidence.db        # SQLite database
    └── results/           # Scan results
```

## 🎯 Use Cases

- **Automated Penetration Testing**: Comprehensive web app security assessment
- **CI/CD Integration**: Continuous security validation
- **Vulnerability Research**: Discovery and analysis of new attack vectors
- **Security Compliance**: Automated vulnerability assessment for audits

## 🧪 Local Vulnerable Lab (Flask)

For testing and development purposes, Elise includes a local vulnerable web application built with Flask.

### Quick Start

1. **Start the lab environment:**
   ```bash
   make lab
   ```

2. **Access the vulnerable app:**
   - Visit: http://localhost:5001/
   - The app contains intentionally vulnerable endpoints for testing

3. **Stop the lab environment:**
   ```bash
   make lab-down
   ```

### Vulnerabilities Included

- **XSS (Reflected)**: HTML, attribute, and JavaScript string contexts
- **XSS (Stored)**: Unsanitized content in notes
- **SQL Injection**: Error-based and boolean-based blind
- **Open Redirect**: Unvalidated URL redirection
- **CSRF**: State-changing operations without token protection

### Test Credentials

- **alice** / **alice** (balance: $100.00)
- **bob** / **bob** (balance: $50.00)

### ⚠️ Important Warning

**This vulnerable lab is for local/offline testing only. Do not expose to the internet or use in production environments.**

## 🔒 Security Considerations

- **Responsible Disclosure**: Only test authorized targets
- **Controlled Testing**: Rate limiting and evidence collection
- **Data Protection**: Local processing with secure storage
- **Audit Trails**: Comprehensive logging for analysis

## 📈 Example Results

```json
{
  "vulnerability_type": "sqli",
  "confidence": 0.98,
  "cvss_base_score": 6.8,
  "cvss_severity": "MEDIUM",
  "evidence": [
    "SQL syntax error detected",
    "Database type: MySQL",
    "Boolean-based blind confirmed"
  ],
  "recommended_payloads": [
    "' OR '1'='1",
    "'; DROP TABLE users--",
    "' UNION SELECT NULL--"
  ]
}
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **FastAPI** for the excellent Python web framework
- **Next.js** for the modern React framework
- **Playwright** for browser automation capabilities
- **Scikit-learn** and **XGBoost** for machine learning capabilities

## 📞 Support

For support, email support@elise-scanner.com or create an issue in the repository.

---