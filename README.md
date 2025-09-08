# Elise - Advanced ML-Powered Web Vulnerability Scanner

[![Python](https://img.shields.io/badge/Python-3.12+-blue.svg)](https://python.org)
[![Next.js](https://img.shields.io/badge/Next.js-15-black.svg)](https://nextjs.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-green.svg)](https://fastapi.tiangolo.com)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Elise** is a sophisticated, full-stack web vulnerability scanning system that combines dynamic crawling, machine learning-based vulnerability prediction, and intelligent payload recommendation to automatically discover and test web application security flaws.

## 🎯 Key Features

- **🧠 Advanced ML System**: 48-feature enhanced vulnerability prediction with confidence calibration
- **🕷️ Dynamic Crawling**: Playwright-based web crawling with smart endpoint discovery
- **🎯 Intelligent Fuzzing**: ML-driven payload recommendation and real-time testing
- **📊 CVSS Scoring**: Industry-standard vulnerability severity assessment
- **🔍 XSS & SQLi Focus**: Specialized detection for Cross-Site Scripting and SQL Injection
- **⚡ Real-time UI**: Modern Next.js interface with live progress tracking
- **🛡️ Exploitation Testing**: Automated payload refinement and verification

## 🏗️ Architecture

### Frontend (Next.js 15)
- Modern React 19 with App Router
- Tailwind CSS for responsive design
- Real-time progress tracking
- Interactive result visualization

### Backend (FastAPI)
- Python 3.12 with async/await
- SQLite database with SQLAlchemy
- Advanced ML models (XGBoost, LightGBM)
- RESTful API with OpenAPI docs

## 🚀 Quick Start

### Prerequisites
- Python 3.12+
- Node.js 18+
- Docker & Docker Compose
- Modern web browser

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

### Option 2: Manual Setup

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd elise
   ```

2. **Setup Backend**
   ```bash
   cd backend
   pip install -r requirements.txt
   python main.py
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

## 🔄 Workflow

### Step 1: Dynamic Crawling
- Enter target URL (e.g., `http://localhost:8082/`)
- System crawls and discovers endpoints
- Smart categorization of API endpoints, forms, and admin areas

### Step 2: ML Vulnerability Prediction
- Advanced feature extraction from endpoints
- ML models predict vulnerability types (XSS, SQLi)
- Confidence scoring with uncertainty quantification
- Context-aware payload recommendation

### Step 3: Intelligent Fuzzing
- Real-time payload testing with evidence collection
- ML-driven payload evolution for better success rates
- CVSS-based severity assessment
- Automated exploitation testing

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

- `POST /api/crawl` - Enhanced dynamic crawling
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