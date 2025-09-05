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
- Modern web browser

### Installation

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

**Elise** - Advanced ML-Powered Web Vulnerability Scanner by Rafael Pang
