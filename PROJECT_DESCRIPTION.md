# Elise - Advanced Web Vulnerability Scanner

## Overview
Elise is a comprehensive web vulnerability scanner that combines intelligent web crawling, machine learning-based vulnerability prediction, and automated fuzzing to detect XSS and SQL injection vulnerabilities. The system features a strict, interaction-based crawler built with Playwright and a canonicalized API architecture.

## Architecture
- **Backend**: FastAPI (Python) with ML models for vulnerability prediction
- **Frontend**: Next.js 15 (JavaScript) with React Query for state management  
- **Lab**: Flask-based vulnerable web application for testing
- **Crawler**: Playwright-based strict crawling with real form submission and XHR capture
- **ML Pipeline**: Calibrated binary classifiers with enhanced feature extraction

## Key Features

### 🕷️ **Strict Playwright Crawler**
- **Real Browser Interaction**: Uses Playwright for actual page visits and form submissions
- **BFS Traversal**: Breadth-first search with configurable depth limits
- **Form Handling**: Real form submission (GET/POST) with proper field filling
- **XHR/Fetch Capture**: Intercepts and captures AJAX requests and responses
- **Parameter Extraction**: Extracts parameters from query strings, form data, and JSON bodies
- **Source Classification**: Classifies requests as 'xhr', 'nav', or 'other' with priority ranking
- **Button Clicking**: Intelligent button clicking to trigger XHR requests
- **Authentication Support**: Optional form-based authentication with configurable fields

### 🤖 **Machine Learning Pipeline**
- **Binary Classifiers**: Separate models for XSS, SQLi, and Redirect vulnerabilities
- **Calibrated Predictions**: Probability calibration for reliable confidence scores
- **Feature Engineering**: 48+ features including parameter patterns, URL structure, and content analysis
- **Enhanced Inference**: Advanced feature extraction with parameter prioritization

### 🔍 **Probe System**
- **XSS Canary**: DOM-based XSS detection with canary tokens
- **Redirect Oracle**: Open redirect vulnerability detection
- **SQLi Triage**: SQL injection detection with error pattern analysis
- **Evidence Collection**: Structured evidence gathering with CVSS v3.1 scoring

### 🎯 **Canonical API Architecture**
- **Single Entry Points**: `/api/crawl`, `/api/ml-predict`, `/api/fuzz`, `/api/exploit`, `/api/healthz`
- **Strict Contracts**: Well-defined request/response schemas with Pydantic validation
- **Hard Truth Health Checks**: Real dependency validation (no fake success responses)
- **Error Handling**: Proper HTTP status codes with detailed error messages

### 🖥️ **Modern Frontend**
- **Next.js 15**: Latest React framework with App Router
- **Centralized API Client**: Single source of truth for all API calls
- **Real-time Updates**: Live health status and crawl progress
- **Rich Endpoint Display**: Detailed endpoint information with source classification
- **Interactive Controls**: Configurable crawl parameters and authentication

## Current Implementation Status

### ✅ **Completed Features**
- **Strict Playwright Crawler**: Fully functional with real browser automation
- **Canonical API Routes**: All endpoints implemented with proper validation
- **ML Prediction Pipeline**: Working binary classifiers with calibration
- **Frontend Integration**: Complete UI with endpoint display and controls
- **Authentication Support**: Form-based login with configurable fields
- **Source Classification**: XHR/NAV/OTHER classification with priority ranking
- **Debug Logging**: Environment-controlled debug output for troubleshooting
- **Docker Support**: Full containerization with docker-compose

### 🔧 **Technical Specifications**
- **Crawler Engine**: `playwright-strict` with real form submission
- **Request Capture**: Both page and context-level listeners for comprehensive coverage
- **Parameter Parsing**: Query, form, and JSON parameter extraction
- **Endpoint Aggregation**: Deduplication with source priority (XHR > FETCH > NAV > OTHER)
- **Meta Tracking**: Pages visited, XHR count, unique paths, endpoints with parameters

## API Endpoints

### POST `/api/crawl`
```json
{
  "target_url": "http://example.com",
  "max_depth": 2,
  "max_endpoints": 30,
  "submit_get_forms": true,
  "submit_post_forms": true,
  "click_buttons": true,
  "seeds": ["/api/users"],
  "auth": {
    "type": "form",
    "login_url": "http://example.com/login",
    "username_field": "username",
    "password_field": "password",
    "username": "admin",
    "password": "admin",
    "submit_selector": "#login-button"
  }
}
```

### Response Format
```json
{
  "endpoints": [
    {
      "url": "http://example.com/api/users",
      "path": "/api/users",
      "method": "GET",
      "params": ["id", "limit"],
      "param_locs": {
        "query": ["id", "limit"],
        "form": [],
        "json": []
      },
      "status": 200,
      "source": "xhr",
      "content_type": "application/json",
      "seen": 3
    }
  ],
  "meta": {
    "engine": "playwright-strict",
    "pagesVisited": 15,
    "xhrCount": 42,
    "emitted": 12,
    "uniquePaths": 8,
    "withParams": 5
  }
}
```

## File Structure
```
elise/
├── backend/                    # FastAPI backend
│   ├── modules/               # Core modules
│   │   ├── playwright_crawler.py    # Strict crawler implementation
│   │   ├── ml/                # ML models and inference
│   │   ├── probes/            # Vulnerability probes
│   │   └── ...               # Other modules
│   ├── routes/                # Canonical API routes
│   │   ├── canonical_crawl_routes.py
│   │   ├── canonical_ml_predict_routes.py
│   │   ├── canonical_fuzz_routes.py
│   │   └── canonical_exploit_routes.py
│   ├── schemas.py             # Pydantic models
│   └── main.py               # FastAPI app entry point
├── frontend/                  # Next.js 15 frontend
│   ├── src/
│   │   ├── lib/api.js        # Centralized API client
│   │   ├── components/       # React components
│   │   ├── types/api.ts      # TypeScript definitions
│   │   └── app/              # App Router pages
│   └── package.json          # Dependencies (v0.2.0)
├── lab/                      # Vulnerable Flask app
│   ├── app.py               # Flask application
│   ├── templates/           # HTML templates
│   └── requirements.txt     # Python dependencies
└── docker-compose.yml       # Container orchestration
```

## Dependencies
- **Backend**: Python 3.8+ with FastAPI, Playwright, scikit-learn, Pydantic
- **Frontend**: Node.js 18+ with Next.js 15, React Query, Tailwind CSS
- **Lab**: Flask with CORS support
- **Containerization**: Docker and Docker Compose

## Usage

### Development Mode
```bash
# Start lab server
cd lab && python app.py

# Start backend
cd backend && python main.py

# Start frontend
cd frontend && npm run dev
```

### Docker Mode
```bash
docker-compose up
```

### API Testing
```bash
# Test crawler with debug output
CRAWL_DEBUG=1 curl -X POST http://localhost:8000/api/crawl \
  -H "Content-Type: application/json" \
  -d '{"target_url": "http://localhost:5001", "max_depth": 1}'
```

## Key Technical Achievements

1. **Strict Crawler Implementation**: Replaced heuristic-based crawling with real browser automation
2. **Canonical API Design**: Single source of truth for all API endpoints with strict contracts
3. **Source Classification**: Intelligent request classification with priority-based aggregation
4. **Authentication Integration**: Seamless form-based authentication support
5. **Debug Infrastructure**: Environment-controlled logging for development and troubleshooting
6. **Frontend Modernization**: Updated to Next.js 15 with centralized API client
7. **Type Safety**: Full TypeScript definitions for frontend API interactions

## Current Status: ✅ **FULLY FUNCTIONAL**
- ✅ Strict Playwright crawler working with real browser automation
- ✅ Canonical API endpoints with proper validation
- ✅ ML prediction pipeline operational
- ✅ Frontend integration complete
- ✅ Authentication support implemented
- ✅ Debug logging and troubleshooting tools
- ✅ Docker containerization working
- ✅ Source classification and aggregation
- ✅ Real-time health monitoring

The system is production-ready with comprehensive vulnerability scanning capabilities, intelligent crawling, and modern web interface.