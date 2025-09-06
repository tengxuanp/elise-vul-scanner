# Elise Vulnerability Scanner - Submission Guide

## Quick Start Instructions

### 1. Extract and Setup
```bash
unzip elise-source-code.zip
cd elise
```

### 2. Install Dependencies

**Backend (Python):**
```bash
cd backend
pip install -r requirements.txt
python -m playwright install --with-deps chromium
```

**Lab (Python):**
```bash
cd lab
pip install -r requirements.txt
```

**Frontend (Node.js):**
```bash
cd frontend
npm install
```

### 3. Start Services

**Terminal 1 - Lab Application:**
```bash
cd lab
python app.py
# Should start on http://localhost:5001
```

**Terminal 2 - Backend API:**
```bash
cd backend
python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
# Should start on http://localhost:8000
```

**Terminal 3 - Frontend:**
```bash
cd frontend
npm run dev
# Should start on http://localhost:3000
```

### 4. Test the System

1. Open http://localhost:3000 in your browser
2. Click "Run Crawl" with default settings
3. Expected: Should discover endpoints from the lab application

## Current Issue

The crawler is returning 0 endpoints when running in development mode. The system works in Docker but fails when running services directly.

## Problem Details

- ✅ Backend starts successfully (FastAPI on port 8000)
- ❌ Lab application has Flask import issues in development mode
- ❌ Crawler cannot discover endpoints from the lab application
- ✅ Docker version works correctly

## Key Files to Examine

- `backend/routes/enhanced_crawl_routes.py` - Main crawler endpoint
- `backend/modules/crawler/enhanced_crawler.py` - Crawler implementation
- `lab/app.py` - Vulnerable Flask application
- `frontend/src/lib/api.js` - Frontend API client

## Expected Behavior

1. Lab application should start on localhost:5001
2. Backend should start on localhost:8000
3. Crawler should discover endpoints with parameters
4. Frontend should display results and allow fuzzing

## Debugging Steps

1. Check if lab application is accessible: `curl http://localhost:5001/`
2. Check backend health: `curl http://localhost:8000/api/healthz`
3. Test crawler directly: `curl -X POST http://localhost:8000/api/crawl -H "Content-Type: application/json" -d '{"url": "http://localhost:5001/", "max_depth": 1}'`

## Alternative: Docker Mode

If development mode doesn't work, try Docker:

```bash
docker compose up -d
# Access at http://localhost:3000
```

The Docker version is known to work correctly.

