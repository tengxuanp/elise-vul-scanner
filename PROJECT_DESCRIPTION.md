# Elise - Vulnerability Scanner System

## Overview
Elise is a comprehensive web vulnerability scanner that combines web crawling, machine learning-based triage, and automated fuzzing to detect XSS and SQL injection vulnerabilities.

## Architecture
- **Backend**: FastAPI (Python) with ML models for vulnerability prediction
- **Frontend**: Next.js (JavaScript) with React Query for state management
- **Lab**: Flask-based vulnerable web application for testing
- **Crawler**: Playwright-based active crawling with parameter extraction
- **ML Pipeline**: Strict ML workflow with calibrated binary classifiers

## Key Features
1. **Enhanced Crawler**: Discovers endpoints with GET/POST parameters via BFS traversal
2. **ML Triage**: Binary classifiers for XSS, SQLi, and Redirect vulnerabilities
3. **Probe System**: XSS canary, redirect oracle, and SQLi triage probes
4. **Evidence Management**: Structured JSONL storage with CVSS v3.1 vectors
5. **Docker Support**: Full containerization with docker-compose

## Current Issue
The crawler is returning 0 endpoints when running in development mode. The system works in Docker but fails when running services directly on localhost.

## Problem Details
- Backend starts successfully (FastAPI on port 8000)
- Lab application has Flask import issues in development mode
- Crawler cannot discover endpoints from the lab application
- Docker networking fix exists but doesn't apply in development mode

## Files Structure
```
elise/
├── backend/                 # FastAPI backend
│   ├── modules/            # Core modules (crawler, ML, targets)
│   ├── routes/             # API endpoints
│   ├── pipeline/           # Workflow orchestration
│   └── main.py            # FastAPI app entry point
├── frontend/               # Next.js frontend
│   ├── src/               # React components and pages
│   └── package.json       # Dependencies
├── lab/                   # Vulnerable Flask app
│   ├── app.py            # Flask application
│   └── requirements.txt  # Python dependencies
└── docker-compose.yml    # Container orchestration
```

## Dependencies
- Python 3.8+ with FastAPI, Playwright, scikit-learn
- Node.js 18+ with Next.js, React Query, Tailwind CSS
- Docker and Docker Compose for containerization

## Expected Behavior
1. Start lab application on localhost:5001
2. Start backend on localhost:8000
3. Crawler should discover endpoints with parameters
4. ML triage should analyze discovered endpoints
5. Frontend should display results and allow fuzzing

## Current Status
- ✅ Backend API working (ML models ready)
- ❌ Lab application startup issues in development
- ❌ Crawler returning 0 endpoints
- ✅ Docker version works correctly


