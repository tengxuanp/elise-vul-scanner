# Benchmark Quick Reference Card

## 🎯 Vulnerability Endpoints

| Vulnerability | Endpoint | Method | Parameter | Test Payload | Expected |
|---------------|----------|--------|-----------|--------------|----------|
| **XSS (HTML)** | `/search` | GET | `q` | `<script>alert('XSS')</script>` | 200 + execution |
| **XSS (Attr)** | `/profile` | GET | `name` | `"><script>alert('XSS')</script>` | 200 + execution |
| **XSS (JS)** | `/script` | GET | `msg` | `";alert('XSS');//` | 200 + execution |
| **XSS (Stored)** | `/notes` | POST | `content` | `<script>alert('Stored')</script>` | 200 + stored |
| **SQLi (Error)** | `/product` | GET | `id` | `1 OR 1=1` | 200 + multiple rows |
| **SQLi (Login)** | `/login` | POST | `username` | `alice' OR '1'='1` | 200 + redirect |
| **SQLi (JSON)** | `/api/search-json` | POST | `q` | `{"q":"a' OR 1=1--"}` | 500 + error |
| **Open Redirect** | `/go` | GET | `url` | `https://evil.com` | 302 + redirect |
| **CSRF** | `/transfer` | POST | `to_user,amount` | Form submission | 200 + transfer |

## 🧪 Quick Test Commands

### XSS Testing
```bash
# HTML Context
curl "http://localhost:5001/search?q=<script>alert('XSS')</script>"

# Attribute Context  
curl "http://localhost:5001/profile?name=\"><script>alert('XSS')</script>"

# JavaScript Context
curl "http://localhost:5001/script?msg=\";alert('XSS');//"
```

### SQL Injection Testing
```bash
# Error-based
curl "http://localhost:5001/product?id=1 OR 1=1"

# Boolean-based (Login)
curl -X POST -d "username=alice' OR '1'='1&password=anything" "http://localhost:5001/login"

# JSON API
curl -X POST -H "Content-Type: application/json" -d '{"q":"a'\'' OR 1=1--"}' "http://localhost:5001/api/search-json"
```

### Other Vulnerabilities
```bash
# Open Redirect
curl "http://localhost:5001/go?url=https://evil.com"

# CSRF (requires login first)
curl -X POST -d "to_user=attacker&amount=100" "http://localhost:5001/transfer"
```

## 📊 Expected Scanner Results

### High Confidence (0.8+)
- XSS payloads that successfully execute
- SQL injection that returns multiple rows
- Authentication bypass attempts

### Medium Confidence (0.4-0.8)
- XSS payloads that inject but don't execute
- SQL injection that causes errors
- Open redirect attempts

### Low Confidence (0.0-0.4)
- Malformed payloads
- Non-vulnerable parameters
- Invalid requests

## 🎯 Success Criteria

### ✅ **Scanner Should Detect**
- All 4 XSS vulnerabilities (different contexts)
- All 3 SQL injection vulnerabilities
- Open redirect vulnerability
- CSRF vulnerability

### ✅ **Scanner Should Provide**
- Correct vulnerability type classification
- Appropriate confidence scores
- CVSS severity ratings
- Evidence of successful exploitation

### ✅ **Scanner Should Avoid**
- False positives on non-vulnerable endpoints
- Misclassification of vulnerability types
- Overly conservative confidence scores

## 🔍 Manual Verification

### XSS Verification
1. Open browser to endpoint with payload
2. Check if JavaScript executes
3. Verify payload appears in page source

### SQL Injection Verification
1. Check if multiple rows returned
2. Look for SQL error messages
3. Verify authentication bypass

### Open Redirect Verification
1. Check HTTP response status (302)
2. Verify Location header contains target URL
3. Confirm redirect occurs in browser

### CSRF Verification
1. Login as valid user
2. Submit transfer form
3. Verify balance changes without user interaction

---

**Use this reference for quick testing and validation of your ML vulnerability scanner's effectiveness.**



