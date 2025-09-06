# Vulnerable Lab - Benchmarking Environment

## 🎯 Overview

This is an intentionally vulnerable Flask web application designed for testing and benchmarking ML-powered vulnerability scanners. The application contains multiple types of vulnerabilities across different contexts to evaluate scanner effectiveness.

## ⚠️ **IMPORTANT WARNING**

**This application is intentionally vulnerable and should ONLY be used for:**
- Local testing and development
- ML model training and validation
- Vulnerability scanner benchmarking
- Security research and education

**DO NOT expose this application to the internet or use in production environments.**

## 🚀 Quick Start

### Start the Lab
```bash
make lab
```

### Access the Application
- **URL**: http://localhost:5001/
- **Health Check**: http://localhost:5001/healthz

### Stop the Lab
```bash
make lab-down
```

## 🎯 Vulnerability Map

### **XSS (Cross-Site Scripting) - Reflected**

#### 1. HTML Context Injection
- **Endpoint**: `GET /search?q=<payload>`
- **Vulnerability**: Reflected XSS in HTML body
- **Context**: Direct HTML injection
- **Test Payloads**:
  ```html
  <script>alert('XSS')</script>
  <img src=x onerror=alert('XSS')>
  <svg onload=alert('XSS')>
  ```
- **Expected Behavior**: Payload executes in browser
- **Severity**: LOW (CVSS 2.4)

#### 2. Attribute Context Injection
- **Endpoint**: `GET /profile?name=<payload>`
- **Vulnerability**: Reflected XSS in HTML attribute
- **Context**: HTML attribute value
- **Test Payloads**:
  ```html
  "><script>alert('XSS')</script>
  " onmouseover="alert('XSS')
  '><img src=x onerror=alert('XSS')>
  ```
- **Expected Behavior**: Payload breaks out of attribute and executes
- **Severity**: LOW (CVSS 2.4)

#### 3. JavaScript String Context Injection
- **Endpoint**: `GET /script?msg=<payload>`
- **Vulnerability**: Reflected XSS in JavaScript string
- **Context**: JavaScript string literal
- **Test Payloads**:
  ```javascript
  ";alert('XSS');//
  ';alert('XSS');//
  </script><script>alert('XSS')</script>
  ```
- **Expected Behavior**: Payload breaks out of JS string and executes
- **Severity**: LOW (CVSS 2.4)

### **XSS (Cross-Site Scripting) - Stored**

#### 4. Stored XSS in Notes
- **Endpoint**: `POST /notes` (form: content)
- **Vulnerability**: Stored XSS in notes content
- **Context**: Unsanitized content storage and display
- **Test Payloads**:
  ```html
  <script>alert('Stored XSS')</script>
  <img src=x onerror=alert('Stored XSS')>
  <iframe src="javascript:alert('Stored XSS')"></iframe>
  ```
- **Expected Behavior**: Payload stored and executed when viewing notes
- **Severity**: MEDIUM (CVSS 4.3)

### **SQL Injection**

#### 5. Error-Based SQL Injection
- **Endpoint**: `GET /product?id=<payload>`
- **Vulnerability**: Error-based SQL injection
- **Context**: Integer parameter in WHERE clause
- **Test Payloads**:
  ```sql
  1 OR 1=1
  1' OR '1'='1
  1; DROP TABLE products--
  1' UNION SELECT NULL--
  ```
- **Expected Behavior**: SQL errors exposed or data manipulation
- **Severity**: MEDIUM (CVSS 6.8)

#### 6. Boolean-Based SQL Injection (Login)
- **Endpoint**: `POST /login` (form: username, password)
- **Vulnerability**: Authentication bypass via SQL injection
- **Context**: String parameters in WHERE clause
- **Test Payloads**:
  ```sql
  Username: admin' OR '1'='1
  Password: anything
  Username: alice' OR '1'='1
  Password: anything
  ```
- **Expected Behavior**: Authentication bypassed, user logged in
- **Severity**: HIGH (CVSS 8.8)

#### 7. JSON API SQL Injection
- **Endpoint**: `POST /api/search-json` (JSON: {"q": "<payload>"})
- **Vulnerability**: SQL injection in JSON API
- **Context**: String parameter in LIKE clause
- **Test Payloads**:
  ```json
  {"q": "a' OR 1=1--"}
  {"q": "a' UNION SELECT name FROM products--"}
  {"q": "a'; DROP TABLE products--"}
  ```
- **Expected Behavior**: SQL errors or data extraction
- **Severity**: MEDIUM (CVSS 6.8)

### **Open Redirect**

#### 8. Unvalidated URL Redirection
- **Endpoint**: `GET /go?url=<payload>`
- **Vulnerability**: Open redirect vulnerability
- **Context**: Unvalidated URL parameter
- **Test Payloads**:
  ```
  https://evil.com
  javascript:alert('XSS')
  //evil.com
  /\/evil.com
  ```
- **Expected Behavior**: Redirects to external URL
- **Severity**: LOW (CVSS 2.6)

### **CSRF (Cross-Site Request Forgery)**

#### 9. State-Changing Operation Without CSRF Protection
- **Endpoint**: `POST /transfer` (form: to_user, amount)
- **Vulnerability**: CSRF vulnerability in money transfer
- **Context**: State-changing operation without token
- **Test Payloads**:
  ```html
  <form action="http://localhost:5001/transfer" method="POST">
    <input name="to_user" value="attacker">
    <input name="amount" value="100">
  </form>
  <script>document.forms[0].submit();</script>
  ```
- **Expected Behavior**: Transfer executed without user consent
- **Severity**: MEDIUM (CVSS 4.3)

## 🧪 Test Credentials

### Valid Users
- **alice** / **alice** (balance: $100.00)
- **bob** / **bob** (balance: $50.00)

### Test Scenarios
1. **Login with valid credentials**: Should succeed
2. **Login with SQL injection**: Should bypass authentication
3. **Transfer money**: Should work without CSRF protection
4. **View notes**: Should display stored XSS payloads

## 📊 Benchmarking Metrics

### **Detection Accuracy**
- **True Positives**: Correctly identified vulnerabilities
- **False Positives**: Incorrectly flagged as vulnerable
- **False Negatives**: Missed actual vulnerabilities
- **Precision**: TP / (TP + FP)
- **Recall**: TP / (TP + FN)
- **F1-Score**: 2 * (Precision * Recall) / (Precision + Recall)

### **Vulnerability Coverage**
- **XSS Detection**: 4 endpoints (3 reflected + 1 stored)
- **SQL Injection**: 3 endpoints (error-based + boolean-based + JSON API)
- **Open Redirect**: 1 endpoint
- **CSRF**: 1 endpoint
- **Total Vulnerabilities**: 9

### **Context Diversity**
- **HTML Context**: 1 endpoint
- **Attribute Context**: 1 endpoint
- **JavaScript Context**: 1 endpoint
- **Stored Context**: 1 endpoint
- **SQL Context**: 3 endpoints
- **Redirect Context**: 1 endpoint
- **Form Context**: 1 endpoint

## 🔍 Scanner Testing Checklist

### **XSS Testing**
- [ ] Detects reflected XSS in HTML context
- [ ] Detects reflected XSS in attribute context
- [ ] Detects reflected XSS in JavaScript context
- [ ] Detects stored XSS in notes
- [ ] Provides appropriate confidence scores
- [ ] Identifies correct vulnerability type

### **SQL Injection Testing**
- [ ] Detects error-based SQL injection
- [ ] Detects boolean-based SQL injection
- [ ] Detects SQL injection in JSON API
- [ ] Provides appropriate confidence scores
- [ ] Identifies correct vulnerability type
- [ ] Handles different parameter types (int, string, JSON)

### **Other Vulnerabilities**
- [ ] Detects open redirect vulnerability
- [ ] Detects CSRF vulnerability
- [ ] Provides appropriate confidence scores
- [ ] Identifies correct vulnerability types

### **Performance Testing**
- [ ] Completes scan within reasonable time
- [ ] Handles multiple endpoints efficiently
- [ ] Provides real-time progress updates
- [ ] Generates comprehensive reports

## 📈 Expected Results

### **ML Confidence Scores**
- **High Confidence (0.8+)**: Clear vulnerability indicators
- **Medium Confidence (0.4-0.8)**: Moderate vulnerability indicators
- **Low Confidence (0.0-0.4)**: Weak vulnerability indicators

### **CVSS Severity Levels**
- **LOW (0.1-3.9)**: XSS, Open Redirect
- **MEDIUM (4.0-6.9)**: Stored XSS, SQL Injection, CSRF
- **HIGH (7.0-8.9)**: Authentication bypass
- **CRITICAL (9.0-10.0)**: None in this lab

### **Response Analysis**
- **200 Status**: Successful injection (XSS, some SQLi)
- **500 Status**: SQL errors (error-based SQLi)
- **302 Status**: Redirects (open redirect)
- **401 Status**: Authentication failures (some SQLi attempts)

## 🛠️ Customization

### **Adding New Vulnerabilities**
1. Add new routes in `app.py`
2. Create corresponding templates
3. Update this README with new endpoint details
4. Test with your scanner

### **Modifying Existing Vulnerabilities**
1. Edit the vulnerable code in `app.py`
2. Update test payloads in this README
3. Re-test with your scanner

### **Database Modifications**
1. Edit `init_db.py` to add new tables/data
2. Update test scenarios in this README
3. Re-initialize database: `python3 lab/init_db.py`

## 📝 Logging and Monitoring

### **Application Logs**
- Flask debug logs show all requests
- SQL errors are displayed to users (intentionally)
- All responses include appropriate status codes

### **Scanner Integration**
- Use health check endpoint for availability testing
- Monitor response times for performance testing
- Check response content for vulnerability confirmation

## 🔧 Troubleshooting

### **Common Issues**
1. **Port 5001 in use**: Change port in `docker-compose.yml`
2. **Database errors**: Re-run `python3 lab/init_db.py`
3. **Container issues**: Run `make lab-down && make lab`

### **Debug Mode**
- Flask debug mode is enabled
- All errors are displayed in browser
- SQL errors show raw error messages

---

**This vulnerable lab provides a comprehensive testing environment for evaluating ML-powered vulnerability scanners across multiple attack vectors and contexts.**


