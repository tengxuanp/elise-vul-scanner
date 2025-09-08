# Job Data Included

This zip includes one sample job data for testing purposes:

## Job ID: 1757320765752

**Target URL**: http://127.0.0.1:5001/  
**Assessment Results**: 5 positive findings (4 XSS, 1 Redirect)  
**Processing Time**: ~20 seconds  
**ML Mode**: Calibrated models active  

### Evidence Files Included:
- `1757320796204_xss_name.json` - XSS vulnerability in profile name parameter
- `1757320796205_xss_q.json` - XSS vulnerability in search query parameter  
- `1757320796211_xss_msg.json` - XSS vulnerability in script message parameter
- `1757320796221_redirect_url.json` - Open redirect vulnerability
- `1757320796228_xss_content.json` - XSS vulnerability in content parameter

### Key Features Demonstrated:
- ✅ ML-driven payload ranking with calibrated models
- ✅ Probe-only confirmations (rank_source: "probe_only")
- ✅ Proper CVSS scoring (6.1 for XSS, 5.4 for redirect)
- ✅ Real timing measurements using perf_counter()
- ✅ Evidence API with safe HTML escaping
- ✅ Complete assessment pipeline from crawl to evidence

### Usage:
1. Start the backend: `uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000`
2. Start the frontend: `cd frontend && npm run dev`
3. Navigate to: `http://localhost:3000/assess?jobId=1757320765752&targetUrl=http://127.0.0.1:5001/`
4. Click "Evidence" buttons to test the evidence modal functionality

This job data represents a complete, working assessment with all the latest fixes applied.
