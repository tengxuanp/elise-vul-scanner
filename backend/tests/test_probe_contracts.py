"""
Probe Contract Tests - Unit tests for probe functionality with rule-based enhancements.
"""
import pytest
from unittest.mock import Mock, patch
from backend.modules.probes.xss_canary import run_xss_probe, detect_xss_context, detect_xss_escaping
from backend.modules.probes.sqli_triage import run_sqli_probe, detect_sqli_dialect
from backend.modules.probes.redirect_oracle import run_redirect_probe

class TestXSSCanary:
    """Test XSS canary with rule-based context and escaping detection."""
    
    def test_detect_xss_context_html_body(self):
        """Test HTML body context detection."""
        html = "<div>EliseXSSCanary123</div>"
        pos = html.find("EliseXSSCanary123")
        context = detect_xss_context(html, pos)
        assert context == "html_body"
    
    def test_detect_xss_context_attr(self):
        """Test HTML attribute context detection."""
        html = '<input value="EliseXSSCanary123">'
        pos = html.find("EliseXSSCanary123")
        context = detect_xss_context(html, pos)
        assert context == "attr"
    
    def test_detect_xss_context_js_string(self):
        """Test JavaScript string context detection."""
        html = '<script>var msg = "EliseXSSCanary123";</script>'
        pos = html.find("EliseXSSCanary123")
        context = detect_xss_context(html, pos)
        assert context == "js_string"
    
    def test_detect_xss_context_url(self):
        """Test URL context detection."""
        html = '<a href="EliseXSSCanary123">link</a>'
        pos = html.find("EliseXSSCanary123")
        context = detect_xss_context(html, pos)
        assert context == "url"
    
    def test_detect_xss_context_css(self):
        """Test CSS context detection."""
        html = '<style>body { content: "EliseXSSCanary123"; }</style>'
        pos = html.find("EliseXSSCanary123")
        context = detect_xss_context(html, pos)
        assert context == "css"
    
    def test_detect_xss_escaping_raw(self):
        """Test raw reflection detection."""
        text = "EliseXSSCanary123"
        pos = 0
        escaping = detect_xss_escaping(text, pos)
        assert escaping == "raw"
    
    def test_detect_xss_escaping_html(self):
        """Test HTML escaping detection."""
        text = "EliseXSSCanary123"  # This would be html.escape() in real scenario
        pos = 0
        # Mock the html.escape to return escaped version
        with patch('backend.modules.probes.xss_canary.html.escape', return_value="EliseXSSCanary123"):
            escaping = detect_xss_escaping(text, pos)
            assert escaping == "html"
    
    def test_detect_xss_escaping_url(self):
        """Test URL encoding detection."""
        text = "EliseXSSCanary123"  # This would be urllib.parse.quote() in real scenario
        pos = 0
        # Mock urllib.parse.quote to return URL encoded version
        with patch('backend.modules.probes.xss_canary.urllib.parse.quote', return_value="EliseXSSCanary123"):
            escaping = detect_xss_escaping(text, pos)
            assert escaping == "url"
    
    @patch('backend.modules.probes.xss_canary.httpx.request')
    def test_run_xss_probe_with_context(self, mock_request):
        """Test XSS probe returns context and escaping information."""
        # Mock response with canary reflection
        mock_response = Mock()
        mock_response.text = '<div>EliseXSSCanary123</div>'
        mock_request.return_value = mock_response
        
        result = run_xss_probe("http://test.com", "GET", "query", "param")
        
        assert result.reflected is True
        assert result.xss_context is not None
        assert result.xss_escaping is not None

class TestSQLiTriage:
    """Test SQLi triage with dialect detection."""
    
    def test_detect_sqli_dialect_mysql(self):
        """Test MySQL dialect detection."""
        response_text = "You have an error in your SQL syntax near 'test'"
        headers = {"Server": "Apache/2.4.41 (Ubuntu)"}
        
        dialect, signals, confident = detect_sqli_dialect(response_text, headers)
        
        assert dialect == "mysql"
        assert "You have an error in your SQL syntax" in signals
        assert confident is True
    
    def test_detect_sqli_dialect_postgresql(self):
        """Test PostgreSQL dialect detection."""
        response_text = "ERROR: syntax error at or near \"test\""
        headers = {"Server": "PostgreSQL"}
        
        dialect, signals, confident = detect_sqli_dialect(response_text, headers)
        
        assert dialect == "postgresql"
        assert "ERROR: syntax error" in signals
        assert confident is True
    
    def test_detect_sqli_dialect_mssql(self):
        """Test SQL Server dialect detection."""
        response_text = "Unclosed quotation mark after the character string 'test'"
        headers = {"Server": "Microsoft-IIS/10.0"}
        
        dialect, signals, confident = detect_sqli_dialect(response_text, headers)
        
        assert dialect == "mssql"
        assert "Unclosed quotation mark" in signals
        assert confident is True
    
    def test_detect_sqli_dialect_sqlite(self):
        """Test SQLite dialect detection."""
        response_text = "SQLiteException: no such table: test"
        headers = {"Server": "Python/3.8"}
        
        dialect, signals, confident = detect_sqli_dialect(response_text, headers)
        
        assert dialect == "sqlite"
        assert "SQLiteException" in signals
        assert confident is True
    
    def test_detect_sqli_dialect_weak_signals(self):
        """Test dialect detection with weak header signals."""
        response_text = "Some generic error"
        headers = {"Server": "PHP/7.4", "X-Powered-By": "PHP"}
        
        dialect, signals, confident = detect_sqli_dialect(response_text, headers)
        
        # Should detect MySQL based on weak signals
        assert dialect == "mysql"
        assert "header:PHP" in signals
        assert confident is False  # Weak signal
    
    def test_detect_sqli_dialect_unknown(self):
        """Test unknown dialect detection."""
        response_text = "Some unknown error message"
        headers = {}
        
        dialect, signals, confident = detect_sqli_dialect(response_text, headers)
        
        assert dialect == "unknown"
        assert len(signals) == 0
        assert confident is False
    
    @patch('backend.modules.probes.sqli_triage.httpx.request')
    def test_run_sqli_probe_with_dialect(self, mock_request):
        """Test SQLi probe returns dialect information."""
        # Mock response with SQL error
        mock_response = Mock()
        mock_response.text = "You have an error in your SQL syntax"
        mock_response.headers = {"Server": "Apache/2.4.41"}
        mock_request.return_value = mock_response
        
        result = run_sqli_probe("http://test.com", "GET", "query", "param")
        
        assert result.error_based is True
        assert result.dialect is not None
        assert result.dialect_signals is not None
        assert isinstance(result.dialect_confident, bool)

class TestRedirectOracle:
    """Test redirect oracle functionality."""
    
    @patch('backend.modules.probes.redirect_oracle.httpx.request')
    def test_redirect_oracle_positive(self, mock_request):
        """Test redirect oracle detects 302 redirect."""
        mock_response = Mock()
        mock_response.status_code = 302
        mock_response.headers = {"Location": "http://evil.com"}
        mock_request.return_value = mock_response
        
        result = run_redirect_probe("http://test.com", "GET", "query", "url")
        
        assert result.redirect_detected is True
        assert result.location == "http://evil.com"
    
    @patch('backend.modules.probes.redirect_oracle.httpx.request')
    def test_redirect_oracle_negative(self, mock_request):
        """Test redirect oracle handles non-redirect response."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_request.return_value = mock_response
        
        result = run_redirect_probe("http://test.com", "GET", "query", "url")
        
        assert result.redirect_detected is False
        assert result.location is None

class TestNoParametersCase:
    """Test handling of targets with no parameters."""
    
    def test_no_parameters_detected(self):
        """Test that targets with no parameters get not_applicable decision."""
        from backend.modules.targets import Target
        
        # Create a target with no parameters
        target = Target(
            url="http://test.com/",
            method="GET",
            param_in=None,
            param=None,
            status=200,
            content_type="text/html"
        )
        
        # This should be handled by gates, but let's verify the decision logic
        from backend.modules.gates import gate_not_applicable
        assert gate_not_applicable(target) is True
