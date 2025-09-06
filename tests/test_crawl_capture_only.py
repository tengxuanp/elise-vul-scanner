"""
Unit tests for capture-only crawling functionality
Tests that no pattern_fallback endpoints are included by default
"""

import pytest
import json
from unittest.mock import Mock, patch, AsyncMock
from fastapi.testclient import TestClient
from backend.routes.enhanced_crawl_routes import router
from backend.modules.crawler.enhanced_crawler import CapturedEndpoint, EnhancedCrawler

# Create test client
from fastapi import FastAPI
app = FastAPI()
app.include_router(router, prefix="/api")
client = TestClient(app)

class TestCaptureOnlyCrawling:
    """Test capture-only crawling functionality"""
    
    def test_captured_endpoint_creation(self):
        """Test CapturedEndpoint dataclass creation"""
        endpoint = CapturedEndpoint(
            url="https://example.com/search",
            path="search",
            method="GET",
            param_names=["q", "limit"],
            content_type="text/html",
            status=200,
            source="document"
        )
        
        assert endpoint.url == "https://example.com/search"
        assert endpoint.path == "search"
        assert endpoint.method == "GET"
        assert endpoint.param_names == ["q", "limit"]
        assert endpoint.content_type == "text/html"
        assert endpoint.status == 200
        assert endpoint.source == "document"
    
    def test_enhanced_crawler_initialization(self):
        """Test EnhancedCrawler initialization"""
        crawler = EnhancedCrawler()
        
        assert crawler.captured_requests == []
        assert crawler.captured_endpoints == {}
        assert crawler.start_url is None
        assert crawler.start_origin is None
    
    def test_normalize_path(self):
        """Test path normalization"""
        crawler = EnhancedCrawler()
        
        assert crawler._normalize_path("/search") == "search"
        assert crawler._normalize_path("search") == "search"
        assert crawler._normalize_path("/api/users") == "api/users"
        assert crawler._normalize_path("") == ""
    
    def test_get_origin(self):
        """Test origin extraction"""
        crawler = EnhancedCrawler()
        
        assert crawler._get_origin("https://example.com/search") == "https://example.com"
        assert crawler._get_origin("http://localhost:5001/api") == "http://localhost:5001"
        assert crawler._get_origin("https://subdomain.example.com:8080/path") == "https://subdomain.example.com:8080"
    
    def test_extract_param_names_from_query(self):
        """Test parameter name extraction from query string"""
        crawler = EnhancedCrawler()
        
        request_data = {
            'url': 'https://example.com/search?q=test&limit=10&page=1'
        }
        
        param_names = crawler._extract_param_names(request_data)
        assert set(param_names) == {"q", "limit", "page"}
    
    def test_extract_param_names_from_form_data(self):
        """Test parameter name extraction from form data"""
        crawler = EnhancedCrawler()
        
        request_data = {
            'url': 'https://example.com/login',
            'content_type': 'application/x-www-form-urlencoded',
            'post_data': 'username=admin&password=secret&remember=true'
        }
        
        param_names = crawler._extract_param_names(request_data)
        assert set(param_names) == {"username", "password", "remember"}
    
    def test_extract_param_names_from_json(self):
        """Test parameter name extraction from JSON data"""
        crawler = EnhancedCrawler()
        
        request_data = {
            'url': 'https://example.com/api/users',
            'content_type': 'application/json',
            'post_data': '{"name": "John", "email": "john@example.com", "age": 30}'
        }
        
        param_names = crawler._extract_param_names(request_data)
        assert set(param_names) == {"name", "email", "age"}
    
    def test_determine_source(self):
        """Test source determination"""
        crawler = EnhancedCrawler()
        
        # Document navigation
        assert crawler._determine_source({'resource_type': 'document'}) == 'document'
        
        # Form submission
        assert crawler._determine_source({
            'method': 'POST',
            'content_type': 'application/x-www-form-urlencoded'
        }) == 'form_submit'
        
        # JSON submission
        assert crawler._determine_source({
            'method': 'POST',
            'content_type': 'application/json'
        }) == 'form_submit'
        
        # XHR/Fetch
        assert crawler._determine_source({'resource_type': 'xhr'}) == 'xhr_fetch'
        assert crawler._determine_source({'resource_type': 'fetch'}) == 'xhr_fetch'
    
    def test_create_endpoint_key(self):
        """Test endpoint deduplication key creation"""
        crawler = EnhancedCrawler()
        
        endpoint = CapturedEndpoint(
            url="https://example.com/search",
            path="search",
            method="GET",
            param_names=["q", "limit"],
            content_type="text/html; charset=utf-8",
            status=200,
            source="document"
        )
        
        key = crawler._create_endpoint_key(endpoint)
        expected = ("GET", "search", ("q", "limit"), "text/html")
        assert key == expected
    
    @patch('backend.routes.enhanced_crawl_routes.crawl_capture_only')
    def test_crawl_endpoint_default_behavior(self, mock_crawl):
        """Test that /api/crawl returns only capture-only endpoints by default"""
        # Mock captured endpoints
        mock_crawl.return_value = [
            {
                "url": "https://example.com/search",
                "path": "search",
                "method": "GET",
                "param_names": ["q"],
                "content_type": "text/html",
                "status": 200,
                "source": "document"
            },
            {
                "url": "https://example.com/api/users",
                "path": "api/users",
                "method": "POST",
                "param_names": ["name", "email"],
                "content_type": "application/json",
                "status": 201,
                "source": "xhr_fetch"
            }
        ]
        
        # Test request
        response = client.post(
            "/api/crawl",
            json={
                "target_url": "https://example.com",
                "max_depth": 2,
                "max_endpoints": 10
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Verify response structure
        assert data["status"] == "success"
        assert data["capture_only"] is True
        assert data["pattern_fallback_used"] is False
        assert data["discovered_endpoints"] == 2
        
        # Verify all endpoints are capture-only (no pattern_fallback)
        for endpoint in data["endpoints"]:
            assert endpoint["source"] != "pattern_fallback"
            assert endpoint["source"] in ["document", "xhr_fetch", "form_submit"]
        
        # Verify ready_for_fuzzing logic
        assert data["ready_for_fuzzing"] is True  # Both endpoints have params and good status
    
    @patch('backend.routes.enhanced_crawl_routes.crawl_capture_only')
    @patch('backend.routes.enhanced_crawl_routes.discover_endpoints_dynamically')
    def test_crawl_endpoint_with_pattern_fallback(self, mock_pattern, mock_crawl):
        """Test that /api/crawl includes pattern endpoints when allow_pattern_fallback=true"""
        # Mock captured endpoints
        mock_crawl.return_value = [
            {
                "url": "https://example.com/search",
                "path": "search",
                "method": "GET",
                "param_names": ["q"],
                "content_type": "text/html",
                "status": 200,
                "source": "document"
            }
        ]
        
        # Mock pattern endpoints
        mock_pattern.return_value = [
            {
                "url": "https://example.com/admin",
                "path": "admin",
                "method": "GET",
                "param_names": [],
                "content_type": "text/html",
                "status": 404,
                "source": "pattern_fallback"
            }
        ]
        
        # Test request with pattern fallback enabled
        response = client.post(
            "/api/crawl?allow_pattern_fallback=true",
            json={
                "target_url": "https://example.com",
                "max_depth": 2,
                "max_endpoints": 10
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Verify response structure
        assert data["status"] == "success"
        assert data["capture_only"] is False
        assert data["pattern_fallback_used"] is True
        assert data["discovered_endpoints"] == 1  # Only count capture-only
        
        # Verify endpoints include both capture-only and pattern
        endpoints = data["endpoints"]
        assert len(endpoints) == 2
        
        # First endpoint should be capture-only
        assert endpoints[0]["source"] == "document"
        
        # Second endpoint should be pattern fallback
        assert endpoints[1]["source"] == "pattern_fallback"
    
    @patch('backend.routes.enhanced_crawl_routes.crawl_capture_only')
    def test_crawl_endpoint_no_fuzzing_ready(self, mock_crawl):
        """Test ready_for_fuzzing=false when no endpoints have params"""
        # Mock captured endpoints without parameters
        mock_crawl.return_value = [
            {
                "url": "https://example.com/",
                "path": "",
                "method": "GET",
                "param_names": [],
                "content_type": "text/html",
                "status": 200,
                "source": "document"
            },
            {
                "url": "https://example.com/about",
                "path": "about",
                "method": "GET",
                "param_names": [],
                "content_type": "text/html",
                "status": 200,
                "source": "document"
            }
        ]
        
        # Test request
        response = client.post(
            "/api/crawl",
            json={
                "target_url": "https://example.com",
                "max_depth": 2,
                "max_endpoints": 10
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Verify ready_for_fuzzing is False
        assert data["ready_for_fuzzing"] is False
    
    @patch('backend.routes.enhanced_crawl_routes.crawl_capture_only')
    def test_crawl_endpoint_bad_status_codes(self, mock_crawl):
        """Test ready_for_fuzzing=false when endpoints have bad status codes"""
        # Mock captured endpoints with bad status codes
        mock_crawl.return_value = [
            {
                "url": "https://example.com/search",
                "path": "search",
                "method": "GET",
                "param_names": ["q"],
                "content_type": "text/html",
                "status": 404,  # Bad status
                "source": "document"
            },
            {
                "url": "https://example.com/api/users",
                "path": "api/users",
                "method": "POST",
                "param_names": ["name"],
                "content_type": "application/json",
                "status": 500,  # Bad status
                "source": "xhr_fetch"
            }
        ]
        
        # Test request
        response = client.post(
            "/api/crawl",
            json={
                "target_url": "https://example.com",
                "max_depth": 2,
                "max_endpoints": 10
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Verify ready_for_fuzzing is False due to bad status codes
        assert data["ready_for_fuzzing"] is False
    
    def test_crawl_endpoint_missing_target_url(self):
        """Test error handling for missing target_url"""
        response = client.post(
            "/api/crawl",
            json={
                "max_depth": 2,
                "max_endpoints": 10
            }
        )
        
        assert response.status_code == 400
        assert "target_url is required" in response.json()["detail"]

if __name__ == "__main__":
    pytest.main([__file__])
