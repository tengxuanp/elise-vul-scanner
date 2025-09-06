#!/usr/bin/env python3
"""
Unit tests for XSS canary probe
"""

import pytest
import httpx
from unittest.mock import patch, MagicMock
import sys
import os

# Add backend to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from modules.probes.xss_canary import classify_reflection, XSSContext, CANARY_KEY


def create_mock_response_with_canary(content_template: str, timestamp: float = 1234567890.123) -> MagicMock:
    """Helper function to create a mock response with the correct canary"""
    # The function injects the full canary but looks for just the base key in the response
    mock_response = MagicMock()
    mock_response.content = content_template.format(canary=CANARY_KEY).encode()
    return mock_response


class TestXSSCanary:
    """Test XSS canary reflection context classifier"""
    
    def test_html_context_reflection(self):
        """Test HTML context detection"""
        with patch('time.time', return_value=1234567890.123):
            mock_response = create_mock_response_with_canary('<div>{canary}</div>')
            
            with patch('httpx.Client') as mock_client:
                mock_client.return_value.__enter__.return_value.request.return_value = mock_response
                
                result = classify_reflection(
                    url="http://localhost:5001/search",
                    method="GET",
                    in_="query",
                    param="q"
                )
                
                assert result == "html"
    
    def test_attr_context_reflection(self):
        """Test attribute context detection"""
        with patch('time.time', return_value=1234567890.123):
            mock_response = create_mock_response_with_canary('<a href="#" title="{canary}">Link</a>')
            
            with patch('httpx.Client') as mock_client:
                mock_client.return_value.__enter__.return_value.request.return_value = mock_response
                
                result = classify_reflection(
                    url="http://localhost:5001/profile",
                    method="GET",
                    in_="query",
                    param="name"
                )
                
                assert result == "attr"
    
    def test_js_string_context_reflection(self):
        """Test JavaScript string context detection"""
        with patch('time.time', return_value=1234567890.123):
            mock_response = create_mock_response_with_canary('<script>var a="{canary}";</script>')
            
            with patch('httpx.Client') as mock_client:
                mock_client.return_value.__enter__.return_value.request.return_value = mock_response
                
                result = classify_reflection(
                    url="http://localhost:5001/script",
                    method="GET",
                    in_="query",
                    param="msg"
                )
                
                assert result == "js_string"
    
    def test_no_reflection(self):
        """Test no reflection detection"""
        with patch('time.time', return_value=1234567890.123):
            mock_response = MagicMock()
            mock_response.content = b'<div>No canary here</div>'
            
            with patch('httpx.Client') as mock_client:
                mock_client.return_value.__enter__.return_value.request.return_value = mock_response
                
                result = classify_reflection(
                    url="http://localhost:5001/notes",
                    method="GET",
                    in_="query",
                    param="id"
                )
                
                assert result == "none"
    
    def test_form_parameter_injection(self):
        """Test form parameter injection"""
        with patch('time.time', return_value=1234567890.123):
            mock_response = create_mock_response_with_canary('<div>{canary}</div>')
            
            with patch('httpx.Client') as mock_client:
                mock_client.return_value.__enter__.return_value.request.return_value = mock_response
                
                result = classify_reflection(
                    url="http://localhost:5001/login",
                    method="POST",
                    in_="form",
                    param="username"
                )
                
                assert result == "html"
    
    def test_json_parameter_injection(self):
        """Test JSON parameter injection"""
        with patch('time.time', return_value=1234567890.123):
            mock_response = create_mock_response_with_canary('<div>{canary}</div>')
            
            with patch('httpx.Client') as mock_client:
                mock_client.return_value.__enter__.return_value.request.return_value = mock_response
                
                result = classify_reflection(
                    url="http://localhost:5001/api/search-json",
                    method="POST",
                    in_="json",
                    param="query"
                )
                
                assert result == "html"
    
    def test_js_context_without_quotes(self):
        """Test JavaScript context without surrounding quotes"""
        with patch('time.time', return_value=1234567890.123):
            mock_response = create_mock_response_with_canary('<script>var a={canary};</script>')
            
            with patch('httpx.Client') as mock_client:
                mock_client.return_value.__enter__.return_value.request.return_value = mock_response
                
                result = classify_reflection(
                    url="http://localhost:5001/script",
                    method="GET",
                    in_="query",
                    param="msg"
                )
                
                # Should still be js_string because it's in a script block
                assert result == "js_string"
    
    def test_multiple_contexts_priority(self):
        """Test priority when canary appears in multiple contexts"""
        with patch('time.time', return_value=1234567890.123):
            mock_response = create_mock_response_with_canary('<div title="{canary}">{canary}</div>')
            
            with patch('httpx.Client') as mock_client:
                mock_client.return_value.__enter__.return_value.request.return_value = mock_response
                
                result = classify_reflection(
                    url="http://localhost:5001/test",
                    method="GET",
                    in_="query",
                    param="test"
                )
                
                # Attribute context should take priority
                assert result == "attr"
    
    def test_empty_response(self):
        """Test empty response handling"""
        with patch('time.time', return_value=1234567890.123):
            mock_response = MagicMock()
            mock_response.content = b''
            
            with patch('httpx.Client') as mock_client:
                mock_client.return_value.__enter__.return_value.request.return_value = mock_response
                
                result = classify_reflection(
                    url="http://localhost:5001/empty",
                    method="GET",
                    in_="query",
                    param="test"
                )
                
                assert result == "none"
    
    def test_http_error_handling(self):
        """Test HTTP error handling"""
        with patch('time.time', return_value=1234567890.123):
            with patch('httpx.Client') as mock_client:
                mock_client.return_value.__enter__.return_value.request.side_effect = httpx.HTTPError("Connection failed")
                
                result = classify_reflection(
                    url="http://localhost:5001/error",
                    method="GET",
                    in_="query",
                    param="test"
                )
                
                # Should return none on error
                assert result == "none"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
