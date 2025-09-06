#!/usr/bin/env python3
"""
Unit tests for redirect oracle probe
"""

import pytest
import httpx
from unittest.mock import patch, MagicMock
import sys
import os

# Add backend to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from modules.probes.redirect_oracle import proves_open_redirect


class TestRedirectOracle:
    """Test redirect influence oracle"""
    
    def test_redirect_influence_detected(self):
        """Test redirect influence detection with token in Location header"""
        # Mock response with 302 redirect and token in Location header
        mock_response = MagicMock()
        mock_response.status_code = 302
        mock_response.headers = {"location": "https://elise.invalid/abc123def456"}
        
        with patch('httpx.Client') as mock_client:
            mock_client.return_value.__enter__.return_value.request.return_value = mock_response
            
            # Mock uuid.uuid4() to return a predictable token
            with patch('uuid.uuid4') as mock_uuid:
                mock_uuid.return_value.hex = "abc123def456"
                
                result = proves_open_redirect(
                    url="http://localhost:5001/go",
                    method="GET",
                    param="url"
                )
                
                assert result == (True, 302, "https://elise.invalid/abc123def456")
    
    def test_no_redirect_influence(self):
        """Test no redirect influence when token not in Location header"""
        # Mock response with 302 redirect but no token in Location header
        mock_response = MagicMock()
        mock_response.status_code = 302
        mock_response.headers = {"location": "https://example.com/login"}
        
        with patch('httpx.Client') as mock_client:
            mock_client.return_value.__enter__.return_value.request.return_value = mock_response
            
            with patch('uuid.uuid4') as mock_uuid:
                mock_uuid.return_value.hex = "abc123def456"
                
                result = proves_open_redirect(
                    url="http://localhost:5001/go",
                    method="GET",
                    param="url"
                )
                
                assert result == (False, 302, "https://example.com/login")
    
    def test_non_redirect_status(self):
        """Test non-redirect status code"""
        # Mock response with 200 OK (not a redirect)
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"location": "https://elise.invalid/abc123def456"}
        
        with patch('httpx.Client') as mock_client:
            mock_client.return_value.__enter__.return_value.request.return_value = mock_response
            
            with patch('uuid.uuid4') as mock_uuid:
                mock_uuid.return_value.hex = "abc123def456"
                
                result = proves_open_redirect(
                    url="http://localhost:5001/go",
                    method="GET",
                    param="url"
                )
                
                assert result == (False, 200, "https://elise.invalid/abc123def456")
    
    def test_no_location_header(self):
        """Test response without Location header"""
        # Mock response with 302 redirect but no Location header
        mock_response = MagicMock()
        mock_response.status_code = 302
        mock_response.headers = {}
        
        with patch('httpx.Client') as mock_client:
            mock_client.return_value.__enter__.return_value.request.return_value = mock_response
            
            with patch('uuid.uuid4') as mock_uuid:
                mock_uuid.return_value.hex = "abc123def456"
                
                result = proves_open_redirect(
                    url="http://localhost:5001/go",
                    method="GET",
                    param="url"
                )
                
                assert result == (False, 302, None)
    
    def test_partial_token_match(self):
        """Test partial token match (should not be considered influence)"""
        # Mock response with 302 redirect and partial token in Location header
        mock_response = MagicMock()
        mock_response.status_code = 302
        mock_response.headers = {"location": "https://elise.invalid/abc123"}
        
        with patch('httpx.Client') as mock_client:
            mock_client.return_value.__enter__.return_value.request.return_value = mock_response
            
            with patch('uuid.uuid4') as mock_uuid:
                mock_uuid.return_value.hex = "abc123def456"
                
                result = proves_open_redirect(
                    url="http://localhost:5001/go",
                    method="GET",
                    param="url"
                )
                
                assert result == (False, 302, "https://elise.invalid/abc123")
    
    def test_different_redirect_status_codes(self):
        """Test different redirect status codes"""
        redirect_codes = [301, 302, 303, 307, 308]
        
        for status_code in redirect_codes:
            mock_response = MagicMock()
            mock_response.status_code = status_code
            mock_response.headers = {"location": "https://elise.invalid/abc123def456"}
            
            with patch('httpx.Client') as mock_client:
                mock_client.return_value.__enter__.return_value.request.return_value = mock_response
                
                with patch('uuid.uuid4') as mock_uuid:
                    mock_uuid.return_value.hex = "abc123def456"
                    
                    result = proves_open_redirect(
                        url="http://localhost:5001/go",
                        method="GET",
                        param="url"
                    )
                    
                    assert result == (True, status_code, "https://elise.invalid/abc123def456")
    
    def test_http_error_handling(self):
        """Test HTTP error handling"""
        with patch('httpx.Client') as mock_client:
            mock_client.return_value.__enter__.return_value.request.side_effect = httpx.HTTPError("Connection failed")
            
            result = proves_open_redirect(
                url="http://localhost:5001/error",
                method="GET",
                param="url"
            )
            
            # Should return False on error
            assert result == (False, None, None)
    
    def test_url_injection_format(self):
        """Test that URL injection uses correct format"""
        with patch('httpx.Client') as mock_client:
            mock_response = MagicMock()
            mock_response.status_code = 302
            mock_response.headers = {"location": "https://elise.invalid/abc123def456"}
            mock_client.return_value.__enter__.return_value.request.return_value = mock_response
            
            with patch('uuid.uuid4') as mock_uuid:
                mock_uuid.return_value.hex = "abc123def456"
                
                # Capture the request URL to verify injection format
                request_capture = []
                def capture_request(*args, **kwargs):
                    request_capture.append(args[1])  # URL is second argument
                    return mock_response
                
                mock_client.return_value.__enter__.return_value.request.side_effect = capture_request
                
                proves_open_redirect(
                    url="http://localhost:5001/go?other=value",
                    method="GET",
                    param="url"
                )
                
                # Verify the injected URL format
                injected_url = request_capture[0]
                assert "https://elise.invalid/abc123def456" in injected_url
                assert "other=value" in injected_url  # Other params should be preserved


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
