#!/usr/bin/env python3
"""
Unit tests for SQLi triage probe
"""

import pytest
import httpx
from unittest.mock import patch, MagicMock
import sys
import os
import time

# Add backend to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from modules.probes.sqli_triage import triage, SQLiTriage


class TestSQLiTriage:
    """Test SQLi triage probe"""
    
    def test_error_based_detection_mysql(self):
        """Test error-based SQLi detection for MySQL"""
        # Mock responses for different SQLi attempts
        baseline_response = MagicMock()
        baseline_response.content = b"<html>Normal response</html>"
        
        error_response = MagicMock()
        error_response.content = b"<html>You have an error in your SQL syntax</html>"
        
        with patch('httpx.Client') as mock_client:
            client_instance = MagicMock()
            mock_client.return_value.__enter__.return_value = client_instance
            
            # Mock the _do function calls
            client_instance.request.side_effect = [
                baseline_response,  # Baseline
                error_response,     # Error-based
                baseline_response,  # Boolean true
                baseline_response,  # Boolean false
                baseline_response,  # Time-based baseline
                baseline_response   # Time-based delay
            ]
            
            result = triage(
                url="http://localhost:5001/product",
                method="GET",
                in_="query",
                param="id"
            )
            
            assert result.error_based == True
            assert result.error_db == "mysql"
            assert result.boolean_delta == 0.0  # No length difference
            assert result.time_based == False   # No time delay
    
    def test_error_based_detection_postgres(self):
        """Test error-based SQLi detection for PostgreSQL"""
        baseline_response = MagicMock()
        baseline_response.content = b"<html>Normal response</html>"
        
        error_response = MagicMock()
        error_response.content = b"<html>org.postgresql.util.PSQLException</html>"
        
        with patch('httpx.Client') as mock_client:
            client_instance = MagicMock()
            mock_client.return_value.__enter__.return_value = client_instance
            
            client_instance.request.side_effect = [
                baseline_response,  # Baseline
                error_response,     # Error-based
                baseline_response,  # Boolean true
                baseline_response,  # Boolean false
                baseline_response,  # Time-based baseline
                baseline_response   # Time-based delay
            ]
            
            result = triage(
                url="http://localhost:5001/api/search",
                method="POST",
                in_="json",
                param="query"
            )
            
            assert result.error_based == True
            assert result.error_db == "postgres"
    
    def test_boolean_based_detection(self):
        """Test boolean-based SQLi detection with length difference"""
        baseline_response = MagicMock()
        baseline_response.content = b"<html>Normal response</html>"  # 25 bytes
        
        true_response = MagicMock()
        true_response.content = b"<html>True response with more content</html>"  # 40 bytes
        
        false_response = MagicMock()
        false_response.content = b"<html>False</html>"  # 15 bytes
        
        with patch('httpx.Client') as mock_client:
            client_instance = MagicMock()
            mock_client.return_value.__enter__.return_value = client_instance
            
            client_instance.request.side_effect = [
                baseline_response,  # Baseline
                baseline_response,  # Error-based (no error)
                true_response,      # Boolean true
                false_response,     # Boolean false
                baseline_response,  # Time-based baseline
                baseline_response   # Time-based delay
            ]
            
            result = triage(
                url="http://localhost:5001/login",
                method="POST",
                in_="form",
                param="username"
            )
            
            assert result.error_based == False
            assert result.error_db is None
            # Delta should be (40-15)/40 = 0.625
            assert result.boolean_delta > 0.1
            assert result.time_based == False
    
    def test_time_based_detection(self):
        """Test time-based SQLi detection with delay"""
        baseline_response = MagicMock()
        baseline_response.content = b"<html>Normal response</html>"
        
        with patch('httpx.Client') as mock_client:
            client_instance = MagicMock()
            mock_client.return_value.__enter__.return_value = client_instance
            
            # Mock time delays
            def mock_request_with_delay(*args, **kwargs):
                # Simulate delay for SLEEP(2) request
                if "SLEEP" in str(args) or "SLEEP" in str(kwargs):
                    time.sleep(0.1)  # Simulate 2 second delay (shortened for test)
                return baseline_response
            
            client_instance.request.side_effect = mock_request_with_delay
            
            # Mock time.time() to simulate delays
            with patch('time.time') as mock_time:
                mock_time.side_effect = [
                    0.0,    # Baseline start
                    0.05,   # Baseline end
                    0.1,    # SLEEP start
                    0.25    # SLEEP end (0.15s delay)
                ]
                
                result = triage(
                    url="http://localhost:5001/api/data",
                    method="POST",
                    in_="json",
                    param="id"
                )
                
                assert result.error_based == False
                assert result.boolean_delta == 0.0
                assert result.time_based == True
                assert result.time_delta_ms > 100  # Should detect the delay
    
    def test_no_sqli_detected(self):
        """Test when no SQLi is detected"""
        baseline_response = MagicMock()
        baseline_response.content = b"<html>Normal response</html>"
        
        with patch('httpx.Client') as mock_client:
            client_instance = MagicMock()
            mock_client.return_value.__enter__.return_value = client_instance
            
            client_instance.request.side_effect = [
                baseline_response,  # Baseline
                baseline_response,  # Error-based (no error)
                baseline_response,  # Boolean true
                baseline_response,  # Boolean false
                baseline_response,  # Time-based baseline
                baseline_response   # Time-based delay
            ]
            
            result = triage(
                url="http://localhost:5001/notes",
                method="GET",
                in_="query",
                param="id"
            )
            
            assert result.error_based == False
            assert result.error_db is None
            assert result.boolean_delta == 0.0
            assert result.time_based == False
            assert result.time_delta_ms == 0.0
    
    def test_multiple_database_errors(self):
        """Test detection of different database error types"""
        error_patterns = [
            (b"mysql_fetch_array()", "mysql"),
            (b"unclosed quotation mark after the character string", "mssql"),
            (b"syntax error at or near", "postgres"),
            (b"sqlite3.OperationalError", "sqlite"),
            (b"ORA-00942", "oracle")
        ]
        
        for error_content, expected_db in error_patterns:
            baseline_response = MagicMock()
            baseline_response.content = b"<html>Normal response</html>"
            
            error_response = MagicMock()
            error_response.content = b"<html>" + error_content + b"</html>"
            
            with patch('httpx.Client') as mock_client:
                client_instance = MagicMock()
                mock_client.return_value.__enter__.return_value = client_instance
                
                client_instance.request.side_effect = [
                    baseline_response,  # Baseline
                    error_response,     # Error-based
                    baseline_response,  # Boolean true
                    baseline_response,  # Boolean false
                    baseline_response,  # Time-based baseline
                    baseline_response   # Time-based delay
                ]
                
                result = triage(
                    url="http://localhost:5001/test",
                    method="GET",
                    in_="query",
                    param="test"
                )
                
                assert result.error_based == True
                assert result.error_db == expected_db
    
    def test_form_parameter_injection(self):
        """Test form parameter injection"""
        baseline_response = MagicMock()
        baseline_response.content = b"<html>Normal response</html>"
        
        error_response = MagicMock()
        error_response.content = b"<html>You have an error in your SQL syntax</html>"
        
        with patch('httpx.Client') as mock_client:
            client_instance = MagicMock()
            mock_client.return_value.__enter__.return_value = client_instance
            
            client_instance.request.side_effect = [
                baseline_response,  # Baseline
                error_response,     # Error-based
                baseline_response,  # Boolean true
                baseline_response,  # Boolean false
                baseline_response,  # Time-based baseline
                baseline_response   # Time-based delay
            ]
            
            result = triage(
                url="http://localhost:5001/login",
                method="POST",
                in_="form",
                param="password"
            )
            
            assert result.error_based == True
            assert result.error_db == "mysql"
    
    def test_json_parameter_injection(self):
        """Test JSON parameter injection"""
        baseline_response = MagicMock()
        baseline_response.content = b"<html>Normal response</html>"
        
        error_response = MagicMock()
        error_response.content = b"<html>You have an error in your SQL syntax</html>"
        
        with patch('httpx.Client') as mock_client:
            client_instance = MagicMock()
            mock_client.return_value.__enter__.return_value = client_instance
            
            client_instance.request.side_effect = [
                baseline_response,  # Baseline
                error_response,     # Error-based
                baseline_response,  # Boolean true
                baseline_response,  # Boolean false
                baseline_response,  # Time-based baseline
                baseline_response   # Time-based delay
            ]
            
            result = triage(
                url="http://localhost:5001/api/search-json",
                method="POST",
                in_="json",
                param="query"
            )
            
            assert result.error_based == True
            assert result.error_db == "mysql"
    
    def test_http_error_handling(self):
        """Test HTTP error handling"""
        with patch('httpx.Client') as mock_client:
            mock_client.return_value.__enter__.return_value.request.side_effect = httpx.HTTPError("Connection failed")
            
            result = triage(
                url="http://localhost:5001/error",
                method="GET",
                in_="query",
                param="test"
            )
            
            # Should return default values on error
            assert result.error_based == False
            assert result.error_db is None
            assert result.boolean_delta == 0.0
            assert result.time_based == False
            assert result.time_delta_ms == 0.0
    
    def test_empty_response_handling(self):
        """Test handling of empty responses"""
        empty_response = MagicMock()
        empty_response.content = b""
        
        with patch('httpx.Client') as mock_client:
            client_instance = MagicMock()
            mock_client.return_value.__enter__.return_value = client_instance
            
            client_instance.request.return_value = empty_response
            
            result = triage(
                url="http://localhost:5001/empty",
                method="GET",
                in_="query",
                param="test"
            )
            
            assert result.error_based == False
            assert result.boolean_delta == 0.0
            assert result.time_based == False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
