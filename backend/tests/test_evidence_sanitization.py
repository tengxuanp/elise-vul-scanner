import pytest
import tempfile
import os
from pathlib import Path
from backend.modules.evidence import EvidenceRow, write_evidence, _sanitize_filename_component
from backend.app_state import DATA_DIR

def test_sanitize_filename_component():
    """Test filename sanitization with various edge cases."""
    
    # Test cases: (input, expected_output)
    test_cases = [
        # Normal cases
        ("param1", "param1"),
        ("user_id", "user_id"),
        ("query.param", "query.param"),
        ("param-1", "param-1"),
        
        # Slashes and backslashes
        ("param/with/slash", "param_with_slash"),
        ("param\\with\\backslash", "param_with_backslash"),
        
        # Spaces and special characters
        ("param with spaces", "param_with_spaces"),
        ("param@#$%^&*()", "param___________"),
        ("param[with]brackets", "param_with_brackets"),
        
        # Unicode characters
        ("param_中文", "param____"),
        ("param_🚀", "param____"),
        ("param_αβγ", "param____"),
        
        # Mixed cases
        ("param/with spaces & symbols!", "param_with_spaces____symbols_"),
        ("query?param=value&other=123", "query_param_value_other_123"),
        
        # Edge cases
        ("", ""),
        ("   ", "___"),
        ("!@#$%^&*()", "__________"),
    ]
    
    for input_param, expected in test_cases:
        result = _sanitize_filename_component(input_param)
        assert result == expected, f"Failed for input '{input_param}': got '{result}', expected '{expected}'"

def test_write_evidence_with_sanitized_filenames():
    """Test that write_evidence creates safe filenames."""
    
    # Create a temporary directory for testing
    with tempfile.TemporaryDirectory() as temp_dir:
        # Override DATA_DIR for testing
        original_data_dir = DATA_DIR
        test_data_dir = Path(temp_dir)
        
        # Mock the DATA_DIR
        import backend.app_state
        backend.app_state.DATA_DIR = test_data_dir
        
        try:
            # Test evidence with problematic param names
            test_cases = [
                ("param/with/slash", "param_with_slash"),
                ("param with spaces", "param_with_spaces"),
                ("param@#$%", "param____"),
                ("param_中文", "param____"),
            ]
            
            for param_name, expected_safe_name in test_cases:
                # Create evidence with problematic param name
                evidence = EvidenceRow(
                    family="xss",
                    url="http://example.com/test",
                    method="GET",
                    param_in="query",
                    param=param_name,
                    payload="<script>alert(1)</script>",
                    request_headers={},
                    response_status=200,
                    response_snippet="<script>alert(1)</script>",
                    probe_signals={},
                    why=["test"]
                )
                
                # Write evidence
                path = write_evidence("test-job", evidence)
                
                # Check that the filename is safe
                filename = Path(path).name
                assert expected_safe_name in filename, f"Expected '{expected_safe_name}' in filename '{filename}'"
                assert "/" not in filename, f"Filename should not contain slashes: '{filename}'"
                assert " " not in filename, f"Filename should not contain spaces: '{filename}'"
                assert "@" not in filename, f"Filename should not contain @: '{filename}'"
                
                # Check that the file was actually created
                assert Path(path).exists(), f"Evidence file should exist at '{path}'"
                
                # Clean up for next iteration
                Path(path).unlink()
                
        finally:
            # Restore original DATA_DIR
            backend.app_state.DATA_DIR = original_data_dir

def test_write_evidence_content_preservation():
    """Test that evidence content is preserved despite filename sanitization."""
    
    with tempfile.TemporaryDirectory() as temp_dir:
        original_data_dir = DATA_DIR
        test_data_dir = Path(temp_dir)
        
        import backend.app_state
        backend.app_state.DATA_DIR = test_data_dir
        
        try:
            # Create evidence with problematic param name
            evidence = EvidenceRow(
                family="xss",
                url="http://example.com/test",
                method="GET",
                param_in="query",
                param="param/with spaces & symbols!",
                payload="<script>alert(1)</script>",
                request_headers={"User-Agent": "test"},
                response_status=200,
                response_snippet="<script>alert(1)</script>",
                probe_signals={"xss_context": "html"},
                why=["test", "ml_ranked"]
            )
            
            # Write evidence
            path = write_evidence("test-job", evidence)
            
            # Read back the evidence
            import json
            with open(path, 'r', encoding='utf-8') as f:
                loaded_evidence = json.load(f)
            
            # Check that original param name is preserved in content
            assert loaded_evidence["param"] == "param/with spaces & symbols!", "Original param name should be preserved in content"
            assert loaded_evidence["family"] == "xss"
            assert loaded_evidence["payload"] == "<script>alert(1)</script>"
            assert loaded_evidence["why"] == ["test", "ml_ranked"]
            
        finally:
            backend.app_state.DATA_DIR = original_data_dir

if __name__ == "__main__":
    pytest.main([__file__])
