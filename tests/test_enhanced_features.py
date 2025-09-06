"""
Tests for Enhanced Features V1

Tests the EnhancedFeaturesV1 schema and extract_features_v1 function
with various endpoint and parameter combinations.
"""

import pytest
import sys
import os
from typing import Dict, Any

# Add backend to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from modules.ml.enhanced_features import (
    EnhancedFeaturesV1, 
    extract_features_v1,
    _calculate_entropy,
    _detect_naming_convention,
    _extract_content_type_features,
    _extract_location_features,
    _extract_method_features,
    _extract_path_features,
    _extract_pre_signals,
    _extract_probe_diffs
)


class TestEnhancedFeaturesV1:
    """Test the EnhancedFeaturesV1 schema validation."""
    
    def test_schema_validation(self):
        """Test that the schema validates correctly with all required fields."""
        features = {
            'schema_version': 'enh-feats-v1',
            
            # One-hot encodings
            'loc_query': 1, 'loc_form': 0, 'loc_json': 0,
            'method_get': 1, 'method_post': 0, 'method_other': 0,
            'ct_json': 0, 'ct_form': 1, 'ct_other': 0,
            
            # Parameter semantics
            'param_len': 5, 'param_entropy': 0.8, 'is_snake': 1, 'is_camel': 0,
            'name_has_id': 1, 'name_has_token': 0, 'name_has_q': 0, 'name_has_redirect': 0,
            'name_has_search': 0, 'name_has_user': 0, 'name_has_auth': 0, 'name_has_pass': 0,
            
            # Endpoint context
            'path_depth': 3, 'has_admin': 0, 'has_login': 1, 'has_cart': 0, 'has_profile': 0,
            
            # Pre-signals
            'prev_reflect_raw': 0, 'prev_reflect_html': 0, 'prev_reflect_attr': 0,
            'prev_sql_error': 1, 'prev_redirect_signal': 0,
            
            # Cheap probe diffs
            'prev_status_delta': 200, 'prev_len_delta': 1500,
        }
        
        validated = EnhancedFeaturesV1(**features)
        assert validated.schema_version == 'enh-feats-v1'
        assert validated.loc_query == 1
        assert validated.param_len == 5
    
    def test_schema_frozen(self):
        """Test that the schema is frozen (immutable)."""
        features = {
            'schema_version': 'enh-feats-v1',
            'loc_query': 1, 'loc_form': 0, 'loc_json': 0,
            'method_get': 1, 'method_post': 0, 'method_other': 0,
            'ct_json': 0, 'ct_form': 1, 'ct_other': 0,
            'param_len': 5, 'param_entropy': 0.8, 'is_snake': 1, 'is_camel': 0,
            'name_has_id': 1, 'name_has_token': 0, 'name_has_q': 0, 'name_has_redirect': 0,
            'name_has_search': 0, 'name_has_user': 0, 'name_has_auth': 0, 'name_has_pass': 0,
            'path_depth': 3, 'has_admin': 0, 'has_login': 1, 'has_cart': 0, 'has_profile': 0,
            'prev_reflect_raw': 0, 'prev_reflect_html': 0, 'prev_reflect_attr': 0,
            'prev_sql_error': 1, 'prev_redirect_signal': 0,
            'prev_status_delta': 200, 'prev_len_delta': 1500,
        }
        
        validated = EnhancedFeaturesV1(**features)
        
        # Should raise error when trying to modify
        with pytest.raises(ValueError):
            validated.param_len = 10
    
    def test_boolean_constraints(self):
        """Test that boolean fields are constrained to 0 or 1."""
        base_features = {
            'schema_version': 'enh-feats-v1',
            'loc_query': 1, 'loc_form': 0, 'loc_json': 0,
            'method_get': 1, 'method_post': 0, 'method_other': 0,
            'ct_json': 0, 'ct_form': 1, 'ct_other': 0,
            'param_len': 5, 'param_entropy': 0.8, 'is_snake': 1, 'is_camel': 0,
            'name_has_id': 1, 'name_has_token': 0, 'name_has_q': 0, 'name_has_redirect': 0,
            'name_has_search': 0, 'name_has_user': 0, 'name_has_auth': 0, 'name_has_pass': 0,
            'path_depth': 3, 'has_admin': 0, 'has_login': 1, 'has_cart': 0, 'has_profile': 0,
            'prev_reflect_raw': 0, 'prev_reflect_html': 0, 'prev_reflect_attr': 0,
            'prev_sql_error': 1, 'prev_redirect_signal': 0,
            'prev_status_delta': 200, 'prev_len_delta': 1500,
        }
        
        # Test valid boolean values
        for field in ['loc_query', 'is_snake', 'name_has_id', 'has_login']:
            features = base_features.copy()
            features[field] = 1
            EnhancedFeaturesV1(**features)
            
            features[field] = 0
            EnhancedFeaturesV1(**features)
        
        # Test invalid boolean values
        for field in ['loc_query', 'is_snake', 'name_has_id', 'has_login']:
            features = base_features.copy()
            features[field] = 2  # Invalid
            with pytest.raises(ValueError):
                EnhancedFeaturesV1(**features)


class TestExtractFeaturesV1:
    """Test the extract_features_v1 function."""
    
    def test_basic_extraction(self):
        """Test basic feature extraction with minimal endpoint/param."""
        endpoint = {
            'url': 'https://example.com/api/search',
            'method': 'GET',
            'param_locs': {'query': ['q', 'limit']},
            'content_type': 'application/json'
        }
        
        param = {
            'name': 'q'
        }
        
        features = extract_features_v1(endpoint, param)
        
        # Check schema version
        assert features['_schema_version'] == 'enh-feats-v1'
        
        # Check all required keys exist
        required_keys = [
            '_schema_version', 'loc_query', 'loc_form', 'loc_json',
            'method_get', 'method_post', 'method_other',
            'ct_json', 'ct_form', 'ct_other',
            'param_len', 'param_entropy', 'is_snake', 'is_camel',
            'name_has_id', 'name_has_token', 'name_has_q', 'name_has_redirect',
            'name_has_search', 'name_has_user', 'name_has_auth', 'name_has_pass',
            'path_depth', 'has_admin', 'has_login', 'has_cart', 'has_profile',
            'prev_reflect_raw', 'prev_reflect_html', 'prev_reflect_attr',
            'prev_sql_error', 'prev_redirect_signal',
            'prev_status_delta', 'prev_len_delta'
        ]
        
        for key in required_keys:
            assert key in features, f"Missing key: {key}"
        
        # Check one-hot consistency
        assert features['loc_query'] + features['loc_form'] + features['loc_json'] == 1
        assert features['method_get'] + features['method_post'] + features['method_other'] == 1
        assert features['ct_json'] + features['ct_form'] + features['ct_other'] == 1
        
        # Check boolean constraints
        boolean_fields = [
            'loc_query', 'loc_form', 'loc_json', 'method_get', 'method_post', 'method_other',
            'ct_json', 'ct_form', 'ct_other', 'is_snake', 'is_camel',
            'name_has_id', 'name_has_token', 'name_has_q', 'name_has_redirect',
            'name_has_search', 'name_has_user', 'name_has_auth', 'name_has_pass',
            'has_admin', 'has_login', 'has_cart', 'has_profile',
            'prev_reflect_raw', 'prev_reflect_html', 'prev_reflect_attr',
            'prev_sql_error', 'prev_redirect_signal'
        ]
        
        for field in boolean_fields:
            assert features[field] in [0, 1], f"Field {field} should be 0 or 1, got {features[field]}"
    
    def test_query_parameter(self):
        """Test extraction for query parameter."""
        endpoint = {
            'url': 'https://example.com/api/search',
            'method': 'GET',
            'param_locs': {'query': ['q']},
            'content_type': 'text/html'
        }
        
        param = {'name': 'q'}
        
        features = extract_features_v1(endpoint, param)
        
        assert features['loc_query'] == 1
        assert features['loc_form'] == 0
        assert features['loc_json'] == 0
        assert features['method_get'] == 1
        assert features['name_has_q'] == 1
        assert features['param_len'] == 1
    
    def test_form_parameter(self):
        """Test extraction for form parameter."""
        endpoint = {
            'url': 'https://example.com/api/login',
            'method': 'POST',
            'param_locs': {'form': ['username', 'password']},
            'content_type': 'application/x-www-form-urlencoded'
        }
        
        param = {'name': 'username'}
        
        features = extract_features_v1(endpoint, param)
        
        assert features['loc_query'] == 0
        assert features['loc_form'] == 1
        assert features['loc_json'] == 0
        assert features['method_post'] == 1
        assert features['ct_form'] == 1
        assert features['name_has_user'] == 1
        assert features['has_login'] == 1
    
    def test_json_parameter(self):
        """Test extraction for JSON parameter."""
        endpoint = {
            'url': 'https://example.com/api/users',
            'method': 'POST',
            'param_locs': {'json': ['user_id', 'email']},
            'content_type': 'application/json'
        }
        
        param = {'name': 'user_id'}
        
        features = extract_features_v1(endpoint, param)
        
        assert features['loc_query'] == 0
        assert features['loc_form'] == 0
        assert features['loc_json'] == 1
        assert features['ct_json'] == 1
        assert features['name_has_id'] == 1
        assert features['name_has_user'] == 1
    
    def test_snake_case_detection(self):
        """Test snake_case parameter detection."""
        endpoint = {
            'url': 'https://example.com/api',
            'method': 'GET',
            'param_locs': {'query': ['user_id', 'session_token']},
        }
        
        param = {'name': 'user_id'}
        
        features = extract_features_v1(endpoint, param)
        
        assert features['is_snake'] == 1
        assert features['is_camel'] == 0
    
    def test_camel_case_detection(self):
        """Test camelCase parameter detection."""
        endpoint = {
            'url': 'https://example.com/api',
            'method': 'GET',
            'param_locs': {'query': ['userId', 'sessionToken']},
        }
        
        param = {'name': 'userId'}
        
        features = extract_features_v1(endpoint, param)
        
        assert features['is_snake'] == 0
        assert features['is_camel'] == 1
    
    def test_path_context_features(self):
        """Test path context feature extraction."""
        endpoint = {
            'url': 'https://example.com/admin/users/profile',
            'method': 'GET',
            'param_locs': {'query': ['id']},
        }
        
        param = {'name': 'id'}
        
        features = extract_features_v1(endpoint, param)
        
        assert features['path_depth'] == 3
        assert features['has_admin'] == 1
        assert features['has_profile'] == 1
        assert features['has_login'] == 0
        assert features['has_cart'] == 0
    
    def test_pre_signals(self):
        """Test pre-signals extraction."""
        endpoint = {
            'url': 'https://example.com/api',
            'method': 'GET',
            'param_locs': {'query': ['q']},
        }
        
        param = {'name': 'q'}
        
        pre = {
            'signals': {
                'xss_reflected': True,
                'sql_error': True,
                'external_redirect': False
            },
            'status_delta': 200,
            'len_delta': 1500
        }
        
        features = extract_features_v1(endpoint, param, pre=pre)
        
        assert features['prev_reflect_raw'] == 1
        assert features['prev_sql_error'] == 1
        assert features['prev_redirect_signal'] == 0
        assert features['prev_status_delta'] == 200
        assert features['prev_len_delta'] == 1500
    
    def test_entropy_calculation(self):
        """Test parameter name entropy calculation."""
        endpoint = {
            'url': 'https://example.com/api',
            'method': 'GET',
            'param_locs': {'query': ['a', 'ab', 'abc', 'abcd']},
        }
        
        # Test different parameter names
        test_cases = [
            ('a', 0.0),      # Single character
            ('ab', 1.0),     # Two different characters
            ('aa', 0.0),     # Two same characters
            ('abc', 1.0),    # Three different characters
            ('aabbcc', 1.0), # Repeated but balanced
        ]
        
        for param_name, expected_entropy in test_cases:
            param = {'name': param_name}
            features = extract_features_v1(endpoint, param)
            assert abs(features['param_entropy'] - expected_entropy) < 0.1, f"Entropy mismatch for '{param_name}'"
    
    def test_semantic_name_features(self):
        """Test semantic parameter name features."""
        endpoint = {
            'url': 'https://example.com/api',
            'method': 'GET',
            'param_locs': {'query': ['search', 'redirect_url', 'auth_token', 'user_pass']},
        }
        
        test_cases = [
            ('search', {'name_has_search': 1, 'name_has_redirect': 0, 'name_has_auth': 0, 'name_has_pass': 0}),
            ('redirect_url', {'name_has_search': 0, 'name_has_redirect': 1, 'name_has_auth': 0, 'name_has_pass': 0}),
            ('auth_token', {'name_has_search': 0, 'name_has_redirect': 0, 'name_has_auth': 1, 'name_has_token': 1}),
            ('user_pass', {'name_has_search': 0, 'name_has_redirect': 0, 'name_has_auth': 0, 'name_has_pass': 1, 'name_has_user': 1}),
        ]
        
        for param_name, expected_features in test_cases:
            param = {'name': param_name}
            features = extract_features_v1(endpoint, param)
            
            for feature_name, expected_value in expected_features.items():
                assert features[feature_name] == expected_value, f"Feature {feature_name} mismatch for '{param_name}'"
    
    def test_edge_cases(self):
        """Test edge cases and error handling."""
        # Empty endpoint
        endpoint = {}
        param = {'name': 'test'}
        
        features = extract_features_v1(endpoint, param)
        assert features['_schema_version'] == 'enh-feats-v1'
        
        # Empty param
        endpoint = {'url': 'https://example.com', 'method': 'GET'}
        param = {}
        
        features = extract_features_v1(endpoint, param)
        assert features['param_len'] == 0
        
        # None values
        endpoint = {'url': None, 'method': None, 'param_locs': None}
        param = {'name': None}
        
        features = extract_features_v1(endpoint, param)
        assert features['_schema_version'] == 'enh-feats-v1'


class TestHelperFunctions:
    """Test helper functions."""
    
    def test_calculate_entropy(self):
        """Test entropy calculation function."""
        assert _calculate_entropy('') == 0.0
        assert _calculate_entropy('a') == 0.0
        assert _calculate_entropy('ab') == 1.0
        assert _calculate_entropy('aa') == 0.0
        assert _calculate_entropy('abc') == 1.0
    
    def test_detect_naming_convention(self):
        """Test naming convention detection."""
        assert _detect_naming_convention('user_id') == (1, 0)  # snake_case
        assert _detect_naming_convention('userId') == (0, 1)   # camelCase
        assert _detect_naming_convention('userid') == (0, 0)   # neither
        assert _detect_naming_convention('') == (0, 0)         # empty
    
    def test_extract_content_type_features(self):
        """Test content type feature extraction."""
        assert _extract_content_type_features('application/json') == (1, 0, 0)
        assert _extract_content_type_features('application/x-www-form-urlencoded') == (0, 1, 0)
        assert _extract_content_type_features('text/html') == (0, 0, 1)
        assert _extract_content_type_features(None) == (0, 0, 1)
    
    def test_extract_method_features(self):
        """Test method feature extraction."""
        assert _extract_method_features('GET') == (1, 0, 0)
        assert _extract_method_features('POST') == (0, 1, 0)
        assert _extract_method_features('PUT') == (0, 0, 1)
        assert _extract_method_features(None) == (1, 0, 0)
    
    def test_extract_path_features(self):
        """Test path feature extraction."""
        path_depth, has_admin, has_login, has_cart, has_profile = _extract_path_features('https://example.com/admin/users/profile')
        assert path_depth == 3
        assert has_admin == 1
        assert has_profile == 1
        assert has_login == 0
        assert has_cart == 0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
