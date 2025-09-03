# backend/modules/ml/enhanced_features.py
from __future__ import annotations

import re
import math
from typing import Dict, Any, List
from urllib.parse import urlparse, parse_qs
from collections import Counter

# --- CRITICAL FIX: Define a fixed order for the 48 features the model expects ---
# The enhanced models were trained with generic feature names (feature_0, feature_1, etc.)
# So we need to output generic names to match what the scaler expects
ORDERED_FEATURE_NAMES = [f'feature_{i}' for i in range(48)]

# Internal mapping for debugging - what each generic feature represents
FEATURE_MAPPING = {
    # Endpoint Features (6)
    'feature_0': 'url_length', 'feature_1': 'path_depth', 'feature_2': 'query_param_count', 
    'feature_3': 'method_post', 'feature_4': 'is_https', 'feature_5': 'path_entropy',
    # Parameter Features (12)
    'feature_6': 'param_name_length', 'feature_7': 'param_value_length', 'feature_8': 'param_name_entropy', 
    'feature_9': 'param_value_entropy', 'feature_10': 'param_name_special_ratio', 'feature_11': 'param_value_special_ratio', 
    'feature_12': 'location_query', 'feature_13': 'location_json', 'feature_14': 'pattern_numeric', 
    'feature_15': 'pattern_uuid', 'feature_16': 'pattern_hex', 'feature_17': 'pattern_base64',
    # Family-Specific Hint Features (6)
    'feature_18': 'sqli_numeric_param', 'feature_19': 'sqli_search_param', 'feature_20': 'xss_content_param', 
    'feature_21': 'xss_display_param', 'feature_22': 'redirect_navigation_param', 'feature_23': 'redirect_callback_param',
    # Payload-Specific Features (16)
    'feature_24': 'payload_length', 'feature_25': 'payload_entropy', 'feature_26': 'payload_special_char_ratio', 
    'feature_27': 'payload_has_quotes', 'feature_28': 'payload_has_sql_keywords', 'feature_29': 'payload_has_sql_functions', 
    'feature_30': 'payload_has_comments', 'feature_31': 'payload_has_script_tags', 'feature_32': 'payload_has_event_handlers', 
    'feature_33': 'payload_has_svg_tags', 'feature_34': 'payload_has_img_tags', 'feature_35': 'payload_has_http_scheme', 
    'feature_36': 'payload_has_protocol_relative', 'feature_37': 'payload_has_encoded_slashes', 'feature_38': 'payload_has_numbers', 
    'feature_39': 'payload_has_uppercase',
    # Security/Business Context Features (8)
    'feature_40': 'security_authentication', 'feature_41': 'security_data_access', 'feature_42': 'security_input_validation',
    'feature_43': 'business_ecommerce', 'feature_44': 'business_banking', 'feature_45': 'business_social', 
    'feature_46': 'business_admin', 'feature_47': 'exposed_in_url'
}


class EnhancedFeatureExtractor:
    """
    Enhanced feature extraction with more sophisticated features for better ML performance.
    """
    
    def __init__(self):
        # Security-sensitive parameter patterns
        self.security_patterns = {
            'authentication': ['auth', 'token', 'jwt', 'session', 'cookie', 'bearer'],
            'authorization': ['role', 'permission', 'access', 'admin', 'user_type'],
            'data_access': ['id', 'user_id', 'customer_id', 'order_id', 'product_id'],
            'input_validation': ['input', 'data', 'content', 'message', 'comment'],
            'file_operations': ['file', 'upload', 'download', 'path', 'filename'],
            'api_operations': ['action', 'method', 'operation', 'command', 'query']
        }
        
        # Business logic indicators
        self.business_contexts = {
            'ecommerce': ['cart', 'checkout', 'payment', 'order', 'product', 'inventory'],
            'banking': ['account', 'transfer', 'balance', 'transaction', 'card'],
            'social': ['profile', 'friend', 'message', 'post', 'comment', 'like'],
            'admin': ['admin', 'manage', 'config', 'settings', 'system', 'user_management']
        }
        
        # Parameter value patterns
        self.value_patterns = {
            'numeric': r'^\d+$',
            'uuid': r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
            'email': r'^[^@]+@[^@]+\.[^@]+$',
            'date': r'^\d{4}-\d{2}-\d{2}$',
            'timestamp': r'^\d{10,13}$',
            'hex': r'^[0-9a-f]+$',
            'base64': r'^[A-Za-z0-9+/]+={0,2}$'
        }
    
    def extract_enhanced_features(self, endpoint: Dict[str, Any], param: Dict[str, Any], 
                                 family: str, context: Dict[str, Any] | None = None) -> Dict[str, float]:
        """
        Extract enhanced features for ML models and return them in a fixed, stable order.
        The models expect generic feature names (feature_0, feature_1, etc.) so we output those.
        """
        # Step 1: Generate all available features into a temporary dictionary using descriptive names.
        # The order in this dictionary is not important.
        generated_features = {}
        generated_features.update(self._extract_endpoint_features(endpoint))
        generated_features.update(self._extract_parameter_features(param))
        generated_features.update(self._extract_family_features(family, param, endpoint))
        
        # --- CRITICAL FIX ---
        # The original code was missing the call to extract payload-specific features.
        # This was causing the model to receive a vector of zeros for all payload characteristics.
        if context and 'payload' in context:
            generated_features.update(self._extract_payload_features(context['payload']))

        generated_features.update(self._extract_relationship_features(endpoint, param))
        generated_features.update(self._extract_security_features(param, endpoint))
        
        # Step 2: Build the final feature dictionary in the correct order with generic names.
        # This guarantees the feature vector is always stable and matches what the scaler expects.
        ordered_features = {}
        for i, generic_name in enumerate(ORDERED_FEATURE_NAMES):
            # Map generic name to descriptive name for lookup
            descriptive_name = FEATURE_MAPPING[generic_name]
            # Use the generated value, or 0.0 if the feature was not generated for this input.
            ordered_features[generic_name] = generated_features.get(descriptive_name, 0.0)
            
        return ordered_features

    
    def _extract_endpoint_features(self, endpoint: Dict[str, Any]) -> Dict[str, float]:
        """Extract endpoint-level features."""
        url = endpoint.get('url', '')
        method = endpoint.get('method', 'GET').upper()
        parsed = urlparse(url)
        
        features = {
            'url_length': len(url),
            'path_depth': len([p for p in parsed.path.split('/') if p]),
            'query_param_count': len(parse_qs(parsed.query)),
            'method_post': 1.0 if method == 'POST' else 0.0,
            'method_put': 1.0 if method == 'PUT' else 0.0,
            'method_delete': 1.0 if method == 'DELETE' else 0.0,
            'has_fragment': 1.0 if parsed.fragment else 0.0,
            'is_https': 1.0 if parsed.scheme == 'https' else 0.0,
            'subdomain_count': len([p for p in parsed.netloc.split('.') if p and p not in ('www', 'api')]),
        }
        
        path_parts = [p for p in parsed.path.split('/') if p]
        features['path_complexity'] = sum(len(p) for p in path_parts) / max(1, len(path_parts))
        features['path_entropy'] = self._calculate_entropy(parsed.path)
        
        return features
    
    def _extract_parameter_features(self, param: Dict[str, Any]) -> Dict[str, float]:
        """Extract parameter-specific features."""
        name = param.get('name', '')
        value = str(param.get('value', ''))
        location = param.get('loc', 'query')
        
        features = {
            'param_name_length': len(name),
            'param_value_length': len(value),
            'param_name_entropy': self._calculate_entropy(name),
            'param_value_entropy': self._calculate_entropy(value),
            'param_name_special_ratio': self._special_char_ratio(name),
            'param_value_special_ratio': self._special_char_ratio(value),
            'location_query': 1.0 if location == 'query' else 0.0,
            'location_form': 1.0 if location == 'form' else 0.0,
            'location_json': 1.0 if location == 'json' else 0.0,
            'location_header': 1.0 if location == 'header' else 0.0,
        }
        
        name_tokens = re.findall(r'[a-zA-Z_][a-zA-Z0-9_]*', name)
        features['param_name_token_count'] = len(name_tokens)
        features['param_name_avg_token_length'] = sum(len(t) for t in name_tokens) / max(1, len(name_tokens))
        features.update(self._match_value_patterns(value))
        
        return features
    
    def _extract_family_features(self, family: str, param: Dict[str, Any], 
                                endpoint: Dict[str, Any]) -> Dict[str, float]:
        """Extract family-specific features."""
        features = {}
        name = param.get('name', '').lower()
        
        if family == 'sqli':
            features.update({
                'sqli_numeric_param': 1.0 if any(p in name for p in ['id', 'num', 'count', 'limit', 'offset']) else 0.0,
                'sqli_search_param': 1.0 if any(p in name for p in ['search', 'query', 'q', 'term', 'keyword']) else 0.0,
            })
        
        elif family == 'xss':
            features.update({
                'xss_content_param': 1.0 if any(p in name for p in ['content', 'body', 'text', 'message', 'comment']) else 0.0,
                'xss_display_param': 1.0 if any(p in name for p in ['title', 'name', 'label', 'caption', 'description']) else 0.0,
            })
        
        elif family == 'redirect':
            features.update({
                'redirect_navigation_param': 1.0 if any(p in name for p in ['next', 'return', 'redirect', 'url', 'target']) else 0.0,
                'redirect_callback_param': 1.0 if any(p in name for p in ['callback', 'cb', 'return_url', 'goto']) else 0.0,
            })
        
        return features
    
    def _extract_payload_features(self, payload: str) -> Dict[str, float]:
        """
        Extracts features directly from the attack payload string.
        This is a new dedicated method to isolate payload feature extraction.
        """
        features = {}
        payload_str = str(payload or '')
        payload_lower = payload_str.lower()
            
        features['payload_length'] = len(payload_str)
        features['payload_entropy'] = self._calculate_entropy(payload_str)
        features['payload_special_char_ratio'] = self._special_char_ratio(payload_str)
        
        features['payload_has_quotes'] = 1.0 if "'" in payload_str or '"' in payload_str else 0.0
        features['payload_has_sql_keywords'] = 1.0 if any(kw in payload_lower for kw in ['union', 'select', 'or', 'and', 'from', 'where']) else 0.0
        features['payload_has_sql_functions'] = 1.0 if any(func in payload_lower for func in ['sleep', 'benchmark', 'waitfor', 'delay']) else 0.0
        features['payload_has_comments'] = 1.0 if '--' in payload_str or '/*' in payload_str or '#' in payload_str else 0.0
        
        features['payload_has_script_tags'] = 1.0 if '<script' in payload_lower else 0.0
        features['payload_has_event_handlers'] = 1.0 if any(handler in payload_lower for handler in ['onerror', 'onload', 'onclick', 'onmouseover']) else 0.0
        features['payload_has_svg_tags'] = 1.0 if '<svg' in payload_lower else 0.0
        features['payload_has_iframe_tags'] = 1.0 if '<iframe' in payload_lower else 0.0
        features['payload_has_img_tags'] = 1.0 if '<img' in payload_lower else 0.0
        
        features['payload_has_http_scheme'] = 1.0 if payload_lower.startswith(('http://', 'https://')) else 0.0
        features['payload_has_protocol_relative'] = 1.0 if payload_lower.startswith('//') else 0.0
        features['payload_has_encoded_slashes'] = 1.0 if '%2f%2f' in payload_lower else 0.0
        
        features['payload_has_numbers'] = 1.0 if any(c.isdigit() for c in payload_str) else 0.0
        features['payload_has_uppercase'] = 1.0 if any(c.isupper() for c in payload_str) else 0.0

        return features

    def _extract_context_features(self, context: Dict[str, Any]) -> Dict[str, float]:
        """Extract context-aware features. Currently, this is a placeholder for future expansion."""
        # This method is kept for future enhancements, such as analyzing HTTP responses
        # or other contextual data that isn't the direct payload.
        features = {}
        return features
    
    def _extract_relationship_features(self, endpoint: Dict[str, Any], param: Dict[str, Any]) -> Dict[str, float]:
        """Extract cross-parameter relationship features."""
        features = {}
        return features
    
    def _extract_security_features(self, param: Dict[str, Any], endpoint: Dict[str, Any]) -> Dict[str, float]:
        """Extract security pattern features."""
        features = {}
        name = param.get('name', '').lower()
        url = endpoint.get('url', '').lower()
        
        for category, patterns in self.security_patterns.items():
            features[f'security_{category}'] = 1.0 if any(p in name for p in patterns) else 0.0
        
        for context, patterns in self.business_contexts.items():
            features[f'business_{context}'] = 1.0 if any(p in url for p in patterns) else 0.0
        
        features['exposed_in_url'] = 1.0 if param.get('loc') == 'query' else 0.0
        
        return features
    
    def _match_value_patterns(self, value: str) -> Dict[str, float]:
        """Match value against common patterns."""
        features = {}
        for pattern_name, pattern in self.value_patterns.items():
            features[f'pattern_{pattern_name}'] = 1.0 if re.match(pattern, value) else 0.0
        return features

    def _calculate_entropy(self, text: str) -> float:
        if not text: return 0.0
        freq = Counter(text)
        length = len(text)
        return -sum((count / length) * math.log2(count / length) for count in freq.values())
    
    def _special_char_ratio(self, text: str) -> float:
        if not text: return 0.0
        special_chars = sum(1 for c in text if not c.isalnum() and not c.isspace())
        return special_chars / len(text)
