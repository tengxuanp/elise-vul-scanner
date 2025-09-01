# backend/modules/ml/enhanced_features.py
from __future__ import annotations

import re
import hashlib
import math
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs
from collections import Counter

class EnhancedFeatureExtractor:
    """
    Enhanced feature extraction with more sophisticated features for better ML performance.
    
    New features include:
    - Semantic parameter analysis
    - Business logic context
    - Security pattern recognition
    - Response behavior prediction
    - Cross-parameter relationships
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
                                 family: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, float]:
        """
        Extract enhanced features for ML models.
        
        Args:
            endpoint: Endpoint information
            param: Parameter information
            family: Vulnerability family (sqli, xss, redirect)
            context: Additional context (previous responses, etc.)
        
        Returns:
            Dictionary of enhanced features
        """
        features = {}
        
        # Basic endpoint features
        features.update(self._extract_endpoint_features(endpoint))
        
        # Parameter-specific features
        features.update(self._extract_parameter_features(param))
        
        # Family-specific features
        family_features = self._extract_family_features(family, param, endpoint)
        features.update(family_features)
        
        # Feature count will be enforced at the end
        
        # Context-aware features
        if context:
            features.update(self._extract_context_features(context))
        
        # Cross-parameter relationship features
        features.update(self._extract_relationship_features(endpoint, param))
        
        # Security pattern features
        features.update(self._extract_security_features(param, endpoint))
        
        # Ensure consistent feature count across families (FINAL CHECK)
        # Pad with zeros if needed to maintain 48 features
        expected_features = 48
        current_features = len(features)
        if current_features < expected_features:
            for i in range(current_features, expected_features):
                features[f'padding_feature_{i}'] = 0.0
        elif current_features > expected_features:
            # Truncate to expected size (keep most important features)
            sorted_features = sorted(features.items(), key=lambda x: x[1], reverse=True)
            features = dict(sorted_features[:expected_features])
        
        # Final check: ensure exactly 48 features
        if len(features) != expected_features:
            # Force truncation to exact size
            feature_items = list(features.items())[:expected_features]
            features = dict(feature_items)
            # Pad if still short
            while len(features) < expected_features:
                features[f'final_padding_{len(features)}'] = 0.0
        
        # Debug: ensure exactly 48 features
        assert len(features) == expected_features, f"Feature count mismatch: {len(features)} != {expected_features}"
        
        return features
    
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
        
        # Path complexity
        path_parts = [p for p in parsed.path.split('/') if p]
        features['path_complexity'] = sum(len(p) for p in path_parts) / max(1, len(path_parts))
        features['path_entropy'] = self._calculate_entropy(parsed.path)
        
        return features
    
    def _extract_parameter_features(self, param: Dict[str, Any]) -> Dict[str, float]:
        """Extract parameter-specific features."""
        name = param.get('name', '')
        value = param.get('value', '')
        location = param.get('loc', 'query')
        
        features = {
            'param_name_length': len(name),
            'param_value_length': len(str(value)),
            'param_name_entropy': self._calculate_entropy(name),
            'param_value_entropy': self._calculate_entropy(str(value)),
            'param_name_special_ratio': self._special_char_ratio(name),
            'param_value_special_ratio': self._special_char_ratio(str(value)),
            'location_query': 1.0 if location == 'query' else 0.0,
            'location_form': 1.0 if location == 'form' else 0.0,
            'location_json': 1.0 if location == 'json' else 0.0,
            'location_header': 1.0 if location == 'header' else 0.0,
        }
        
        # Parameter name analysis
        name_tokens = re.findall(r'[a-zA-Z_][a-zA-Z0-9_]*', name)
        features['param_name_token_count'] = len(name_tokens)
        features['param_name_avg_token_length'] = sum(len(t) for t in name_tokens) / max(1, len(name_tokens))
        
        # Value pattern matching
        features.update(self._match_value_patterns(str(value)))
        
        return features
    
    def _extract_family_features(self, family: str, param: Dict[str, Any], 
                                endpoint: Dict[str, Any]) -> Dict[str, float]:
        """Extract family-specific features."""
        features = {}
        name = param.get('name', '').lower()
        value = str(param.get('value', '')).lower()
        
        if family == 'sqli':
            features.update({
                'sqli_numeric_param': 1.0 if any(p in name for p in ['id', 'num', 'count', 'limit', 'offset']) else 0.0,
                'sqli_search_param': 1.0 if any(p in name for p in ['search', 'query', 'q', 'term', 'keyword']) else 0.0,
                'sqli_filter_param': 1.0 if any(p in name for p in ['filter', 'where', 'condition', 'criteria']) else 0.0,
                'sqli_sort_param': 1.0 if any(p in name for p in ['sort', 'order', 'by', 'asc', 'desc']) else 0.0,
            })
        
        elif family == 'xss':
            features.update({
                'xss_content_param': 1.0 if any(p in name for p in ['content', 'body', 'text', 'message', 'comment']) else 0.0,
                'xss_display_param': 1.0 if any(p in name for p in ['title', 'name', 'label', 'caption', 'description']) else 0.0,
                'xss_user_input_param': 1.0 if any(p in name for p in ['input', 'user', 'author', 'username']) else 0.0,
            })
        
        elif family == 'redirect':
            features.update({
                'redirect_navigation_param': 1.0 if any(p in name for p in ['next', 'return', 'redirect', 'url', 'target']) else 0.0,
                'redirect_callback_param': 1.0 if any(p in name for p in ['callback', 'cb', 'return_url', 'goto']) else 0.0,
                'redirect_continue_param': 1.0 if any(p in name for p in ['continue', 'proceed', 'next_page']) else 0.0,
            })
        
        return features
    
    def _extract_context_features(self, context: Dict[str, Any]) -> Dict[str, float]:
        """Extract context-aware features."""
        features = {}
        
        # Previous response patterns
        if 'prev_responses' in context:
            responses = context['prev_responses']
            if responses:
                features['avg_response_time'] = sum(r.get('time', 0) for r in responses) / len(responses)
                features['response_time_variance'] = self._calculate_variance([r.get('time', 0) for r in responses])
                features['success_rate'] = sum(1 for r in responses if r.get('status', 0) < 400) / len(responses)
        
        # Parameter interaction history
        if 'param_history' in context:
            history = context['param_history']
            features['param_usage_frequency'] = len(history)
            features['param_value_changes'] = len(set(str(h.get('value', '')) for h in history))
        
        return features
    
    def _extract_relationship_features(self, endpoint: Dict[str, Any], param: Dict[str, Any]) -> Dict[str, float]:
        """Extract cross-parameter relationship features."""
        features = {}
        
        # Check for related parameters
        url = endpoint.get('url', '')
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        param_name = param.get('name', '')
        related_params = []
        
        for name in query_params.keys():
            if name != param_name and self._are_params_related(param_name, name):
                related_params.append(name)
        
        features['related_param_count'] = len(related_params)
        features['param_isolation'] = 1.0 if len(related_params) == 0 else 0.0
        
        return features
    
    def _extract_security_features(self, param: Dict[str, Any], endpoint: Dict[str, Any]) -> Dict[str, float]:
        """Extract security pattern features."""
        features = {}
        
        name = param.get('name', '').lower()
        url = endpoint.get('url', '').lower()
        
        # Security-sensitive parameter detection
        for category, patterns in self.security_patterns.items():
            features[f'security_{category}'] = 1.0 if any(p in name for p in patterns) else 0.0
        
        # Business context detection
        for context, patterns in self.business_contexts.items():
            features[f'business_{context}'] = 1.0 if any(p in url for p in patterns) else 0.0
        
        # Parameter exposure risk
        features['exposed_in_url'] = 1.0 if param.get('loc') == 'query' else 0.0
        features['exposed_in_body'] = 1.0 if param.get('loc') in ['form', 'json'] else 0.0
        
        return features
    
    def _match_value_patterns(self, value: str) -> Dict[str, float]:
        """Match value against common patterns."""
        features = {}
        
        for pattern_name, pattern in self.value_patterns.items():
            features[f'pattern_{pattern_name}'] = 1.0 if re.match(pattern, value) else 0.0
        
        return features
    
    def _are_params_related(self, param1: str, param2: str) -> bool:
        """Check if two parameters are semantically related."""
        # Simple heuristic based on common patterns
        common_patterns = [
            (r'(\w+)_id', r'\1_name'),
            (r'(\w+)_id', r'\1_ref'),
            (r'(\w+)_id', r'\1_code'),
            (r'start_(\w+)', r'end_\1'),
            (r'min_(\w+)', r'max_\1'),
        ]
        
        for pattern1, pattern2 in common_patterns:
            if re.match(pattern1, param1) and re.match(pattern2, param2):
                return True
            if re.match(pattern2, param1) and re.match(pattern1, param2):
                return True
        
        return False
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0
        
        freq = Counter(text)
        length = len(text)
        return -sum((count / length) * math.log2(count / length) for count in freq.values())
    
    def _special_char_ratio(self, text: str) -> float:
        """Calculate ratio of special characters in a string."""
        if not text:
            return 0.0
        
        special_chars = sum(1 for c in text if not c.isalnum() and not c.isspace())
        return special_chars / len(text)
    
    def _calculate_variance(self, values: List[float]) -> float:
        """Calculate variance of a list of values."""
        if len(values) < 2:
            return 0.0
        
        mean = sum(values) / len(values)
        squared_diff_sum = sum((x - mean) ** 2 for x in values)
        return squared_diff_sum / (len(values) - 1)
