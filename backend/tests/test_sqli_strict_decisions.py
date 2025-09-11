"""
Guardrail tests for strict SQLi decision policies.

Tests ensure:
1. SQLi positives only when reason ∈ {error_signature, boolean_confirmed, time_based_confirmed}
2. Reflection never contributes to SQLi
3. Boolean/timing require confirm trials with control payloads
4. URL-like params are skipped/de-weighted for SQLi unless hard SQL evidence exists
5. Family purity stays intact (no XSS markers/payloads inside SQLi attempts)
"""

import pytest
import os
import sys
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, Any

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from backend.triage.sqli_decider import (
    decide_sqli, confirm_helper, is_url_like_param, 
    should_suppress_sqli_for_param, LIKELY_URL_KEYS
)
from backend.modules.gates import gate_candidate_sqli
from backend.modules.targets import Target


class TestSQLiStrictDecisions:
    """Test strict SQLi decision logic"""
    
    def test_sqli_positive_only_with_valid_reasons(self):
        """Test that SQLi positives only occur with valid reasons"""
        
        # Test error_signature
        signals = {'sqli.error_based': True}
        target = Mock()
        target.param = 'id'
        target.param_value = '1'
        
        decision, reason, extras = decide_sqli(signals, "'", target, None)
        assert decision == 'positive'
        assert reason == 'error_signature'
        
        # Test boolean_confirmed (with mock confirmation)
        signals = {'sqli.boolean_delta': 0.35}
        with patch('backend.triage.sqli_decider.confirm_helper') as mock_confirm:
            mock_confirm.return_value = (True, Mock())
            decision, reason, extras = decide_sqli(signals, "' OR '1'='1' --", target, mock_confirm)
            assert decision == 'positive'
            assert reason == 'boolean_confirmed'
        
        # Test time_based_confirmed (with mock confirmation)
        signals = {'sqli.timing_based': True}
        with patch('backend.triage.sqli_decider.confirm_helper') as mock_confirm:
            mock_confirm.return_value = (True, Mock())
            decision, reason, extras = decide_sqli(signals, "1 AND SLEEP(2) --", target, mock_confirm)
            assert decision == 'positive'
            assert reason == 'time_based_confirmed'
    
    def test_sqli_never_positive_with_reflection(self):
        """Test that reflection never promotes SQLi to positive"""
        
        # Test with reflection but no SQL evidence
        signals = {
            'sqli.error_based': False,
            'sqli.boolean_delta': 0.0,
            'sqli.timing_based': False,
            'xss.reflected': True,  # Reflection present
            'xss.context': 'html_body'
        }
        target = Mock()
        target.param = 'id'
        target.param_value = '1'
        
        decision, reason, extras = decide_sqli(signals, "'", target, None)
        assert decision == 'clean'
        assert reason == 'no_sql_evidence'
        assert 'reflection' not in reason.lower()
    
    def test_sqli_boolean_confirm_required(self):
        """Test that boolean-based SQLi requires confirmation"""
        
        # Test large delta without confirmation -> suspected
        signals = {'sqli.boolean_delta': 0.35}
        target = Mock()
        target.param = 'id'
        target.param_value = '1'
        
        decision, reason, extras = decide_sqli(signals, "' OR '1'='1' --", target, None)
        assert decision == 'suspected'
        assert reason == 'boolean_no_confirm'
        
        # Test with failed confirmation -> suspected
        with patch('backend.triage.sqli_decider.confirm_helper') as mock_confirm:
            mock_confirm.return_value = (False, Mock())
            decision, reason, extras = decide_sqli(signals, "' OR '1'='1' --", target, mock_confirm)
            assert decision == 'suspected'
            assert reason == 'boolean_unconfirmed'
        
        # Test with successful confirmation -> positive
        with patch('backend.triage.sqli_decider.confirm_helper') as mock_confirm:
            mock_confirm.return_value = (True, Mock())
            decision, reason, extras = decide_sqli(signals, "' OR '1'='1' --", target, mock_confirm)
            assert decision == 'positive'
            assert reason == 'boolean_confirmed'
    
    def test_sqli_timing_confirm_required(self):
        """Test that timing-based SQLi requires confirmation"""
        
        # Test timing without confirmation -> suspected
        signals = {'sqli.timing_based': True}
        target = Mock()
        target.param = 'id'
        target.param_value = '1'
        
        decision, reason, extras = decide_sqli(signals, "1 AND SLEEP(2) --", target, None)
        assert decision == 'suspected'
        assert reason == 'time_based_no_confirm'
        
        # Test with failed confirmation -> suspected
        with patch('backend.triage.sqli_decider.confirm_helper') as mock_confirm:
            mock_confirm.return_value = (False, Mock())
            decision, reason, extras = decide_sqli(signals, "1 AND SLEEP(2) --", target, mock_confirm)
            assert decision == 'suspected'
            assert reason == 'time_based_unconfirmed'
        
        # Test with successful confirmation -> positive
        with patch('backend.triage.sqli_decider.confirm_helper') as mock_confirm:
            mock_confirm.return_value = (True, Mock())
            decision, reason, extras = decide_sqli(signals, "1 AND SLEEP(2) --", target, mock_confirm)
            assert decision == 'positive'
            assert reason == 'time_based_confirmed'
    
    def test_sqli_weak_boolean_delta_suspected(self):
        """Test that weak boolean deltas result in suspected"""
        
        signals = {'sqli.boolean_delta': 0.20}  # Between suspect and positive thresholds
        target = Mock()
        target.param = 'id'
        target.param_value = '1'
        
        decision, reason, extras = decide_sqli(signals, "' OR '1'='1' --", target, None)
        assert decision == 'suspected'
        assert reason == 'weak_boolean_delta'
        assert extras['delta'] == 0.20


class TestURLParamSuppression:
    """Test URL parameter suppression for SQLi"""
    
    def test_url_param_suppression(self):
        """Test that URL-like parameters are suppressed for SQLi"""
        
        # Test URL parameter names
        for param_name in LIKELY_URL_KEYS:
            assert is_url_like_param(param_name, 'some_value')
            assert should_suppress_sqli_for_param(param_name, 'some_value', has_error_evidence=False)
        
        # Test URL-like values
        url_values = [
            'http://example.com',
            'https://example.com',
            'www.example.com',
            '/path/to/page',
            'example.com/page'
        ]
        
        for value in url_values:
            assert is_url_like_param('param', value)
            assert should_suppress_sqli_for_param('param', value, has_error_evidence=False)
    
    def test_url_param_not_suppressed_with_error_evidence(self):
        """Test that URL params are not suppressed when error evidence exists"""
        
        # Even URL-like params should not be suppressed if we have error evidence
        assert not should_suppress_sqli_for_param('url', 'http://example.com', has_error_evidence=True)
        assert not should_suppress_sqli_for_param('next', '/redirect', has_error_evidence=True)
    
    def test_gate_candidate_sqli_url_suppression(self):
        """Test that gate_candidate_sqli suppresses URL-like parameters"""
        
        # Test URL parameter suppression
        target = Target(
            url='http://example.com/go?url=https://example.com',
            method='GET',
            param_in='query',
            param='url'
        )
        
        # Should be suppressed (no error evidence)
        assert not gate_candidate_sqli(target)
        
        # Test non-URL parameter passes
        target.param = 'id'
        assert gate_candidate_sqli(target)


class TestConfirmHelper:
    """Test confirmation helper functionality"""
    
    @patch('backend.modules.injector.inject_once')
    def test_confirm_helper_boolean_success(self, mock_inject):
        """Test successful boolean confirmation"""
        
        # Mock injection results
        attack_result = Mock()
        attack_result.latency_ms = 100
        attack_result.status = 200
        attack_result.response_body = 'a' * 1000  # 1000 bytes
        
        control_result = Mock()
        control_result.latency_ms = 100
        control_result.status = 200
        control_result.response_body = 'b' * 500   # 500 bytes
        
        mock_inject.side_effect = [attack_result] * 3 + [control_result] * 3
        
        target = Mock()
        target.url = 'http://example.com'
        target.method = 'GET'
        target.param_in = 'query'
        target.param = 'id'
        target.headers = {}
        
        confirmed, stats = confirm_helper('boolean', target, "' OR '1'='1' --", min_trials=3, min_delta=0.30)
        
        assert confirmed
        assert stats is not None
        assert len(stats.trials) == 6  # 3 attack + 3 control
        assert stats.delta_length == 500  # 1000 - 500
        assert stats.consistent
    
    @patch('backend.modules.injector.inject_once')
    def test_confirm_helper_timing_success(self, mock_inject):
        """Test successful timing confirmation"""
        
        # Mock injection results with timing difference
        attack_result = Mock()
        attack_result.latency_ms = 3000  # 3 seconds
        attack_result.status = 200
        attack_result.response_body = 'response'
        
        control_result = Mock()
        control_result.latency_ms = 100   # 100ms
        control_result.status = 200
        control_result.response_body = 'response'
        
        mock_inject.side_effect = [attack_result] * 3 + [control_result] * 3
        
        target = Mock()
        target.url = 'http://example.com'
        target.method = 'GET'
        target.param_in = 'query'
        target.param = 'id'
        target.headers = {}
        
        confirmed, stats = confirm_helper('timing', target, "1 AND SLEEP(2) --", min_trials=3, min_slowdown=1.5)
        
        assert confirmed
        assert stats is not None
        assert stats.attack_avg_latency > stats.control_avg_latency
        assert stats.delta_latency > 0


class TestFamilyPurity:
    """Test that family purity is maintained"""
    
    def test_sqli_never_uses_xss_signals(self):
        """Test that SQLi decisions never use XSS signals"""
        
        # Test with XSS signals present
        signals = {
            'sqli.error_based': False,
            'sqli.boolean_delta': 0.0,
            'sqli.timing_based': False,
            'xss.reflected': True,
            'xss.context': 'html_body',
            'xss.escaping': 'raw'
        }
        target = Mock()
        target.param = 'id'
        target.param_value = '1'
        
        decision, reason, extras = decide_sqli(signals, "'", target, None)
        
        # Should be clean, not influenced by XSS signals
        assert decision == 'clean'
        assert reason == 'no_sql_evidence'
        assert 'xss' not in reason.lower()
        assert 'reflection' not in reason.lower()
    
    def test_sqli_decision_reasons_are_sqli_specific(self):
        """Test that SQLi decision reasons are SQLi-specific"""
        
        valid_sqli_reasons = {
            'error_signature', 'boolean_confirmed', 'time_based_confirmed',
            'boolean_unconfirmed', 'time_based_unconfirmed', 'boolean_no_confirm',
            'time_based_no_confirm', 'weak_boolean_delta', 'no_sql_evidence',
            'url_param_suppressed'
        }
        
        # Test various signal combinations
        test_cases = [
            {'sqli.error_based': True},
            {'sqli.boolean_delta': 0.35},
            {'sqli.timing_based': True},
            {'sqli.boolean_delta': 0.20},
            {}
        ]
        
        target = Mock()
        target.param = 'id'
        target.param_value = '1'
        
        for signals in test_cases:
            decision, reason, extras = decide_sqli(signals, "'", target, None)
            assert reason in valid_sqli_reasons, f"Invalid SQLi reason: {reason}"


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
