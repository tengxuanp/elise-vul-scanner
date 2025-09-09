"""
Tests for scan strategy modes.
"""

import pytest
from backend.modules.strategy import ScanStrategy, parse_strategy, validate_strategy_requirements, get_strategy_behavior
from backend.modules.decisions import canonical_decision, canonicalize_results, ensure_telemetry_defaults
from backend.modules.event_aggregator import AssessAggregator


class TestScanStrategy:
    """Test scan strategy functionality."""
    
    def test_parse_strategy_valid(self):
        """Test parsing valid strategy strings."""
        assert parse_strategy("auto") == ScanStrategy.AUTO
        assert parse_strategy("probe_only") == ScanStrategy.PROBE_ONLY
        assert parse_strategy("ml_only") == ScanStrategy.ML_ONLY
        assert parse_strategy("hybrid") == ScanStrategy.HYBRID
        assert parse_strategy("AUTO") == ScanStrategy.AUTO  # Case insensitive
        assert parse_strategy(" Auto ") == ScanStrategy.AUTO  # Whitespace handling
    
    def test_parse_strategy_invalid(self):
        """Test parsing invalid strategy strings."""
        with pytest.raises(ValueError):
            parse_strategy("invalid")
        with pytest.raises(ValueError):
            parse_strategy("probe")
        # Empty string should use default strategy, not raise error
        result = parse_strategy("")
        assert result in ScanStrategy
    
    def test_parse_strategy_none(self):
        """Test parsing None strategy (should use default)."""
        # This should not raise an error and return the default
        result = parse_strategy(None)
        assert result in ScanStrategy
    
    def test_validate_strategy_requirements_ml_available(self):
        """Test strategy validation when ML is available."""
        result = validate_strategy_requirements(ScanStrategy.ML_ONLY, True)
        assert result["strategy"] == "ml_only"
        assert result["ml_required"] is True
        assert result["ml_available"] is True
        assert result["fallback"] is None
    
    def test_validate_strategy_requirements_ml_unavailable_require_ranker(self):
        """Test strategy validation when ML is unavailable and REQUIRE_RANKER=1."""
        # Mock REQUIRE_RANKER to be True
        import backend.modules.strategy
        original_require_ranker = backend.modules.strategy.REQUIRE_RANKER
        backend.modules.strategy.REQUIRE_RANKER = True
        
        try:
            with pytest.raises(ValueError, match="Strategy requires ML models"):
                validate_strategy_requirements(ScanStrategy.ML_ONLY, False)
        finally:
            backend.modules.strategy.REQUIRE_RANKER = original_require_ranker
    
    def test_validate_strategy_requirements_ml_unavailable_no_require_ranker(self):
        """Test strategy validation when ML is unavailable and REQUIRE_RANKER=0."""
        # Mock REQUIRE_RANKER to be False
        import backend.modules.strategy
        original_require_ranker = backend.modules.strategy.REQUIRE_RANKER
        backend.modules.strategy.REQUIRE_RANKER = False
        
        try:
            result = validate_strategy_requirements(ScanStrategy.ML_ONLY, False)
            assert result["fallback"] == "probe_only"
            assert "ml_fallback" in result["flags"]
        finally:
            backend.modules.strategy.REQUIRE_RANKER = original_require_ranker
    
    def test_get_strategy_behavior(self):
        """Test getting strategy behavior configuration."""
        auto_behavior = get_strategy_behavior(ScanStrategy.AUTO)
        assert auto_behavior["run_probes"] is True
        assert auto_behavior["run_injections"] is True
        assert auto_behavior["probe_first"] is True
        assert auto_behavior["stop_on_probe_positive"] is True
        
        probe_only_behavior = get_strategy_behavior(ScanStrategy.PROBE_ONLY)
        assert probe_only_behavior["run_probes"] is True
        assert probe_only_behavior["run_injections"] is False
        
        ml_only_behavior = get_strategy_behavior(ScanStrategy.ML_ONLY)
        assert ml_only_behavior["run_probes"] is False
        assert ml_only_behavior["run_injections"] is True
        
        hybrid_behavior = get_strategy_behavior(ScanStrategy.HYBRID)
        assert hybrid_behavior["run_probes"] is True
        assert hybrid_behavior["run_injections"] is True
        assert hybrid_behavior["use_context_pool"] is True
        assert hybrid_behavior["max_context_injections"] == 1


class TestDecisionCanonicalization:
    """Test decision canonicalization functionality."""
    
    def test_canonical_decision_valid(self):
        """Test canonicalizing valid decisions."""
        assert canonical_decision("positive") == "positive"
        assert canonical_decision("suspected") == "suspected"
        assert canonical_decision("abstain") == "abstain"
        assert canonical_decision("not_applicable") == "not_applicable"
        assert canonical_decision("error") == "error"
    
    def test_canonical_decision_mapping(self):
        """Test canonicalizing mapped decisions."""
        assert canonical_decision("clean") == "abstain"
        assert canonical_decision("not_vulnerable") == "abstain"
        assert canonical_decision("vulnerable") == "positive"
        assert canonical_decision("exploitable") == "positive"
        assert canonical_decision("possible") == "suspected"
        assert canonical_decision("failed") == "error"
        assert canonical_decision("skipped") == "not_applicable"
    
    def test_canonical_decision_edge_cases(self):
        """Test canonicalizing edge cases."""
        assert canonical_decision(None) == "abstain"
        assert canonical_decision("") == "abstain"
        assert canonical_decision("unknown") == "abstain"
        assert canonical_decision("invalid") == "abstain"
        assert canonical_decision("POSITIVE") == "positive"  # Case insensitive
    
    def test_canonicalize_results(self):
        """Test canonicalizing a list of results."""
        results = [
            {"decision": "clean", "url": "test1"},
            {"decision": "positive", "url": "test2"},
            {"decision": "vulnerable", "url": "test3"},
            {"decision": "unknown", "url": "test4"}
        ]
        
        canonicalized = canonicalize_results(results)
        
        assert canonicalized[0]["decision"] == "abstain"  # clean -> abstain
        assert canonicalized[1]["decision"] == "positive"  # positive -> positive
        assert canonicalized[2]["decision"] == "positive"  # vulnerable -> positive
        assert canonicalized[3]["decision"] == "abstain"  # unknown -> abstain
    
    def test_ensure_telemetry_defaults(self):
        """Test ensuring telemetry defaults."""
        row = {"decision": "positive", "why": ["probe_proof"]}
        result = ensure_telemetry_defaults(row)
        
        assert result["attempt_idx"] == 0
        assert result["top_k_used"] == 0
        assert result["rank_source"] == "probe_only"  # Because "probe_proof" in why
        
        # Test NA result
        na_row = {"decision": "not_applicable"}
        na_result = ensure_telemetry_defaults(na_row)
        assert na_result["rank_source"] == "none"
        
        # Test existing rank_source
        existing_row = {"decision": "positive", "rank_source": "ml_ranked"}
        existing_result = ensure_telemetry_defaults(existing_row)
        assert existing_result["rank_source"] == "ml_ranked"  # Should not override


class TestEventAggregator:
    """Test event aggregator functionality."""
    
    def test_aggregator_initialization(self):
        """Test aggregator initialization."""
        agg = AssessAggregator()
        assert agg.probe_attempts == 0
        assert agg.probe_successes == 0
        assert agg.inject_attempts == 0
        assert agg.inject_successes == 0
    
    def test_record_probe_attempt(self):
        """Test recording probe attempts."""
        agg = AssessAggregator()
        
        agg.record_probe_attempt(False)
        assert agg.probe_attempts == 1
        assert agg.probe_successes == 0
        
        agg.record_probe_attempt(True)
        assert agg.probe_attempts == 2
        assert agg.probe_successes == 1
    
    def test_record_inject_attempt(self):
        """Test recording injection attempts."""
        agg = AssessAggregator()
        
        agg.record_inject_attempt(False)
        assert agg.inject_attempts == 1
        assert agg.inject_successes == 0
        
        agg.record_inject_attempt(True)
        assert agg.inject_attempts == 2
        assert agg.inject_successes == 1
    
    def test_get_meta_data_consistent(self):
        """Test getting meta data with consistent counters."""
        agg = AssessAggregator()
        
        # Record some events
        agg.record_probe_attempt(True)
        agg.record_inject_attempt(True)
        
        # Create results that match the events
        results = [
            {"decision": "positive", "rank_source": "probe_only"},
            {"decision": "positive", "rank_source": "ml_ranked"}
        ]
        
        meta = agg.get_meta_data(results)
        
        assert meta["probe_attempts"] == 1
        assert meta["probe_successes"] == 1
        assert meta["ml_inject_attempts"] == 1
        assert meta["ml_inject_successes"] == 1
        assert meta["counters_consistent"] is True
    
    def test_get_meta_data_inconsistent(self):
        """Test getting meta data with inconsistent counters."""
        agg = AssessAggregator()
        
        # Record some events
        agg.record_probe_attempt(True)
        agg.record_inject_attempt(True)
        
        # Create results that don't match the events
        results = [
            {"decision": "positive", "rank_source": "probe_only"}
            # Missing the second positive result
        ]
        
        meta = agg.get_meta_data(results)
        
        assert meta["counters_consistent"] is False
    
    def test_reset(self):
        """Test resetting the aggregator."""
        agg = AssessAggregator()
        
        # Record some events
        agg.record_probe_attempt(True)
        agg.record_inject_attempt(True)
        
        # Reset
        agg.reset()
        
        assert agg.probe_attempts == 0
        assert agg.probe_successes == 0
        assert agg.inject_attempts == 0
        assert agg.inject_successes == 0
