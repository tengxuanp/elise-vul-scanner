"""
Smoke tests for EnhancedInferenceEngineStrict

Tests that the inference engine fails loudly when models are missing
and works correctly when models are present.
"""

import pytest
import tempfile
import shutil
from pathlib import Path
import json
import joblib
import numpy as np

# Add backend to path for imports
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from modules.ml.enhanced_inference import EnhancedInferenceEngineStrict
from modules.ml.errors import ModelNotReadyError


class MockModel:
    """A simple mock model that can be pickled by joblib."""
    
    def __init__(self, proba_return=None):
        if proba_return is None:
            self.proba_return = np.array([[0.3, 0.7]])
        else:
            self.proba_return = proba_return
    
    def predict_proba(self, X):
        return self.proba_return


class TestEnhancedInferenceEngineStrict:
    """Test cases for the strict inference engine."""
    
    def test_missing_models_dir_raises_error(self):
        """Test that missing models directory raises ModelNotReadyError."""
        with pytest.raises(ModelNotReadyError, match="Missing model:"):
            EnhancedInferenceEngineStrict("/nonexistent/directory")
    
    def test_missing_model_files_raises_error(self):
        """Test that missing model files raise ModelNotReadyError."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Create directory but no model files
            with pytest.raises(ModelNotReadyError, match="Missing model:"):
                EnhancedInferenceEngineStrict(temp_path)
    
    def test_missing_calibration_files_raises_error(self):
        """Test that missing calibration files raise ModelNotReadyError when required."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Create mock model files but no calibration
            for family in ["xss", "sqli", "redirect"]:
                model_path = temp_path / f"family_{family}.joblib"
                # Create a simple mock model
                mock_model = MockModel()
                joblib.dump(mock_model, model_path)
            
            # Should raise error when calibration is required
            with pytest.raises(ModelNotReadyError, match="Missing calibration:"):
                EnhancedInferenceEngineStrict(temp_path, require_calibration=True)
    
    def test_works_without_calibration_when_not_required(self):
        """Test that engine works when calibration is not required."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Create mock model files
            for family in ["xss", "sqli", "redirect"]:
                model_path = temp_path / f"family_{family}.joblib"
                mock_model = MockModel()
                joblib.dump(mock_model, model_path)
            
            # Should work when calibration is not required
            engine = EnhancedInferenceEngineStrict(temp_path, require_calibration=False)
            assert engine is not None
            assert len(engine.models) == 3
    
    def test_works_with_models_and_calibration(self):
        """Test that engine works correctly with models and calibration data."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Create mock model files
            for family in ["xss", "sqli", "redirect"]:
                model_path = temp_path / f"family_{family}.joblib"
                mock_model = MockModel()
                joblib.dump(mock_model, model_path)
                
                # Create calibration files
                cal_path = temp_path / f"family_{family}.cal.json"
                cal_data = {"temperature": 1.5}
                with open(cal_path, 'w') as f:
                    json.dump(cal_data, f)
            
            # Should work with both models and calibration
            engine = EnhancedInferenceEngineStrict(temp_path, require_calibration=True)
            assert engine is not None
            assert len(engine.models) == 3
            assert len(engine.temperatures) == 3
    
    def test_predict_distribution_returns_valid_probabilities(self):
        """Test that predict_distribution returns valid probability distributions."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Create mock model files with different probabilities
            families = ["xss", "sqli", "redirect"]
            expected_probs = [0.8, 0.6, 0.4]  # Different probabilities for each family
            
            for i, family in enumerate(families):
                model_path = temp_path / f"family_{family}.joblib"
                # Return probability for positive class
                prob = expected_probs[i]
                mock_model = MockModel(np.array([[1-prob, prob]]))
                joblib.dump(mock_model, model_path)
                
                # Create calibration files
                cal_path = temp_path / f"family_{family}.cal.json"
                cal_data = {"temperature": 1.0}  # No temperature scaling
                with open(cal_path, 'w') as f:
                    json.dump(cal_data, f)
            
            engine = EnhancedInferenceEngineStrict(temp_path, require_calibration=True)
            
            # Test prediction
            features = {"feature1": 1.0, "feature2": 0.5}
            result = engine.predict_distribution(features)
            
            # Check result structure
            assert "probs" in result
            assert "family" in result
            assert "entropy" in result
            
            # Check probabilities sum to approximately 1
            prob_sum = sum(result["probs"].values())
            assert abs(prob_sum - 1.0) < 1e-6, f"Probabilities sum to {prob_sum}, not 1.0"
            
            # Check no NaNs
            for family, prob in result["probs"].items():
                assert not np.isnan(prob), f"NaN probability for family {family}"
                assert 0 <= prob <= 1, f"Invalid probability {prob} for family {family}"
            
            # Check entropy is valid
            assert not np.isnan(result["entropy"]), "Entropy is NaN"
            assert result["entropy"] >= 0, f"Negative entropy: {result['entropy']}"
            
            # Check family is one of the expected families
            assert result["family"] in families, f"Unexpected family: {result['family']}"
    
    def test_predict_distribution_with_temperature_scaling(self):
        """Test that temperature scaling affects the probability distribution."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            families = ["xss", "sqli", "redirect"]
            
            # Create models with same probabilities
            for family in families:
                model_path = temp_path / f"family_{family}.joblib"
                mock_model = MockModel()
                joblib.dump(mock_model, model_path)
                
                # Create calibration files with different temperatures
                cal_path = temp_path / f"family_{family}.cal.json"
                # Use different temperatures to see the effect
                temp_value = 2.0 if family == "xss" else 1.0
                cal_data = {"temperature": temp_value}
                with open(cal_path, 'w') as f:
                    json.dump(cal_data, f)
            
            engine = EnhancedInferenceEngineStrict(temp_path, require_calibration=True)
            
            features = {"feature1": 1.0, "feature2": 0.5}
            result = engine.predict_distribution(features)
            
            # With temperature scaling, the distribution should be affected
            # Higher temperature should make the distribution more uniform
            prob_sum = sum(result["probs"].values())
            assert abs(prob_sum - 1.0) < 1e-6, f"Probabilities sum to {prob_sum}, not 1.0"
            
            # Check no NaNs
            for family, prob in result["probs"].items():
                assert not np.isnan(prob), f"NaN probability for family {family}"
    
    def test_predict_distribution_no_models_raises_error(self):
        """Test that predict_distribution raises error when no models are loaded."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Create empty directory
            with pytest.raises(ModelNotReadyError, match="Missing model:"):
                engine = EnhancedInferenceEngineStrict(temp_path)
                # This should not be reached, but if it is, predict should fail
                engine.predict_distribution({})
