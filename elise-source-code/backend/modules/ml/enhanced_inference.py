"""
Enhanced Inference Engine with Strict Model Validation

This module provides a strict inference engine that only produces probabilities
when real models and calibration data are available. It enforces proper model
loading and temperature calibration for reliable probability distributions.
"""

import json
import math
from pathlib import Path
from typing import Dict, List, Union, Any
import joblib
import numpy as np

from .errors import ModelNotReadyError


class EnhancedInferenceEngineStrict:
    """
    Strict inference engine that requires real models and calibration data.
    
    This engine enforces that:
    1. All required family models are present and loaded
    2. All required calibration data is present (if require_calibration=True)
    3. Only real model predictions are used (no synthetic scores)
    4. Temperature calibration is applied for proper probability distributions
    """
    
    def __init__(
        self, 
        model_dir: Union[str, Path], 
        families: tuple = ("xss", "sqli", "redirect"),
        require_calibration: bool = True
    ):
        """
        Initialize the strict inference engine.
        
        Args:
            model_dir: Directory containing model files
            families: Tuple of family names to load models for
            require_calibration: Whether calibration data is required
            
        Raises:
            ModelNotReadyError: If required models or calibration data is missing
        """
        self.model_dir = Path(model_dir)
        self.families = families
        self.require_calibration = require_calibration
        
        # Storage for loaded models and calibration data
        self.models: Dict[str, Any] = {}
        self.temperatures: Dict[str, float] = {}
        
        # Load models and calibration data
        self._load_models()
        if self.require_calibration:
            self._load_calibration()
    
    def _load_models(self) -> None:
        """Load all required family models."""
        for family in self.families:
            model_path = self.model_dir / f"family_{family}.joblib"
            
            if not model_path.exists():
                raise ModelNotReadyError(f"Missing model: {model_path}")
            
            try:
                self.models[family] = joblib.load(model_path)
            except Exception as e:
                raise ModelNotReadyError(f"Failed to load model {model_path}: {e}")
    
    def _load_calibration(self) -> None:
        """Load calibration data for all families."""
        for family in self.families:
            cal_path = self.model_dir / f"family_{family}.cal.json"
            
            if not cal_path.exists():
                raise ModelNotReadyError(f"Missing calibration: {cal_path}")
            
            try:
                with open(cal_path, 'r') as f:
                    cal_data = json.load(f)
                
                if "temperature" not in cal_data:
                    raise ModelNotReadyError(f"Missing temperature in calibration: {cal_path}")
                
                self.temperatures[family] = float(cal_data["temperature"])
                
            except Exception as e:
                raise ModelNotReadyError(f"Failed to load calibration {cal_path}: {e}")
    
    def predict_distribution(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Predict probability distribution across families.
        
        Args:
            features: Feature dictionary (must be compatible with loaded models)
            
        Returns:
            Dictionary with:
            - "probs": Probability distribution across families
            - "family": Family with highest probability
            - "entropy": Entropy of the distribution
        """
        if not self.models:
            raise ModelNotReadyError("No models loaded")
        
        # Get logits for each family
        logits = []
        family_names = []
        
        for family in self.families:
            model = self.models[family]
            
            # Get positive class probability
            try:
                # Convert features to numpy array if needed
                if isinstance(features, dict):
                    # Assume models expect a 2D array - convert dict to array
                    # This is a simplified approach; real implementation would need
                    # proper feature vectorization based on model requirements
                    feature_array = np.array([list(features.values())]).reshape(1, -1)
                else:
                    feature_array = features
                
                # Get probability for positive class (assuming binary classification)
                proba = model.predict_proba(feature_array)[0]
                if len(proba) == 2:
                    p = proba[1]  # Positive class probability
                else:
                    p = proba[0]  # Single class case
                
            except Exception as e:
                raise ModelNotReadyError(f"Model prediction failed for {family}: {e}")
            
            # Clamp probability to avoid log(0) or log(1)
            p = max(1e-6, min(1 - 1e-6, p))
            
            # Convert to logits
            z = math.log(p / (1 - p))
            
            # Apply temperature calibration if available
            if self.require_calibration and family in self.temperatures:
                T = self.temperatures[family]
                z = z / T
            
            logits.append(z)
            family_names.append(family)
        
        # Convert to numpy array for stable softmax
        logits_array = np.array(logits)
        
        # Compute stable softmax
        # Subtract max for numerical stability
        logits_stable = logits_array - np.max(logits_array)
        exp_logits = np.exp(logits_stable)
        probs = exp_logits / np.sum(exp_logits)
        
        # Create probability dictionary
        prob_dict = {family: float(prob) for family, prob in zip(family_names, probs)}
        
        # Find family with highest probability
        max_idx = np.argmax(probs)
        best_family = family_names[max_idx]
        
        # Compute entropy
        entropy = -np.sum(probs * np.log(probs + 1e-10))
        
        return {
            "probs": prob_dict,
            "family": best_family,
            "entropy": float(entropy)
        }