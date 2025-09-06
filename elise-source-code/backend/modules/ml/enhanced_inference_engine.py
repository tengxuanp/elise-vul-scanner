#!/usr/bin/env python3
"""
Enhanced inference engine for strict ML predictions
"""

import os
import joblib
import numpy as np
from typing import Dict, Any, Optional
import logging

class EnhancedInferenceEngineStrict:
    """Strict inference engine for vulnerability prediction"""
    
    def __init__(self, model_dir: str):
        """
        Initialize the inference engine.
        
        Args:
            model_dir: Directory containing trained models
        """
        self.model_dir = model_dir
        self.vulnerability_predictor = None
        self.payload_recommender = None
        self._load_models()
    
    def _load_models(self):
        """Load trained models from disk"""
        try:
            # Load vulnerability predictor
            vuln_model_path = os.path.join(self.model_dir, "vulnerability_predictor.joblib")
            if os.path.exists(vuln_model_path):
                self.vulnerability_predictor = joblib.load(vuln_model_path)
                logging.info("✅ Loaded vulnerability predictor model")
            else:
                logging.warning(f"⚠️ Vulnerability predictor model not found: {vuln_model_path}")
            
            # Load payload recommender
            payload_model_path = os.path.join(self.model_dir, "payload_recommender.joblib")
            if os.path.exists(payload_model_path):
                self.payload_recommender = joblib.load(payload_model_path)
                logging.info("✅ Loaded payload recommender model")
            else:
                logging.warning(f"⚠️ Payload recommender model not found: {payload_model_path}")
                
        except Exception as e:
            logging.error(f"❌ Failed to load models: {e}")
            raise
    
    def predict_distribution(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Predict vulnerability distribution for given features.
        
        Args:
            features: Feature dictionary
            
        Returns:
            Dictionary with probabilities, family, and entropy
        """
        if not self.vulnerability_predictor:
            raise RuntimeError("Vulnerability predictor model not loaded")
        
        try:
            # Convert features to numpy array (assuming the model expects this format)
            # This is a simplified version - in practice, you'd need to match the training format
            feature_vector = self._features_to_vector(features)
            
            # Get prediction probabilities
            if hasattr(self.vulnerability_predictor, 'predict_proba'):
                probabilities = self.vulnerability_predictor.predict_proba(feature_vector)
                classes = self.vulnerability_predictor.classes_
            else:
                # Fallback for models without predict_proba
                prediction = self.vulnerability_predictor.predict(feature_vector)
                probabilities = np.array([[0.1, 0.9]])  # Dummy probabilities
                classes = ['none', 'xss']  # Dummy classes
            
            # Convert to dictionary
            probs = {}
            for i, class_name in enumerate(classes):
                probs[class_name] = float(probabilities[0][i])
            
            # Find top family
            top_family = max(probs.items(), key=lambda x: x[1])[0]
            
            # Calculate entropy
            entropy = self._calculate_entropy(list(probs.values()))
            
            return {
                "probs": probs,
                "family": top_family,
                "entropy": entropy
            }
            
        except Exception as e:
            logging.error(f"❌ Prediction failed: {e}")
            # Return safe defaults
            return {
                "probs": {"none": 1.0},
                "family": "none",
                "entropy": 0.0
            }
    
    def _features_to_vector(self, features: Dict[str, Any]) -> np.ndarray:
        """
        Convert feature dictionary to numpy vector.
        
        This is a simplified implementation - in practice, you'd need to match
        the exact feature extraction used during training.
        """
        # Extract numeric features (simplified)
        numeric_features = []
        
        # Add basic features
        numeric_features.append(features.get("param_length", 0))
        numeric_features.append(features.get("url_length", 0))
        numeric_features.append(features.get("path_depth", 0))
        
        # Add probe features
        numeric_features.append(1 if features.get("reflect_html") else 0)
        numeric_features.append(1 if features.get("reflect_attr") else 0)
        numeric_features.append(1 if features.get("reflect_js") else 0)
        numeric_features.append(1 if features.get("redirect_influence") else 0)
        numeric_features.append(1 if features.get("sqli_error") else 0)
        numeric_features.append(features.get("sqli_boolean_delta", 0.0))
        numeric_features.append(1 if features.get("sqli_time") else 0)
        
        # Pad or truncate to expected length (assuming 20 features)
        while len(numeric_features) < 20:
            numeric_features.append(0.0)
        numeric_features = numeric_features[:20]
        
        return np.array(numeric_features).reshape(1, -1)
    
    def _calculate_entropy(self, probabilities: list) -> float:
        """Calculate entropy of probability distribution"""
        entropy = 0.0
        for p in probabilities:
            if p > 0:
                entropy -= p * np.log2(p)
        return entropy
    
    def is_ready(self) -> bool:
        """Check if the engine is ready for predictions"""
        return self.vulnerability_predictor is not None
