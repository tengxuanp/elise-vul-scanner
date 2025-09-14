#!/usr/bin/env python3
"""
SQLi Dialect Classifier Inference

This module provides ML-based SQLi dialect classification, similar to how
XSS context classifier works. It loads the SQLi dialect classifier model
and provides prediction functions.
"""

import os
import sys
import joblib
import numpy as np
from typing import Dict, Any, Optional

# Add the backend modules to the path
sys.path.append('backend/modules')

def _load_sqli_dialect_model():
    """Load the SQLi dialect classifier model."""
    # Get the absolute path to the model file
    current_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(current_dir, 'models', 'sqli_dialect_classifier.joblib')
    
    if not os.path.exists(model_path):
        print(f"SQLi dialect model not found at {model_path}")
        return None
    
    try:
        model = joblib.load(model_path)
        print(f"SQLi dialect model loaded successfully from {model_path}")
        return model
    except Exception as e:
        print(f"Error loading SQLi dialect model: {e}")
        return None

# Global model cache
_sqli_dialect_model = None

def get_sqli_dialect_model():
    """Get the SQLi dialect model, loading it if necessary."""
    global _sqli_dialect_model
    if _sqli_dialect_model is None:
        _sqli_dialect_model = _load_sqli_dialect_model()
    return _sqli_dialect_model

def _extract_sqli_dialect_features(response_text: str, headers: dict, status_code: int = None) -> np.ndarray:
    """Extract features for SQLi dialect classification."""
    # Create feature vector: [error_text_length, status_code, content_type_html, content_type_json]
    error_text_length = len(response_text or "")
    status_code = status_code or 200
    
    # Determine content type
    content_type = ""
    if headers:
        content_type = headers.get("content-type", "").lower()
    
    content_type_html = 1 if "text/html" in content_type else 0
    content_type_json = 1 if "application/json" in content_type else 0
    
    features = np.array([
        error_text_length,
        status_code,
        content_type_html,
        content_type_json
    ]).reshape(1, -1)
    
    return features

def predict_sqli_dialect(response_text: str, headers: dict, status_code: int = None) -> Optional[Dict[str, Any]]:
    """
    Predict SQLi dialect using ML classification.
    
    Args:
        response_text: The response text from the server
        headers: Response headers
        status_code: HTTP status code
        
    Returns:
        Dictionary with 'pred' (predicted dialect) and 'proba' (confidence)
        or None if prediction fails
    """
    model = get_sqli_dialect_model()
    if model is None:
        return None
    
    try:
        # Extract features
        features = _extract_sqli_dialect_features(response_text, headers, status_code)
        
        # Make prediction
        prediction = model.predict(features)[0]
        probabilities = model.predict_proba(features)[0]
        
        # Get the probability for the predicted class
        predicted_proba = probabilities[model.classes_ == prediction][0]
        
        return {
            "pred": prediction,
            "proba": float(predicted_proba),
            "all_probas": {
                dialect: float(prob) 
                for dialect, prob in zip(model.classes_, probabilities)
            }
        }
        
    except Exception as e:
        print(f"Error in SQLi dialect prediction: {e}")
        return None

def test_sqli_dialect_classifier():
    """Test the SQLi dialect classifier with sample data."""
    print("🧪 Testing SQLi Dialect Classifier...")
    
    # Test cases
    test_cases = [
        {
            "name": "MySQL Error",
            "response_text": "You have an error in your SQL syntax",
            "headers": {"content-type": "text/html"},
            "status_code": 500
        },
        {
            "name": "PostgreSQL Error", 
            "response_text": "ERROR: syntax error at or near",
            "headers": {"content-type": "text/html"},
            "status_code": 500
        },
        {
            "name": "MSSQL Error",
            "response_text": "Microsoft SQL Server error",
            "headers": {"content-type": "text/html"},
            "status_code": 500
        },
        {
            "name": "SQLite Error",
            "response_text": "SQLiteException: no such table",
            "headers": {"content-type": "text/html"},
            "status_code": 500
        },
        {
            "name": "Unknown Error",
            "response_text": "Database error occurred",
            "headers": {"content-type": "text/html"},
            "status_code": 500
        }
    ]
    
    for test_case in test_cases:
        result = predict_sqli_dialect(
            test_case["response_text"],
            test_case["headers"],
            test_case["status_code"]
        )
        
        if result:
            print(f"  {test_case['name']}: {result['pred']} (confidence: {result['proba']:.3f})")
        else:
            print(f"  {test_case['name']}: Prediction failed")

if __name__ == "__main__":
    test_sqli_dialect_classifier()