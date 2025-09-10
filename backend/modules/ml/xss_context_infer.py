"""
XSS Context ML Inference Module

Provides ML-based predictions for XSS context and escaping classification.
Used by the hybrid rule-ML approach in xss_canary.py.
"""

import numpy as np
import re
from typing import Dict, Any, Optional, Tuple
from pathlib import Path
import joblib

from backend.app_state import MODEL_DIR

# Global model cache
_context_model = None
_context_vectorizer = None
_escaping_model = None
_escaping_vectorizer = None

def load_models() -> Tuple[bool, bool]:
    """Load ML models if available."""
    global _context_model, _context_vectorizer, _escaping_model, _escaping_vectorizer
    
    context_loaded = False
    escaping_loaded = False
    
    try:
        # Load context model
        context_model_path = MODEL_DIR / "xss_context_model.joblib"
        context_vectorizer_path = MODEL_DIR / "xss_context_vectorizer.joblib"
        
        if context_model_path.exists() and context_vectorizer_path.exists():
            _context_model = joblib.load(context_model_path)
            _context_vectorizer = joblib.load(context_vectorizer_path)
            context_loaded = True
            
    except Exception as e:
        print(f"Failed to load context model: {e}")
    
    try:
        # Load escaping model
        escaping_model_path = MODEL_DIR / "xss_escaping_model.joblib"
        escaping_vectorizer_path = MODEL_DIR / "xss_escaping_vectorizer.joblib"
        
        if escaping_model_path.exists() and escaping_vectorizer_path.exists():
            _escaping_model = joblib.load(escaping_model_path)
            _escaping_vectorizer = joblib.load(escaping_vectorizer_path)
            escaping_loaded = True
            
    except Exception as e:
        print(f"Failed to load escaping model: {e}")
    
    return context_loaded, escaping_loaded

def extract_features_for_inference(text_window: str, canary_pos: int) -> Tuple[np.ndarray, np.ndarray]:
    """Extract features for ML inference."""
    
    # Extract binary features (same as training)
    has_script_tag = '<script' in text_window.lower()
    has_style_tag = '<style' in text_window.lower() or 'style=' in text_window.lower()
    has_quotes = '"' in text_window or "'" in text_window
    has_equals = '=' in text_window
    has_angle_brackets = '<' in text_window and '>' in text_window
    has_url_attrs = any(attr in text_window.lower() for attr in ['href=', 'src=', 'action=', 'formaction='])
    has_style_attr = 'style=' in text_window.lower()
    
    # Quote type
    quote_type = ""
    if '"' in text_window:
        quote_type = "double"
    elif "'" in text_window:
        quote_type = "single"
    
    # Attribute name
    attr_name = ""
    attr_match = re.search(r'(\w+)=["\']([^"\']*EliseXSSCanary123[^"\']*)["\']', text_window)
    if attr_match:
        attr_name = attr_match.group(1)
    
    # Content type (not available in inference, use defaults)
    content_type = "text/html"
    
    # Binary features
    binary_features = np.array([[
        int(has_script_tag),
        int(has_style_tag),
        int(has_quotes),
        int(has_equals),
        int(has_angle_brackets),
        int(has_url_attrs),
        int(has_style_attr),
        int(has_script_tag),  # in_script_tag (same as has_script_tag for inference)
        int(bool(attr_name)),  # in_attr
        int(has_style_tag),  # in_style (same as has_style_tag for inference)
        1 if quote_type == 'double' else 0,
        1 if quote_type == 'single' else 0,
        1 if 'text/html' in content_type else 0,
        1 if 'application/json' in content_type else 0,
    ]])
    
    # Text features (same as training)
    text = text_window
    if has_script_tag:
        text += " SCRIPT_TAG"
    if has_style_tag:
        text += " STYLE_TAG"
    if has_quotes:
        text += f" QUOTES_{quote_type}"
    if has_equals:
        text += " EQUALS"
    if has_angle_brackets:
        text += " ANGLE_BRACKETS"
    if has_url_attrs:
        text += " URL_ATTRS"
    if has_style_attr:
        text += " STYLE_ATTR"
    if attr_name:
        text += f" ATTR_{attr_name}"
    
    return text, binary_features

def predict_xss_context(text_window: str, canary_pos: int) -> Optional[Dict[str, Any]]:
    """Predict XSS context using ML model."""
    global _context_model, _context_vectorizer
    
    if _context_model is None or _context_vectorizer is None:
        # Try to load models
        context_loaded, _ = load_models()
        if not context_loaded:
            return None
    
    try:
        from backend.ml.xss_ctx.utils import window
        
        # Extract windowed text (same as training)
        text = window(text_window, "EliseXSSCanary123", 120)
        
        # Transform text
        X = _context_vectorizer.transform([text])
        
        # Predict
        pred_proba = _context_model.predict_proba(X)[0]
        pred_class_idx = np.argmax(pred_proba)
        pred_class = _context_model.classes_[pred_class_idx]
        confidence = pred_proba[pred_class_idx]
        
        return {
            "pred": pred_class,
            "proba": float(confidence),
            "all_probas": {cls: float(prob) for cls, prob in zip(_context_model.classes_, pred_proba)}
        }
        
    except Exception as e:
        print(f"Error in context prediction: {e}")
        return None

def predict_xss_escaping(text_window: str, canary_pos: int) -> Optional[Dict[str, Any]]:
    """Predict XSS escaping using ML model."""
    global _escaping_model, _escaping_vectorizer
    
    if _escaping_model is None or _escaping_vectorizer is None:
        # Try to load models
        _, escaping_loaded = load_models()
        if not escaping_loaded:
            return None
    
    try:
        from backend.ml.xss_ctx.utils import window
        
        # Extract windowed text (same as training)
        text = window(text_window, "EliseXSSCanary123", 120)
        
        # Transform text
        X = _escaping_vectorizer.transform([text])
        
        # Predict
        pred_proba = _escaping_model.predict_proba(X)[0]
        pred_class_idx = np.argmax(pred_proba)
        pred_class = _escaping_model.classes_[pred_class_idx]
        confidence = pred_proba[pred_class_idx]
        
        return {
            "pred": pred_class,
            "proba": float(confidence),
            "all_probas": {cls: float(prob) for cls, prob in zip(_escaping_model.classes_, pred_proba)}
        }
        
    except Exception as e:
        print(f"Error in escaping prediction: {e}")
        return None

def get_model_info() -> Dict[str, Any]:
    """Get information about loaded models."""
    context_loaded, escaping_loaded = load_models()
    
    info = {
        "context_model_loaded": context_loaded,
        "escaping_model_loaded": escaping_loaded,
        "context_classes": None,
        "escaping_classes": None
    }
    
    if _context_model is not None:
        info["context_classes"] = _context_model.classes_.tolist()
    
    if _escaping_model is not None:
        info["escaping_classes"] = _escaping_model.classes_.tolist()
    
    return info

# Initialize models on import
load_models()
