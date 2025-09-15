"""
XSS Context ML Inference Module

Provides ML-based predictions for XSS context and escaping classification.
Used by the hybrid rule-ML approach in xss_canary.py.
"""

import numpy as np
import re
from typing import Dict, Any, Optional, Tuple
from threading import Lock
from pathlib import Path
import joblib
import sys
import os

from backend.app_state import MODEL_DIR
import joblib
from sklearn.base import BaseEstimator


class MockContextModel:
    """Mock XSS context model for testing when real models can't be loaded."""
    
    def __init__(self):
        self.classes_ = np.array(['attr', 'comment', 'css', 'html_body', 'js_string', 'json', 'url'])
    
    def predict_proba(self, X):
        """Return mock context probabilities."""
        n_samples = X.shape[0]
        # Return mock probabilities for different contexts
        probs = np.array([[0.1, 0.1, 0.1, 0.1, 0.6, 0.1, 0.1]] * n_samples)  # js_string has highest prob
        return probs
    
    def predict(self, X):
        """Return mock context predictions."""
        n_samples = X.shape[0]
        return np.array([4] * n_samples)  # js_string index


class MockEscapingModel:
    """Mock XSS escaping model for testing when real models can't be loaded."""
    
    def __init__(self):
        self.classes_ = np.array(['html', 'js', 'raw', 'url'])
    
    def predict_proba(self, X):
        """Return mock escaping probabilities."""
        n_samples = X.shape[0]
        # Return mock probabilities for different escaping types
        probs = np.array([[0.2, 0.2, 0.2, 0.4]] * n_samples)  # raw has highest prob
        return probs
    
    def predict(self, X):
        """Return mock escaping predictions."""
        n_samples = X.shape[0]
        return np.array([2] * n_samples)  # raw index


class MockVectorizer:
    """Mock vectorizer for testing when real vectorizers can't be loaded."""
    
    def transform(self, X):
        """Return mock feature vectors."""
        n_samples = len(X)
        return np.random.rand(n_samples, 100)  # Random 100-dimensional vectors


# Global model cache with thread synchronization
_context_model = None
_context_vectorizer = None
_escaping_model = None
_escaping_vectorizer = None
_ctx_pipeline = None  # optional sklearn Pipeline
_esc_pipeline = None
_model_loading_lock = Lock()

def load_models() -> Tuple[bool, bool]:
    """Load ML models if available with thread synchronization."""
    global _context_model, _context_vectorizer, _escaping_model, _escaping_vectorizer, _model_loading_lock
    
    # Check if models are already loaded
    if _context_model is not None and _context_vectorizer is not None and _escaping_model is not None and _escaping_vectorizer is not None:
        return True, True
    
    # Use lock to prevent race conditions during model loading
    with _model_loading_lock:
        # Double-check after acquiring lock
        if _context_model is not None and _context_vectorizer is not None and _escaping_model is not None and _escaping_vectorizer is not None:
            return True, True
        
        context_loaded = False
        escaping_loaded = False
        
        try:
            # Load context model
            context_model_path = MODEL_DIR / "xss_context_model.joblib"
            context_vectorizer_path = MODEL_DIR / "xss_context_vectorizer.joblib"
            ctx_pipe_path = MODEL_DIR / "xss_context_pipeline.joblib"
            
            skip_pipe = os.getenv('ELISE_SKIP_XSS_PIPELINE', '1') == '1'
            if not skip_pipe and ctx_pipe_path.exists():
                try:
                    global _ctx_pipeline
                    # Compat: some pipelines depend on numpy._core (NumPy >=2)
                    try:
                        import numpy as _np
                        if 'numpy._core' not in sys.modules:
                            sys.modules['numpy._core'] = _np.core
                    except Exception:
                        pass
                    _ctx_pipeline = joblib.load(ctx_pipe_path)
                    context_loaded = True
                    print("XSS context pipeline loaded successfully")
                except Exception as e:
                    print(f"Failed to load XSS context pipeline: {e}")
            if _ctx_pipeline is None and context_model_path.exists() and context_vectorizer_path.exists():
                # Try loading with compatibility options for numpy 2.x
                # Compat alias for numpy._core
                try:
                    import numpy as _np
                    if 'numpy._core' not in sys.modules:
                        sys.modules['numpy._core'] = _np.core
                except Exception:
                    pass
                _context_model = joblib.load(context_model_path, mmap_mode=None)
                _context_vectorizer = joblib.load(context_vectorizer_path, mmap_mode=None)
                context_loaded = True
                print("Context model loaded successfully")
                
        except Exception as e:
            print(f"Failed to load context model: {e}")
            print(f"Context model path exists: {(MODEL_DIR / 'xss_context_model.joblib').exists()}")
            print(f"Context vectorizer path exists: {(MODEL_DIR / 'xss_context_vectorizer.joblib').exists()}")
            # Use mock model as fallback
            _context_model = MockContextModel()
            _context_vectorizer = MockVectorizer()
            context_loaded = True
            print("Using mock context model")
            print(f"Mock context model classes: {_context_model.classes_}")
        
        try:
            # Load escaping model
            escaping_model_path = MODEL_DIR / "xss_escaping_model.joblib"
            escaping_vectorizer_path = MODEL_DIR / "xss_escaping_vectorizer.joblib"
            esc_pipe_path = MODEL_DIR / "xss_escaping_pipeline.joblib"
            
            skip_esc_pipe = os.getenv('ELISE_SKIP_XSS_PIPELINE', '1') == '1'
            if not skip_esc_pipe and esc_pipe_path.exists():
                try:
                    global _esc_pipeline
                    # Compat: numpy._core alias for legacy pickles
                    try:
                        import numpy as _np
                        if 'numpy._core' not in sys.modules:
                            sys.modules['numpy._core'] = _np.core
                    except Exception:
                        pass
                    _esc_pipeline = joblib.load(esc_pipe_path)
                    escaping_loaded = True
                    print("XSS escaping pipeline loaded successfully")
                except Exception as e:
                    print(f"Failed to load XSS escaping pipeline: {e}")
            if _esc_pipeline is None and escaping_model_path.exists() and escaping_vectorizer_path.exists():
                # Try loading with compatibility options for numpy 2.x
                try:
                    import numpy as _np
                    if 'numpy._core' not in sys.modules:
                        sys.modules['numpy._core'] = _np.core
                except Exception:
                    pass
                _escaping_model = joblib.load(escaping_model_path, mmap_mode=None)
                _escaping_vectorizer = joblib.load(escaping_vectorizer_path, mmap_mode=None)
                escaping_loaded = True
                print("Escaping model loaded successfully")
                
        except Exception as e:
            print(f"Failed to load escaping model: {e}")
            print(f"Escaping model path exists: {(MODEL_DIR / 'xss_escaping_model.joblib').exists()}")
            print(f"Escaping vectorizer path exists: {(MODEL_DIR / 'xss_escaping_vectorizer.joblib').exists()}")
            # Use mock model as fallback
            _escaping_model = MockEscapingModel()
            _escaping_vectorizer = MockVectorizer()
            escaping_loaded = True
            print("Using mock escaping model")
            print(f"Mock escaping model classes: {_escaping_model.classes_}")
        
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

def _extract_features(text_window: str) -> Tuple[str, np.ndarray]:
    """Extract features using the same method as training."""
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
    elif '`' in text_window:
        quote_type = "backtick"
    else:
        quote_type = "none"
    
    # Attribute name
    attr_name = ""
    attr_match = re.search(r'(\w+)=["\']([^"\']*EliseXSSCanary123[^"\']*)["\']', text_window)
    if attr_match:
        attr_name = attr_match.group(1)
    
    # Content type (not available in inference, use defaults)
    content_type = "text/html"
    
    # Binary features (matching training script)
    feature_row = [
        int(has_script_tag),
        int(has_style_tag),
        int(has_quotes),
        int(has_equals),
        int(has_angle_brackets),
        int(has_url_attrs),
        int(has_style_attr),
    ]
    
    # One-hot encode quote type
    quote_types = ['single', 'double', 'backtick', 'none']
    for qt in quote_types:
        feature_row.append(int(quote_type == qt))
    
    # One-hot encode attr name feature
    attr_names = ['src', 'href', 'value', 'onclick', 'style', 'class', 'id', 'other', 'none']
    for an in attr_names:
        feature_row.append(int(attr_name == an))
    
    binary_features = np.array([feature_row])
    
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
        if _ctx_pipeline is not None:
            # Use pipeline on augmented window text
            text_aug, _ = extract_features_for_inference(text_window, canary_pos)
            proba = _ctx_pipeline.predict_proba([text_aug])[0]
            if hasattr(_ctx_pipeline.named_steps['clf'], 'classes_'):
                classes = _ctx_pipeline.named_steps['clf'].classes_
            else:
                # Fallback: infer from meta if needed
                classes = np.array(['html_body','attr','js_string','url','css','comment','json'])
            idx = int(np.argmax(proba))
            pred_class = classes[idx]
            confidence = float(proba[idx])
            return {"pred": pred_class, "proba": confidence, "all_probas": {cls: float(p) for cls,p in zip(classes, proba)}}

        # Legacy path
        text, binary_features = extract_features_for_inference(text_window, canary_pos)
        X_text = _context_vectorizer.transform([text])
        X = np.hstack([X_text.toarray(), binary_features])
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
        if _esc_pipeline is not None:
            text_aug, _ = extract_features_for_inference(text_window, canary_pos)
            proba = _esc_pipeline.predict_proba([text_aug])[0]
            if hasattr(_esc_pipeline.named_steps['clf'], 'classes_'):
                classes = _esc_pipeline.named_steps['clf'].classes_
            else:
                classes = np.array(['raw','html','url','js'])
            idx = int(np.argmax(proba))
            pred_class = classes[idx]
            confidence = float(proba[idx])
            return {"pred": pred_class, "proba": confidence, "all_probas": {cls: float(p) for cls,p in zip(classes, proba)}}

        # Legacy path
        text, binary_features = extract_features_for_inference(text_window, canary_pos)
        X_text = _escaping_vectorizer.transform([text])
        X = np.hstack([X_text.toarray(), binary_features])
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
