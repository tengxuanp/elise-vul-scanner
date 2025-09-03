# backend/modules/ml/enhanced_inference.py
from __future__ import annotations

import json
import logging
import os
import hashlib
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import numpy as np

try:
    import joblib
    JOBLIB_AVAILABLE = True
except ImportError:
    JOBLIB_AVAILABLE = False

try:
    import xgboost as xgb
    XGB_AVAILABLE = True
except ImportError:
    xgb = None  # type: ignore
    XGB_AVAILABLE = False

# Set up logging first
log = logging.getLogger(__name__)

# Enhanced ML imports with fallback
try:
    # Use absolute import from 'backend' assuming the project root is in sys.path
    # This is handled by the entrypoint in main.py
    from backend.modules.ml.enhanced_features import EnhancedFeatureExtractor
    from backend.modules.ml.enhanced_trainer import EnhancedModelTrainer
    from backend.modules.ml.confidence_calibration import ConfidenceCalibrator
    log.info("✅ Successfully imported Enhanced ML modules using absolute import.")
except ImportError as e:
    # Final fallback - create dummy classes
    log.critical(f"🚨 CRITICAL: Failed to import EnhancedFeatureExtractor. Using dummy class. Error: {e!r}")
    log.critical(f"🚨 This will cause ML scoring to fail! Check the import paths and package structure.")
    
    class EnhancedFeatureExtractor:
        def extract_enhanced_features(self, *args, **kwargs):
            log.error("🚨 DUMMY FEATURE EXTRACTOR BEING USED - ML SCORING WILL FAIL!")
            return {"dummy": 0.0}
    
    class EnhancedModelTrainer:
        pass
    
    class ConfidenceCalibrator:
        def __init__(self, method="isotonic"):
            self.method = method
            self.is_fitted = False

class EnhancedInferenceEngine:
    """
    Enhanced inference engine with improved features, confidence calibration, and uncertainty estimation.
    
    Features:
    - Enhanced feature extraction
    - Confidence calibration
    - Uncertainty quantification
    - Ensemble predictions
    - Fallback mechanisms
    """
    
    def __init__(self, model_dir: Optional[str] = None):
        self.model_dir = Path(model_dir) if model_dir else Path(__file__).parent
        self.feature_extractor = EnhancedFeatureExtractor()
        self.models = {}
        self.scalers = {}
        self.calibrators = {}
        self.metadata = {}
        
        # Load models and metadata
        self._load_models()
    
    def _load_models(self):
        """Load trained models, scalers, and metadata."""
        families = ["sqli", "xss", "redirect"]
        
        for family in families:
            try:
                # Load enhanced model
                model_path = self.model_dir / f"enhanced_ranker_{family}.joblib"
                if (model_path.exists() and JOBLIB_AVAILABLE):
                    self.models[family] = joblib.load(model_path)
                    log.info(f"✅ Loaded enhanced {family} model from {model_path}")
                else:
                    log.warning(f"❌ Enhanced {family} model not found at {model_path}")
                
                # Load scaler
                scaler_path = self.model_dir / f"enhanced_scaler_{family}.joblib"
                if (scaler_path.exists() and JOBLIB_AVAILABLE):
                    self.scalers[family] = joblib.load(scaler_path)
                    expected_features = getattr(self.scalers[family], 'n_features_in_', 'unknown')
                    log.info(f"✅ Loaded {family} scaler from {scaler_path}, expects {expected_features} features")
                else:
                    log.warning(f"❌ Enhanced {family} scaler not found at {scaler_path}")
                
                # Load metadata
                metadata_path = self.model_dir / f"enhanced_metadata_{family}.json"
                if metadata_path.exists():
                    with open(metadata_path, 'r') as f:
                        self.metadata[family] = json.load(f)
                    log.info(f"✅ Loaded {family} metadata from {metadata_path}")
                else:
                    log.warning(f"❌ Enhanced {family} metadata not found at {metadata_path}")

                # Initialize calibrator
                self.calibrators[family] = ConfidenceCalibrator(method="isotonic")
                
                # Verify model is properly loaded
                if family in self.models and family in self.scalers:
                    log.info(f"✅ Enhanced ML for {family} fully loaded and ready")
                else:
                    log.warning(f"⚠️ Enhanced ML for {family} partially loaded - model: {family in self.models}, scaler: {family in self.scalers}")
                
            except Exception as e:
                log.error(f"❌ Failed to load {family} enhanced ML components: {e}")
                # Clean up partial loads
                if family in self.models:
                    del self.models[family]
                if family in self.scalers:
                    del self.scalers[family]
                if family in self.metadata:
                    del self.metadata[family]
    
    def predict_with_confidence(
        self,
        endpoint: Dict[str, Any],
        param: Dict[str, Any],
        family: str,
        context: Optional[Dict[str, Any]] = None,
        top_k: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Make predictions with confidence scores and uncertainty estimates.
        
        Args:
            endpoint: Endpoint information
            param: Parameter information
            family: Vulnerability family
            context: Additional context
            top_k: Number of top predictions to return
        
        Returns:
            Dictionary with predictions, confidence, and uncertainty
        """
        try:
            # Extract enhanced features
            features = self.feature_extractor.extract_enhanced_features(
                endpoint, param, family, context
            )
            
            # CRITICAL DEBUG: Log the exact feature count and structure
            log.info(f"DEBUG: Feature extraction result - count: {len(features)}, keys: {list(features.keys())[:10]}...")
            log.info(f"DEBUG: Feature values shape: {np.array(list(features.values())).shape}")
            
            # Debug logging for payload-specific features
            if context and 'payload' in context:
                payload = context['payload']
                payload_features = [k for k, v in features.items() if k.startswith('payload_')]
                log.info(f"Extracted {len(payload_features)} payload-specific features for payload '{payload[:50]}': {payload_features[:5]}...")
            
            # Convert features to numpy array
            feature_vector = np.array(list(features.values())).reshape(1, -1)
            log.info(f"DEBUG: Feature vector shape before scaler: {feature_vector.shape}")
            
            # Check if we have the model
            if family not in self.models:
                log.warning(f"No model loaded for family {family}, using fallback")
                return self._fallback_prediction(endpoint, param, family, context)
            
            log.info(f"Using trained {family} model for prediction")
            
            # Preprocess features
            if family in self.scalers:
                log.info(f"DEBUG: About to apply scaler for {family}, feature vector shape: {feature_vector.shape}")
                try:
                    expected_features = self.scalers[family].n_features_in_ if hasattr(self.scalers[family], 'n_features_in_') else 'unknown'
                    log.info(f"DEBUG: Scaler expects {expected_features} features, got {feature_vector.shape[1]}")
                    feature_vector = self.scalers[family].transform(feature_vector)
                    log.info(f"DEBUG: Scaler transformation successful, new shape: {feature_vector.shape}")
                except Exception as scaler_error:
                    log.error(f"DEBUG: Scaler transformation failed: {scaler_error}")
                    log.error(f"DEBUG: Feature vector content: {feature_vector.flatten()[:10]}...")
                    log.warning(f"Scaler failed for {family}, using fallback prediction")
                    return self._fallback_prediction(endpoint, param, family, context)
            
            # Make prediction
            model = self.models[family]
            if hasattr(model, 'predict_proba'):
                # Classification model
                raw_proba = model.predict_proba(feature_vector)[0]
                prediction = model.predict(feature_vector)[0]
                log.info(f"DEBUG: Classification model prediction - raw_proba: {raw_proba}, prediction: {prediction}")
            else:
                # Ranking model
                raw_proba = model.predict(feature_vector)[0]
                prediction = 1 if raw_proba > 0.5 else 0
                log.info(f"DEBUG: Ranking model prediction - raw_proba: {raw_proba}, prediction: {prediction}")
            
            # Ensure raw_proba is a scalar
            if hasattr(raw_proba, '__len__') and len(raw_proba) > 1:
                raw_proba = raw_proba[1] if len(raw_proba) == 2 else raw_proba[0]  # For binary classification
            raw_proba = float(raw_proba)
            log.info(f"DEBUG: Final raw_proba after scalar conversion: {raw_proba}")
            
            # Calibrate probabilities if calibrator is fitted
            calibrated_proba = self._calibrate_probability(family, raw_proba)
            log.info(f"DEBUG: Calibrated probability: {calibrated_proba}")
            
            # Estimate uncertainty
            uncertainty = self._estimate_uncertainty(family, raw_proba, calibrated_proba)
            
            # Calculate confidence
            confidence = self._calculate_confidence(calibrated_proba, uncertainty)
            log.info(f"DEBUG: Final confidence score: {confidence} for family {family}")
            
            # Prepare result
            result = {
                "family": family,
                "prediction": int(prediction),
                "raw_probability": float(raw_proba),
                "calibrated_probability": float(calibrated_proba),
                "confidence": float(confidence),
                "uncertainty": float(uncertainty),
                "features_used": len(features),
                "model_type": self.metadata.get(family, {}).get("model_type", "enhanced_ml"),
                "calibration_method": self.calibrators[family].method if family in self.calibrators else "none",
                "used_path": "enhanced_ml",  # Indicate this used real ML
                "is_ml_prediction": True,    # Clear flag for frontend
                "fallback_used": False       # Not a fallback
            }
            
            # Add feature importance if available
            if family in self.metadata and "feature_importance" in self.metadata[family]:
                result["top_features"] = self._get_top_features(family, features)
            
            return result
            
        except Exception as e:
            log.error(f"Error in enhanced prediction for {family}: {e}")
            return self._fallback_prediction(endpoint, param, family, context)
    
    def _calibrate_probability(self, family: str, raw_proba: float) -> float:
        """Calibrate raw probability using fitted calibrator."""
        if family not in self.calibrators:
            return raw_proba
        
        calibrator = self.calibrators[family]
        if not calibrator.is_fitted:
            return raw_proba
        
        try:
            # Convert to 2D array for calibrator
            proba_array = np.array([[raw_proba]])
            calibrated = calibrator.calibrate(proba_array)
            return float(calibrated[0])
        except Exception as e:
            log.warning(f"Calibration failed for {family}: {e}")
            return raw_proba
    
    def _estimate_uncertainty(self, family: str, raw_proba: float, 
                            calibrated_proba: float) -> float:
        """Estimate prediction uncertainty."""
        # Use entropy-based uncertainty
        proba = calibrated_proba if calibrated_proba != raw_proba else raw_proba
        eps = 1e-15
        proba = np.clip(proba, eps, 1 - eps)
        
        # Binary entropy: -p*log(p) - (1-p)*log(1-p)
        entropy = -proba * np.log(proba) - (1 - proba) * np.log(1 - proba)
        
        # Normalize to [0, 1] range
        max_entropy = np.log(2)  # Maximum entropy for binary case
        normalized_entropy = entropy / max_entropy
        
        return float(normalized_entropy)
    
    def _calculate_confidence(self, probability: float, uncertainty: float) -> float:
        """Calculate confidence score combining probability and uncertainty."""
        # Simple confidence calculation: high probability + low uncertainty = high confidence
        confidence = probability * (1 - uncertainty)
        return float(np.clip(confidence, 0.0, 1.0))
    
    def _get_top_features(self, family: str, features: Dict[str, float]) -> List[Dict[str, Any]]:
        """Get top contributing features for the prediction."""
        if family not in self.metadata:
            return []
        
        feature_importance = self.metadata[family].get("feature_importance", {})
        if not feature_importance:
            return []
        
        # Sort features by importance
        sorted_features = sorted(
            feature_importance.items(), 
            key=lambda x: x[1], 
            reverse=True
        )[:5]  # Top 5 features
        
        # Map feature indices to actual feature names
        feature_names = list(features.keys())
        top_features = []
        
        for feat_idx, importance in sorted_features:
            try:
                # Extract feature index from "feature_X" format
                idx = int(feat_idx.split("_")[1])
                if idx < len(feature_names):
                    feature_name = feature_names[idx]
                    feature_value = features[feature_name]
                    top_features.append({
                        "name": feature_name,
                        "value": float(feature_value),
                        "importance": float(importance)
                    })
            except (ValueError, IndexError):
                continue
        
        return top_features
    
    def _fallback_prediction(self, endpoint: Dict[str, Any], param: Dict[str, Any], 
                           family: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Fallback prediction when enhanced model is not available."""
        log.info(f"Using fallback prediction for {family}")
        
        # Simple heuristic-based prediction
        param_name = param.get('name', '').lower()
        param_value = str(param.get('value', '')).lower()
        
        score = 0.0
        
        if family == 'sqli':
            # Check for SQL injection indicators
            sql_indicators = ['id', 'user_id', 'product_id', 'order_id', 'search', 'query']
            if any(indicator in param_name for indicator in sql_indicators):
                score = 0.1  # Assign a low base score for potential SQLi params
            
        elif family == 'xss':
            # Check for XSS indicators
            xss_indicators = ['name', 'message', 'comment', 'redirect', 'url']
            if any(indicator in param_name for indicator in xss_indicators):
                score = 0.1  # Assign a low base score for potential XSS params
            
        elif family == 'redirect':
            # Check for redirect indicators
            redirect_indicators = ['next', 'url', 'target', 'redirect', 'return_to']
            if any(indicator in param_name for indicator in redirect_indicators):
                score = 0.1  # Assign a low base score for potential redirect params
            
        else:
            score = 0.0

        return {
            "family": family,
            "prediction": 0,
            "raw_probability": score,
            "calibrated_probability": score,
            "confidence": 0.1,  # Low confidence for heuristics
            "uncertainty": 0.9, # High uncertainty
            "features_used": 0,
            "model_type": "heuristic",
            "calibration_method": "none",
            "used_path": "heuristic",     # Indicate this is heuristic
            "is_ml_prediction": False,    # Clear flag for frontend 
            "fallback_used": True         # This is a fallback
        }
    
    def rank_payloads(
        self,
        endpoint: Dict[str, Any],
        param: Dict[str, Any],
        family: str,
        candidates: List[str],
        context: Optional[Dict[str, Any]] = None,
        top_k: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """
        Ranks payload candidates using the actual ML model for each payload.
        Each payload gets individual ML scoring based on its specific content and features.
        """
        if not candidates:
            return []

        ranked_candidates = []
        for i, payload in enumerate(candidates):
            try:
                # 1. Create payload-specific parameter context
                payload_param = param.copy()
                payload_param['value'] = payload  # Use the actual payload as the value
                
                # 2. Create payload-specific context that includes the payload content
                payload_context = (context or {}).copy()
                payload_context['payload'] = payload
                payload_context['payload_length'] = len(payload)
                payload_context['payload_hash'] = hashlib.md5(payload.encode()).hexdigest()[:8]
                
                # 3. Get ML prediction for this specific payload with payload-specific features
                payload_prediction = self.predict_with_confidence(
                    endpoint, payload_param, family, payload_context
                )
                
                # 4. Extract ML-driven scores from the prediction
                ml_score = payload_prediction.get("calibrated_probability", 0.0)
                confidence = payload_prediction.get("confidence", 0.5)
                uncertainty = payload_prediction.get("uncertainty", 0.5)
                
                ranked_candidates.append({
                    "payload": payload,
                    "rank": i + 1,
                    "score": float(ml_score),
                    "confidence": float(confidence),
                    "uncertainty": float(uncertainty),
                    "family": family,
                    "raw_probability": payload_prediction.get("raw_probability", 0.0),
                    "calibrated_probability": float(ml_score),
                    "model_type": payload_prediction.get("model_type", "enhanced"),
                    "features_used": payload_prediction.get("features_used", 0),
                    "fallback_used": payload_prediction.get("fallback_used", False),
                    "payload_specific": True  # Flag indicating this score is payload-specific
                })
                
            except Exception as e:
                log.warning(f"Failed to get ML prediction for payload {payload[:50]}: {e}")
                # Fallback to basic scoring if ML fails for this payload
                fallback_score = self._calculate_payload_score(payload, family, param)
                ranked_candidates.append({
                    "payload": payload,
                    "rank": i + 1,
                    "score": float(fallback_score),
                    "confidence": 0.3,  # Low confidence for fallback
                    "uncertainty": 0.7,  # High uncertainty for fallback
                    "family": family,
                    "raw_probability": fallback_score,
                    "calibrated_probability": float(fallback_score),
                    "model_type": "fallback",
                    "features_used": 0,
                    "fallback_used": True,
                    "payload_specific": False  # Flag indicating this score is heuristic
                })
        
        # 5. Sort candidates based on the ML score (highest first)
        ranked_candidates.sort(key=lambda x: x["score"], reverse=True)
        
        # Apply top_k if specified
        if top_k is not None:
            ranked_candidates = ranked_candidates[:top_k]
        
        # Update ranks
        for i, candidate in enumerate(ranked_candidates):
            candidate["rank"] = i + 1
        
        return ranked_candidates
    
    def _calculate_payload_score(self, payload: str, family: str, param: Dict[str, Any]) -> float:
        """Calculate payload-specific score based on family and parameter context."""
        payload_lower = payload.lower()
        param_name = param.get('name', '').lower()
        
        if family == 'sqli':
            # SQL injection payload scoring
            if "'" in payload or '"' in payload:
                base_score = 0.8
            elif any(keyword in payload_lower for keyword in ['union', 'select', 'or', 'and']):
                base_score = 0.7
            elif any(keyword in payload_lower for keyword in ['sleep', 'waitfor', 'benchmark']):
                base_score = 0.6
            else:
                base_score = 0.4
                
        elif family == 'xss':
            # XSS payload scoring
            if '<script>' in payload_lower:
                base_score = 0.9
            elif any(tag in payload_lower for tag in ['<img', '<svg', '<iframe']):
                base_score = 0.8
            elif 'onerror=' in payload_lower or 'onload=' in payload_lower:
                base_score = 0.7
            else:
                base_score = 0.5
                
        elif family == 'redirect':
            # Redirect payload scoring
            if payload_lower.startswith(('http://', 'https://')):
                base_score = 0.8
            elif payload_lower.startswith('//'):
                base_score = 0.7
            elif '%2f%2f' in payload_lower:
                base_score = 0.6
            else:
                base_score = 0.4
        else:
            base_score = 0.3
        
        # Adjust based on parameter context
        if family == 'sqli' and any(num in param_name for num in ['id', 'num', 'count']):
            base_score += 0.1
        elif family == 'xss' and any(text in param_name for text in ['content', 'body', 'message']):
            base_score += 0.1
        elif family == 'redirect' and any(redirect in param_name for redirect in ['next', 'return', 'url']):
            base_score += 0.1
        
        return min(1.0, base_score)
    
    def _calculate_payload_confidence(
        self,
        payload: str,
        family: str,
        base_prediction: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> float:
        """Calculate confidence for a specific payload."""
        # Start with base confidence
        confidence = base_prediction.get("confidence", 0.5)
        
        # Adjust based on payload complexity
        payload_complexity = len(payload) / 100.0  # Normalize by expected max length
        complexity_factor = 1.0 - min(0.3, payload_complexity * 0.3)
        
        # Adjust based on context if available
        context_factor = 1.0
        if context and "prev_responses" in context:
            # Lower confidence if we have limited context
            context_factor = min(1.0, len(context["prev_responses"]) / 10.0)
        
        final_confidence = confidence * complexity_factor * context_factor
        return float(np.clip(final_confidence, 0.0, 1.0))
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about loaded models."""
        info = {
            "models_loaded": list(self.models.keys()),
            "scalers_loaded": list(self.scalers.keys()),
            "metadata_available": list(self.metadata.keys()),
            "total_models": len(self.models)
        }
        
        # Add per-family details
        for family in self.models.keys():
            if family in self.metadata:
                info[f"{family}_model_type"] = self.metadata[family].get("model_type", "unknown")
                info[f"{family}_features"] = self.metadata[family].get("feature_count", 0)
                info[f"{family}_cv_score"] = self.metadata[family].get("cv_scores", {}).get("cv_mean", 0.0)
        
        return info
    
    def retrain_calibrator(self, family: str, y_true: List[int], 
                          y_pred_proba: List[float]) -> bool:
        """Retrain the confidence calibrator for a specific family."""
        if family not in self.calibrators:
            log.warning(f"No calibrator found for family: {family}")
            return False
        
        try:
            calibrator = self.calibrators[family]
            y_true_array = np.array(y_true)
            y_pred_array = np.array(y_pred_proba)
            
            calibrator.fit(y_true_array, y_pred_array)
            log.info(f"Retrained calibrator for {family}")
            return True
            
        except Exception as e:
            log.error(f"Failed to retrain calibrator for {family}: {e}")
            return False

