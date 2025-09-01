# backend/modules/ml/enhanced_inference.py
from __future__ import annotations

import json
import logging
import os
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

# Enhanced ML imports with fallback
try:
    from .enhanced_features import EnhancedFeatureExtractor
    from .enhanced_trainer import EnhancedModelTrainer
    from .confidence_calibration import ConfidenceCalibrator
except ImportError:
    # Fallback for direct execution
    try:
        from enhanced_features import EnhancedFeatureExtractor
        from enhanced_trainer import EnhancedModelTrainer
        from confidence_calibration import ConfidenceCalibrator
    except ImportError:
        # Final fallback - create dummy classes
        class EnhancedFeatureExtractor:
            def extract_enhanced_features(self, *args, **kwargs):
                return {"dummy": 0.0}
        
        class EnhancedModelTrainer:
            pass
        
        class ConfidenceCalibrator:
            def __init__(self, method="isotonic"):
                self.method = method
                self.is_fitted = False

log = logging.getLogger(__name__)

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
                if model_path.exists() and JOBLIB_AVAILABLE:
                    self.models[family] = joblib.load(model_path)
                    log.info(f"Loaded enhanced {family} model from {model_path}")
                
                # Load scaler
                scaler_path = self.model_dir / f"enhanced_scaler_{family}.joblib"
                if scaler_path.exists() and JOBLIB_AVAILABLE:
                    self.scalers[family] = joblib.load(scaler_path)
                    log.info(f"Loaded {family} scaler from {scaler_path}")
                
                # Load metadata
                metadata_path = self.model_dir / f"enhanced_metadata_{family}.json"
                if metadata_path.exists():
                    with open(metadata_path, 'r') as f:
                        self.metadata[family] = json.load(f)
                    log.info(f"Loaded {family} metadata from {metadata_path}")
                
                # Initialize calibrator
                self.calibrators[family] = ConfidenceCalibrator(method="isotonic")
                
            except Exception as e:
                log.warning(f"Failed to load {family} model: {e}")
    
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
            
            # Convert features to numpy array
            feature_vector = np.array(list(features.values())).reshape(1, -1)
            
            # Check if we have the model
            if family not in self.models:
                return self._fallback_prediction(endpoint, param, family, context)
            
            # Preprocess features
            if family in self.scalers:
                feature_vector = self.scalers[family].transform(feature_vector)
            
            # Make prediction
            model = self.models[family]
            if hasattr(model, 'predict_proba'):
                # Classification model
                raw_proba = model.predict_proba(feature_vector)[0]
                prediction = model.predict(feature_vector)[0]
            else:
                # Ranking model
                raw_proba = model.predict(feature_vector)[0]
                prediction = 1 if raw_proba > 0.5 else 0
            
            # Ensure raw_proba is a scalar
            if hasattr(raw_proba, '__len__') and len(raw_proba) > 1:
                raw_proba = raw_proba[1] if len(raw_proba) == 2 else raw_proba[0]  # For binary classification
            raw_proba = float(raw_proba)
            
            # Calibrate probabilities if calibrator is fitted
            calibrated_proba = self._calibrate_probability(family, raw_proba)
            
            # Estimate uncertainty
            uncertainty = self._estimate_uncertainty(family, raw_proba, calibrated_proba)
            
            # Calculate confidence
            confidence = self._calculate_confidence(calibrated_proba, uncertainty)
            
            # Prepare result
            result = {
                "family": family,
                "prediction": int(prediction),
                "raw_probability": float(raw_proba),
                "calibrated_probability": float(calibrated_proba),
                "confidence": float(confidence),
                "uncertainty": float(uncertainty),
                "features_used": len(features),
                "model_type": self.metadata.get(family, {}).get("model_type", "unknown"),
                "calibration_method": self.calibrators[family].method if family in self.calibrators else "none"
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
        
        if family == 'sqli':
            # Check for SQL injection indicators
            sql_indicators = ['id', 'user_id', 'product_id', 'order_id', 'search', 'query']
            probability = 0.3 if any(ind in param_name for ind in sql_indicators) else 0.1
            
        elif family == 'xss':
            # Check for XSS indicators
            xss_indicators = ['content', 'body', 'text', 'message', 'comment', 'title', 'name']
            probability = 0.4 if any(ind in param_name for ind in xss_indicators) else 0.1
            
        elif family == 'redirect':
            # Check for redirect indicators
            redirect_indicators = ['next', 'return', 'redirect', 'url', 'target', 'callback']
            probability = 0.5 if any(ind in param_name for ind in redirect_indicators) else 0.1
            
        else:
            probability = 0.1
        
        return {
            "family": family,
            "prediction": 1 if probability > 0.3 else 0,
            "raw_probability": probability,
            "calibrated_probability": probability,
            "confidence": 0.5,  # Medium confidence for fallback
            "confidence": 0.5,  # Medium confidence for fallback
            "uncertainty": 0.5,  # High uncertainty for fallback
            "features_used": 0,
            "model_type": "fallback",
            "calibration_method": "none",
            "fallback_used": True
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
        Rank payload candidates with enhanced features and confidence.
        
        Args:
            endpoint: Endpoint information
            param: Parameter information
            family: Vulnerability family
            candidates: List of payload candidates
            context: Additional context
            top_k: Number of top candidates to return
        
        Returns:
            List of ranked payloads with confidence scores
        """
        if not candidates:
            return []
        
        # Get base prediction for the endpoint-parameter combination
        base_prediction = self.predict_with_confidence(endpoint, param, family, context)
        
        # Rank candidates based on family-specific heuristics
        ranked_candidates = []
        
        for i, payload in enumerate(candidates):
            # Calculate payload-specific score
            payload_score = self._calculate_payload_score(payload, family, param)
            
            # Combine with base prediction
            combined_score = (base_prediction["calibrated_probability"] + payload_score) / 2
            
            # Calculate confidence for this specific payload
            payload_confidence = self._calculate_payload_confidence(
                payload, family, base_prediction, context
            )
            
            ranked_candidates.append({
                "payload": payload,
                "rank": i + 1,
                "score": float(combined_score),
                "confidence": float(payload_confidence),
                "family": family,
                "base_prediction": base_prediction["calibrated_probability"],
                "payload_score": float(payload_score)
            })
        
        # Sort by combined score
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

