# backend/modules/ml/confidence_calibration.py
from __future__ import annotations

import numpy as np
import logging
from typing import Dict, Any, List, Tuple, Optional
from sklearn.calibration import CalibratedClassifierCV, calibration_curve
from sklearn.metrics import brier_score_loss
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression
import matplotlib.pyplot as plt
from pathlib import Path

log = logging.getLogger(__name__)

class ConfidenceCalibrator:
    """
    Confidence calibration for ML models to provide better uncertainty quantification.
    
    This module implements several calibration techniques:
    - Platt scaling (logistic regression)
    - Isotonic regression
    - Temperature scaling
    - Ensemble-based uncertainty
    """
    
    def __init__(self, method: str = "isotonic"):
        """
        Initialize the calibrator.
        
        Args:
            method: Calibration method ("platt", "isotonic", "temperature", "ensemble")
        """
        self.method = method
        self.calibrator = None
        self.calibration_params = {}
        self.is_fitted = False
        
    def fit(self, y_true: np.ndarray, y_pred_proba: np.ndarray, 
            method: Optional[str] = None) -> "ConfidenceCalibrator":
        """
        Fit the calibrator on validation data.
        
        Args:
            y_true: True labels
            y_pred_proba: Predicted probabilities
            method: Override the default method
        
        Returns:
            Self for chaining
        """
        if method:
            self.method = method
            
        if self.method == "platt":
            self._fit_platt(y_true, y_pred_proba)
        elif self.method == "isotonic":
            self._fit_isotonic(y_true, y_pred_proba)
        elif self.method == "temperature":
            self._fit_temperature(y_true, y_pred_proba)
        elif self.method == "ensemble":
            self._fit_ensemble(y_true, y_pred_proba)
        else:
            raise ValueError(f"Unknown calibration method: {self.method}")
        
        self.is_fitted = True
        return self
    
    def _fit_platt(self, y_true: np.ndarray, y_pred_proba: np.ndarray):
        """Fit Platt scaling (logistic regression)."""
        # Ensure we have 2D array for sklearn
        if y_pred_proba.ndim == 1:
            y_pred_proba = y_pred_proba.reshape(-1, 1)
        
        # Platt scaling: fit logistic regression to logits
        # Convert probabilities to logits
        eps = 1e-15
        y_pred_proba = np.clip(y_pred_proba, eps, 1 - eps)
        logits = np.log(y_pred_proba / (1 - y_pred_proba))
        
        self.calibrator = LogisticRegression()
        self.calibrator.fit(logits, y_true)
        
        self.calibration_params = {
            'method': 'platt',
            'coef': self.calibrator.coef_[0][0],
            'intercept': self.calibrator.intercept_[0]
        }
        
        log.info(f"Fitted Platt scaling: coef={self.calibration_params['coef']:.4f}, "
                f"intercept={self.calibration_params['intercept']:.4f}")
    
    def _fit_isotonic(self, y_true: np.ndarray, y_pred_proba: np.ndarray):
        """Fit isotonic regression."""
        if y_pred_proba.ndim == 1:
            y_pred_proba = y_pred_proba.reshape(-1, 1)
        
        # Use the first column if we have multiple
        probas = y_pred_proba[:, 0] if y_pred_proba.shape[1] > 1 else y_pred_proba.flatten()
        
        self.calibrator = IsotonicRegression(out_of_bounds='clip')
        self.calibrator.fit(probas, y_true)
        
        self.calibration_params = {
            'method': 'isotonic',
            'fitted': True
        }
        
        log.info("Fitted isotonic regression calibrator")
    
    def _fit_temperature(self, y_true: np.ndarray, y_pred_proba: np.ndarray):
        """Fit temperature scaling."""
        if y_pred_proba.ndim == 1:
            y_pred_proba = y_pred_proba.reshape(-1, 1)
        
        # Temperature scaling: find optimal temperature T
        # P(y|x) = softmax(logits / T)
        eps = 1e-15
        y_pred_proba = np.clip(y_pred_proba, eps, 1 - eps)
        logits = np.log(y_pred_proba / (1 - y_pred_proba))
        
        # Optimize temperature using validation set
        temperatures = np.logspace(-2, 2, 100)
        best_temp = 1.0
        best_score = float('inf')
        
        for temp in temperatures:
            calibrated_probs = self._apply_temperature(logits, temp)
            score = brier_score_loss(y_true, calibrated_probs)
            if score < best_score:
                best_score = score
                best_temp = temp
        
        self.calibration_params = {
            'method': 'temperature',
            'temperature': best_temp
        }
        
        log.info(f"Fitted temperature scaling: T={best_temp:.4f}")
    
    def _fit_ensemble(self, y_true: np.ndarray, y_pred_proba: np.ndarray):
        """Fit ensemble-based uncertainty estimation."""
        if y_pred_proba.ndim == 1:
            y_pred_proba = y_pred_proba.reshape(-1, 1)
        
        # For ensemble, we'll use the variance of predictions as uncertainty
        # This is a simple approach - in practice you'd have multiple model predictions
        self.calibration_params = {
            'method': 'ensemble',
            'fitted': True
        }
        
        log.info("Fitted ensemble-based uncertainty estimator")
    
    def calibrate(self, y_pred_proba: np.ndarray) -> np.ndarray:
        """
        Calibrate predicted probabilities.
        
        Args:
            y_pred_proba: Raw predicted probabilities
            
        Returns:
            Calibrated probabilities
        """
        if not self.is_fitted:
            raise ValueError("Calibrator must be fitted before use")
        
        if self.method == "platt":
            return self._calibrate_platt(y_pred_proba)
        elif self.method == "isotonic":
            return self._calibrate_isotonic(y_pred_proba)
        elif self.method == "temperature":
            return self._calibrate_temperature(y_pred_proba)
        elif self.method == "ensemble":
            return self._calibrate_ensemble(y_pred_proba)
        else:
            raise ValueError(f"Unknown calibration method: {self.method}")
    
    def _calibrate_platt(self, y_pred_proba: np.ndarray) -> np.ndarray:
        """Apply Platt scaling calibration."""
        if y_pred_proba.ndim == 1:
            y_pred_proba = y_pred_proba.reshape(-1, 1)
        
        eps = 1e-15
        y_pred_proba = np.clip(y_pred_proba, eps, 1 - eps)
        logits = np.log(y_pred_proba / (1 - y_pred_proba))
        
        # Apply calibration
        calibrated_logits = self.calibrator.coef_[0][0] * logits + self.calibrator.intercept_[0]
        calibrated_probs = 1 / (1 + np.exp(-calibrated_logits))
        
        return calibrated_probs.flatten()
    
    def _calibrate_isotonic(self, y_pred_proba: np.ndarray) -> np.ndarray:
        """Apply isotonic regression calibration."""
        if y_pred_proba.ndim == 1:
            y_pred_proba = y_pred_proba.reshape(-1, 1)
        
        probas = y_pred_proba[:, 0] if y_pred_proba.shape[1] > 1 else y_pred_proba.flatten()
        calibrated_probs = self.calibrator.predict(probas)
        
        return calibrated_probs
    
    def _calibrate_temperature(self, y_pred_proba: np.ndarray) -> np.ndarray:
        """Apply temperature scaling calibration."""
        if y_pred_proba.ndim == 1:
            y_pred_proba = y_pred_proba.reshape(-1, 1)
        
        eps = 1e-15
        y_pred_proba = np.clip(y_pred_proba, eps, 1 - eps)
        logits = np.log(y_pred_proba / (1 - y_pred_proba))
        
        temp = self.calibration_params['temperature']
        calibrated_probs = self._apply_temperature(logits, temp)
        
        return calibrated_probs
    
    def _calibrate_ensemble(self, y_pred_proba: np.ndarray) -> np.ndarray:
        """Apply ensemble-based calibration."""
        # For now, return original probabilities
        # In practice, this would use multiple model predictions
        return y_pred_proba.flatten()
    
    def _apply_temperature(self, logits: np.ndarray, temperature: float) -> np.ndarray:
        """Apply temperature scaling to logits."""
        scaled_logits = logits / temperature
        exp_logits = np.exp(scaled_logits)
        return exp_logits / (1 + exp_logits)
    
    def estimate_uncertainty(self, y_pred_proba: np.ndarray, 
                           method: str = "entropy") -> np.ndarray:
        """
        Estimate prediction uncertainty.
        
        Args:
            y_pred_proba: Predicted probabilities
            method: Uncertainty estimation method ("entropy", "variance", "confidence")
            
        Returns:
            Uncertainty scores (higher = more uncertain)
        """
        if method == "entropy":
            return self._entropy_uncertainty(y_pred_proba)
        elif method == "variance":
            return self._variance_uncertainty(y_pred_proba)
        elif method == "confidence":
            return self._confidence_uncertainty(y_pred_proba)
        else:
            raise ValueError(f"Unknown uncertainty method: {method}")
    
    def _entropy_uncertainty(self, y_pred_proba: np.ndarray) -> np.ndarray:
        """Calculate entropy-based uncertainty."""
        eps = 1e-15
        y_pred_proba = np.clip(y_pred_proba, eps, 1 - eps)
        
        # Binary case: entropy = -p*log(p) - (1-p)*log(1-p)
        if y_pred_proba.ndim == 1:
            p = y_pred_proba
            entropy = -p * np.log(p) - (1 - p) * np.log(1 - p)
        else:
            # Multi-class case
            entropy = -np.sum(y_pred_proba * np.log(y_pred_proba + eps), axis=1)
        
        return entropy
    
    def _variance_uncertainty(self, y_pred_proba: np.ndarray) -> np.ndarray:
        """Calculate variance-based uncertainty."""
        if y_pred_proba.ndim == 1:
            # For binary, variance = p * (1 - p)
            p = y_pred_proba
            variance = p * (1 - p)
        else:
            # For multi-class, variance = sum(p * (1 - p))
            variance = np.sum(y_pred_proba * (1 - y_pred_proba), axis=1)
        
        return variance
    
    def _confidence_uncertainty(self, y_pred_proba: np.ndarray) -> np.ndarray:
        """Calculate confidence-based uncertainty (1 - max probability)."""
        if y_pred_proba.ndim == 1:
            # For binary, confidence = 1 - max(p, 1-p)
            p = y_pred_proba
            confidence = 1 - np.maximum(p, 1 - p)
        else:
            # For multi-class, confidence = 1 - max(p)
            confidence = 1 - np.max(y_pred_proba, axis=1)
        
        return confidence
    
    def evaluate_calibration(self, y_true: np.ndarray, y_pred_proba: np.ndarray) -> Dict[str, float]:
        """
        Evaluate calibration quality.
        
        Args:
            y_true: True labels
            y_pred_proba: Predicted probabilities
            
        Returns:
            Dictionary of calibration metrics
        """
        if y_pred_proba.ndim == 1:
            y_pred_proba = y_pred_proba.reshape(-1, 1)
        
        # Brier score (lower is better)
        brier = brier_score_loss(y_true, y_pred_proba[:, 0])
        
        # Calibration curve
        fraction_of_positives, mean_predicted_value = calibration_curve(
            y_true, y_pred_proba[:, 0], n_bins=10
        )
        
        # ECE (Expected Calibration Error)
        ece = self._calculate_ece(y_true, y_pred_proba[:, 0])
        
        # Reliability diagram statistics
        reliability_stats = self._calculate_reliability_stats(y_true, y_pred_proba[:, 0])
        
        return {
            'brier_score': brier,
            'ece': ece,
            'reliability_stats': reliability_stats,
            'calibration_curve': {
                'fraction_of_positives': fraction_of_positives.tolist(),
                'mean_predicted_value': mean_predicted_value.tolist()
            }
        }
    
    def _calculate_ece(self, y_true: np.ndarray, y_pred_proba: np.ndarray, 
                      n_bins: int = 10) -> float:
        """Calculate Expected Calibration Error."""
        bin_boundaries = np.linspace(0, 1, n_bins + 1)
        bin_lowers = bin_boundaries[:-1]
        bin_uppers = bin_boundaries[1:]
        
        ece = 0.0
        for bin_lower, bin_upper in zip(bin_lowers, bin_uppers):
            # Find predictions in this bin
            in_bin = (y_pred_proba > bin_lower) & (y_pred_proba <= bin_upper)
            bin_size = np.sum(in_bin)
            
            if bin_size > 0:
                bin_accuracy = np.sum(y_true[in_bin]) / bin_size
                bin_confidence = np.mean(y_pred_proba[in_bin])
                ece += bin_size * np.abs(bin_accuracy - bin_confidence)
        
        return ece / len(y_true)
    
    def _calculate_reliability_stats(self, y_true: np.ndarray, y_pred_proba: np.ndarray) -> Dict[str, float]:
        """Calculate reliability diagram statistics."""
        # Group predictions into bins and calculate empirical vs predicted probabilities
        n_bins = 10
        bin_boundaries = np.linspace(0, 1, n_bins + 1)
        
        empirical_probs = []
        predicted_probs = []
        bin_counts = []
        
        for i in range(n_bins):
            bin_lower = bin_boundaries[i]
            bin_upper = bin_boundaries[i + 1]
            
            in_bin = (y_pred_proba > bin_lower) & (y_pred_proba <= bin_upper)
            bin_size = np.sum(in_bin)
            
            if bin_size > 0:
                bin_accuracy = np.sum(y_true[in_bin]) / bin_size
                bin_confidence = np.mean(y_pred_proba[in_bin])
                
                empirical_probs.append(bin_accuracy)
                predicted_probs.append(bin_confidence)
                bin_counts.append(bin_size)
        
        if empirical_probs:
            # Calculate correlation between empirical and predicted probabilities
            correlation = np.corrcoef(empirical_probs, predicted_probs)[0, 1]
            
            # Calculate mean absolute difference
            mean_diff = np.mean(np.abs(np.array(empirical_probs) - np.array(predicted_probs)))
            
            return {
                'correlation': correlation if not np.isnan(correlation) else 0.0,
                'mean_absolute_difference': mean_diff,
                'n_bins': len(empirical_probs)
            }
        else:
            return {
                'correlation': 0.0,
                'mean_absolute_difference': 0.0,
                'n_bins': 0
            }
    
    def plot_calibration(self, y_true: np.ndarray, y_pred_proba: np.ndarray, 
                        save_path: Optional[str] = None) -> None:
        """
        Plot calibration curve and reliability diagram.
        
        Args:
            y_true: True labels
            y_pred_proba: Predicted probabilities
            save_path: Optional path to save the plot
        """
        try:
            import matplotlib.pyplot as plt
        except ImportError:
            log.warning("Matplotlib not available, skipping calibration plot")
            return
        
        if y_pred_proba.ndim == 1:
            y_pred_proba = y_pred_proba.reshape(-1, 1)
        
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
        
        # Calibration curve
        fraction_of_positives, mean_predicted_value = calibration_curve(
            y_true, y_pred_proba[:, 0], n_bins=10
        )
        
        ax1.plot(mean_predicted_value, fraction_of_positives, "s-", label="Calibrated")
        ax1.plot([0, 1], [0, 1], "k--", label="Perfectly calibrated")
        ax1.set_xlabel("Mean predicted probability")
        ax1.set_ylabel("Fraction of positives")
        ax1.set_title("Calibration Curve")
        ax1.legend()
        ax1.grid(True)
        
        # Reliability diagram
        n_bins = 10
        bin_boundaries = np.linspace(0, 1, n_bins + 1)
        bin_centers = (bin_boundaries[:-1] + bin_boundaries[1:]) / 2
        
        empirical_probs = []
        for i in range(n_bins):
            bin_lower = bin_boundaries[i]
            bin_upper = bin_boundaries[i + 1]
            
            in_bin = (y_pred_proba[:, 0] > bin_lower) & (y_pred_proba[:, 0] <= bin_upper)
            bin_size = np.sum(in_bin)
            
            if bin_size > 0:
                bin_accuracy = np.sum(y_true[in_bin]) / bin_size
                empirical_probs.append(bin_accuracy)
            else:
                empirical_probs.append(0)
        
        ax2.bar(bin_centers, empirical_probs, width=0.1, alpha=0.7, label="Empirical")
        ax2.plot([0, 1], [0, 1], "k--", label="Perfect calibration")
        ax2.set_xlabel("Predicted probability")
        ax2.set_ylabel("Empirical probability")
        ax2.set_title("Reliability Diagram")
        ax2.legend()
        ax2.grid(True)
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            log.info(f"Calibration plot saved to {save_path}")
        
        plt.show()
