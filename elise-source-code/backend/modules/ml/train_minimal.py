#!/usr/bin/env python3
"""
Minimal Training + Calibration CLI for ML Models

This module provides a minimal training pipeline that generates synthetic data
and trains binary classifiers for XSS, SQLi, and Redirect vulnerabilities.
"""

import os
import json
import logging
import random
import numpy as np
from pathlib import Path
from typing import Dict, List, Tuple, Any
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import classification_report, log_loss
import joblib

# Import the feature schema
from .enhanced_features import EnhancedFeaturesV1, build_features_for_target
from ..targets import Target

logger = logging.getLogger(__name__)

class MinimalTrainer:
    """Minimal trainer for binary vulnerability classifiers"""
    
    def __init__(self, models_dir: str = "backend/modules/ml/models"):
        self.models_dir = Path(models_dir)
        self.models_dir.mkdir(parents=True, exist_ok=True)
        self.families = ["xss", "sqli", "redirect"]
        
    def generate_synthetic_data(self, n_samples: int = 1000) -> Tuple[np.ndarray, Dict[str, np.ndarray]]:
        """
        Generate synthetic training data using the same feature schema.
        
        Args:
            n_samples: Number of samples to generate per family
            
        Returns:
            Tuple of (features_matrix, labels_dict)
        """
        logger.info(f"Generating {n_samples} samples per family...")
        
        all_features = []
        labels = {family: [] for family in self.families}
        
        for family in self.families:
            logger.info(f"Generating {family} samples...")
            
            for i in range(n_samples):
                # Generate synthetic target
                target = self._generate_synthetic_target(family, i)
                
                # Build features using the same schema
                features = build_features_for_target(target)
                
                # Convert to numpy array (excluding schema_version)
                feature_dict = {k: v for k, v in features.items() if k != "_schema_version"}
                feature_vector = np.array(list(feature_dict.values()), dtype=np.float32)
                
                all_features.append(feature_vector)
                
                # Create binary labels for this family
                for fam in self.families:
                    labels[fam].append(1 if fam == family else 0)
        
        # Convert to numpy arrays
        X = np.array(all_features)
        for family in self.families:
            labels[family] = np.array(labels[family])
            
        logger.info(f"Generated {X.shape[0]} samples with {X.shape[1]} features")
        return X, labels
    
    def _generate_synthetic_target(self, family: str, sample_id: int) -> Target:
        """Generate a synthetic target for training"""
        
        # Base URL patterns by family
        url_patterns = {
            "xss": [
                "http://example.com/search?q={param}",
                "http://example.com/find?term={param}",
                "http://example.com/api/search?query={param}",
            ],
            "sqli": [
                "http://example.com/login?email={param}",
                "http://example.com/products?id={param}",
                "http://example.com/api/users?userId={param}",
            ],
            "redirect": [
                "http://example.com/redirect?url={param}",
                "http://example.com/callback?return_url={param}",
                "http://example.com/go?target={param}",
            ]
        }
        
        # Parameter patterns by family
        param_patterns = {
            "xss": ["q", "query", "term", "search", "find"],
            "sqli": ["id", "email", "userId", "productId", "username"],
            "redirect": ["url", "return_url", "target", "redirect", "callback"]
        }
        
        # Method patterns by family
        method_patterns = {
            "xss": ["GET"],
            "sqli": ["GET", "POST"],
            "redirect": ["GET"]
        }
        
        # Select random patterns
        url_template = random.choice(url_patterns[family])
        param_name = random.choice(param_patterns[family])
        method = random.choice(method_patterns[family])
        
        # Generate URL
        url = url_template.format(param=f"test_{sample_id}")
        
        # Extract path from URL
        from urllib.parse import urlparse
        parsed_url = urlparse(url)
        path = parsed_url.path or "/"
        
        # Create target
        target = Target(
            url=url,
            path=path,
            method=method,
            param=param_name,
            param_in="query" if method == "GET" else "form",
            status=200,
            provenance_ids=[1]  # Synthetic provenance ID
        )
        
        return target
    
    def train_family_classifier(self, X: np.ndarray, y: np.ndarray, family: str) -> Tuple[Any, Dict[str, Any]]:
        """
        Train a binary classifier for a specific family.
        
        Args:
            X: Feature matrix
            y: Binary labels for this family
            family: Family name (xss, sqli, redirect)
            
        Returns:
            Tuple of (trained_model, calibration_info)
        """
        logger.info(f"Training {family} classifier...")
        
        # Split data
        X_train, X_val, y_train, y_val = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Train base classifier (Logistic Regression for simplicity)
        base_clf = LogisticRegression(
            random_state=42,
            max_iter=1000,
            class_weight='balanced'
        )
        
        # Train with calibration
        calibrated_clf = CalibratedClassifierCV(
            base_clf, 
            method='isotonic', 
            cv=3
        )
        
        calibrated_clf.fit(X_train, y_train)
        
        # Evaluate
        y_pred = calibrated_clf.predict(X_val)
        y_prob = calibrated_clf.predict_proba(X_val)[:, 1]
        
        # Calculate metrics
        val_loss = log_loss(y_val, y_prob)
        
        logger.info(f"{family} classifier trained:")
        logger.info(f"  Validation log loss: {val_loss:.4f}")
        logger.info(f"  Validation accuracy: {(y_pred == y_val).mean():.4f}")
        
        # Print classification report
        report = classification_report(y_val, y_pred, output_dict=True)
        logger.info(f"  Precision: {report['1']['precision']:.4f}")
        logger.info(f"  Recall: {report['1']['recall']:.4f}")
        logger.info(f"  F1-score: {report['1']['f1-score']:.4f}")
        
        # Prepare calibration info
        calibration_info = {
            "family": family,
            "validation_log_loss": val_loss,
            "validation_accuracy": (y_pred == y_val).mean(),
            "precision": report['1']['precision'],
            "recall": report['1']['recall'],
            "f1_score": report['1']['f1-score'],
            "support": report['1']['support'],
            "n_samples": len(X),
            "n_features": X.shape[1]
        }
        
        return calibrated_clf, calibration_info
    
    def save_model(self, model: Any, family: str, calibration_info: Dict[str, Any]):
        """Save model and calibration info to disk"""
        
        # Save model
        model_path = self.models_dir / f"family_{family}.joblib"
        joblib.dump(model, model_path)
        logger.info(f"Saved {family} model to {model_path}")
        
        # Save calibration info
        cal_path = self.models_dir / f"family_{family}.cal.json"
        with open(cal_path, 'w') as f:
            json.dump(calibration_info, f, indent=2)
        logger.info(f"Saved {family} calibration info to {cal_path}")
    
    def train_all_models(self, n_samples: int = 1000):
        """Train all family classifiers"""
        
        logger.info("Starting minimal training pipeline...")
        
        # Generate synthetic data
        X, labels = self.generate_synthetic_data(n_samples)
        
        # Train each family classifier
        for family in self.families:
            logger.info(f"\n{'='*50}")
            logger.info(f"Training {family.upper()} classifier")
            logger.info(f"{'='*50}")
            
            # Train classifier
            model, calibration_info = self.train_family_classifier(
                X, labels[family], family
            )
            
            # Save model and calibration info
            self.save_model(model, family, calibration_info)
        
        logger.info(f"\n{'='*50}")
        logger.info("Training completed successfully!")
        logger.info(f"{'='*50}")
        
        # Print summary
        for family in self.families:
            cal_path = self.models_dir / f"family_{family}.cal.json"
            if cal_path.exists():
                with open(cal_path, 'r') as f:
                    cal_info = json.load(f)
                logger.info(f"{family.upper()}: F1={cal_info['f1_score']:.3f}, "
                          f"Loss={cal_info['validation_log_loss']:.3f}")


def main():
    """Main CLI entry point"""
    
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create trainer
    trainer = MinimalTrainer()
    
    # Train all models
    trainer.train_all_models(n_samples=1000)
    
    print("\n✅ Training completed! Models saved to backend/modules/ml/models/")
    print("📊 Check /api/healthz to verify ml_ready=true")
    print("🧪 Test /api/ml-predict to verify calibrated predictions")


if __name__ == "__main__":
    main()
