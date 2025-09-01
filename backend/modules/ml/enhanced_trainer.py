# backend/modules/ml/enhanced_trainer.py
from __future__ import annotations

import json
import logging
import os
import random
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional
from dataclasses import dataclass
from collections import defaultdict

import numpy as np
import pandas as pd
from sklearn.model_selection import (
    StratifiedKFold, 
    GridSearchCV, 
    cross_val_score,
    train_test_split
)
from sklearn.metrics import (
    ndcg_score, 
    make_scorer,
    classification_report,
    confusion_matrix
)
from sklearn.preprocessing import StandardScaler, RobustScaler
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC

try:
    from xgboost import XGBRanker, XGBClassifier
    XGB_AVAILABLE = True
except ImportError:
    XGB_AVAILABLE = False
    XGBRanker = None
    XGBClassifier = None

try:
    import lightgbm as lgb
    LGB_AVAILABLE = True
except ImportError:
    LGB_AVAILABLE = False

try:
    import joblib
    JOBLIB_AVAILABLE = True
except ImportError:
    JOBLIB_AVAILABLE = False

try:
    from .enhanced_features import EnhancedFeatureExtractor
except ImportError:
    from enhanced_features import EnhancedFeatureExtractor

log = logging.getLogger(__name__)

@dataclass
class ModelConfig:
    """Configuration for model training."""
    family: str
    model_type: str = "xgboost"  # xgboost, lightgbm, random_forest, svm, logistic
    use_cross_validation: bool = True
    cv_folds: int = 5
    hyperparameter_tuning: bool = True
    feature_selection: bool = True
    ensemble_method: bool = False
    random_state: int = 42

class EnhancedModelTrainer:
    """
    Enhanced model trainer with cross-validation, hyperparameter tuning, and ensemble methods.
    """
    
    def __init__(self, config: ModelConfig):
        self.config = config
        self.feature_extractor = EnhancedFeatureExtractor()
        self.models = {}
        self.feature_importance = {}
        self.cv_scores = {}
        self.best_params = {}
        
        # Set random seeds
        random.seed(config.random_state)
        np.random.seed(config.random_state)
        
        if XGB_AVAILABLE:
            import xgboost as xgb
            xgb.set_config(verbosity=0)
    
    def train_model(self, X: np.ndarray, y: np.ndarray, 
                   groups: Optional[List[int]] = None) -> Dict[str, Any]:
        """
        Train a model with enhanced features and evaluation.
        
        Args:
            X: Feature matrix
            y: Target labels
            groups: Group labels for ranking (if applicable)
        
        Returns:
            Training results and model information
        """
        log.info(f"Training {self.config.family} model with {self.config.model_type}")
        
        # Feature preprocessing
        X_processed = self._preprocess_features(X)
        
        # Feature selection
        if self.config.feature_selection:
            X_processed, selected_features = self._select_features(X_processed, y)
            log.info(f"Selected {len(selected_features)} features out of {X.shape[1]}")
        
        # Split data
        X_train, X_val, y_train, y_val = train_test_split(
            X_processed, y, test_size=0.2, random_state=self.config.random_state,
            stratify=y if len(np.unique(y)) > 1 else None
        )
        
        # Train model
        if self.config.model_type == "xgboost" and XGB_AVAILABLE:
            # For now, always use classification (not ranking) for simplicity
            model = self._train_xgboost(X_train, y_train, None)
        elif self.config.model_type == "lightgbm" and LGB_AVAILABLE:
            # For now, always use classification (not ranking) for simplicity
            model = self._train_lightgbm(X_train, y_train, None)
        elif self.config.model_type == "random_forest":
            model = self._train_random_forest(X_train, y_train)
        elif self.config.model_type == "svm":
            model = self._train_svm(X_train, y_train)
        elif self.config.model_type == "logistic":
            model = self._train_logistic(X_train, y_train)
        else:
            raise ValueError(f"Unsupported model type: {self.config.model_type}")
        
        # Cross-validation
        if self.config.use_cross_validation:
            cv_scores = self._cross_validate(X_processed, y, groups)
            self.cv_scores = cv_scores
        
        # Evaluate model
        train_score = model.score(X_train, y_train)
        val_score = model.score(X_val, y_val)
        
        # Feature importance
        self.feature_importance = self._extract_feature_importance(model)
        
        # Save model
        self._save_model(model, X_val, y_val)
        
        results = {
            "family": self.config.family,
            "model_type": self.config.model_type,
            "train_score": train_score,
            "val_score": val_score,
            "cv_scores": self.cv_scores,
            "feature_importance": self.feature_importance,
            "best_params": self.best_params,
            "n_features": X_processed.shape[1],
            "n_samples": len(X)
        }
        
        log.info(f"Training completed. Train score: {train_score:.4f}, Val score: {val_score:.4f}")
        return results
    
    def _preprocess_features(self, X: np.ndarray) -> np.ndarray:
        """Preprocess features with scaling and normalization."""
        # Handle missing values
        X = np.nan_to_num(X, nan=0.0, posinf=1.0, neginf=-1.0)
        
        # Robust scaling for better handling of outliers
        scaler = RobustScaler()
        X_scaled = scaler.fit_transform(X)
        
        # Save scaler for inference
        self.scaler = scaler
        
        return X_scaled
    
    def _select_features(self, X: np.ndarray, y: np.ndarray) -> Tuple[np.ndarray, List[int]]:
        """Select most important features using statistical tests."""
        from sklearn.feature_selection import SelectKBest, f_classif, mutual_info_classif
        
        # Use mutual information for feature selection
        selector = SelectKBest(score_func=mutual_info_classif, k=min(100, X.shape[1]))
        X_selected = selector.fit_transform(X, y)
        
        # Get selected feature indices
        selected_features = selector.get_support(indices=True)
        
        return X_selected, selected_features.tolist()
    
    def _train_xgboost(self, X_train: np.ndarray, y_train: np.ndarray, 
                       groups: Optional[List[int]] = None) -> Any:
        """Train XGBoost model with hyperparameter tuning."""
        if groups is not None and len(groups) > 0:
            # Ranking task
            model = XGBRanker(
                objective='rank:pairwise',
                random_state=self.config.random_state,
                n_jobs=-1
            )
            
            # Hyperparameter tuning for ranking
            param_grid = {
                'n_estimators': [100, 200, 300],
                'max_depth': [3, 6, 9],
                'learning_rate': [0.01, 0.1, 0.2],
                'subsample': [0.8, 0.9, 1.0],
                'colsample_bytree': [0.8, 0.9, 1.0]
            }
        else:
            # Classification task
            model = XGBClassifier(
                objective='binary:logistic',
                random_state=self.config.random_state,
                n_jobs=-1
            )
            
            # Hyperparameter tuning for classification
            param_grid = {
                'n_estimators': [100, 200, 300],
                'max_depth': [3, 6, 9],
                'learning_rate': [0.01, 0.1, 0.2],
                'subsample': [0.8, 0.9, 1.0],
                'colsample_bytree': [0.8, 0.9, 1.0],
                'reg_alpha': [0, 0.1, 1.0],
                'reg_lambda': [0, 0.1, 1.0]
            }
        
        if self.config.hyperparameter_tuning:
            # Use cross-validation for hyperparameter tuning
            cv = StratifiedKFold(n_splits=3, shuffle=True, random_state=self.config.random_state)
            grid_search = GridSearchCV(
                model, param_grid, cv=cv, scoring='accuracy', n_jobs=-1, verbose=0
            )
            grid_search.fit(X_train, y_train)
            
            model = grid_search.best_estimator_
            self.best_params = grid_search.best_params_
            log.info(f"Best XGBoost parameters: {self.best_params}")
        else:
            # Use default parameters
            model.fit(X_train, y_train)
        
        self.models['xgboost'] = model
        return model
    
    def _train_lightgbm(self, X_train: np.ndarray, y_train: np.ndarray, 
                        groups: Optional[List[int]] = None) -> Any:
        """Train LightGBM model."""
        if not LGB_AVAILABLE:
            raise ImportError("LightGBM is not available")
        
        if groups is not None:
            # Ranking task
            model = lgb.LGBMRanker(
                objective='lambdarank',
                random_state=self.config.random_state,
                n_jobs=-1
            )
        else:
            # Classification task
            model = lgb.LGBMClassifier(
                objective='binary',
                random_state=self.config.random_state,
                n_jobs=-1
            )
        
        model.fit(X_train, y_train)
        self.models['lightgbm'] = model
        return model
    
    def _train_random_forest(self, X_train: np.ndarray, y_train: np.ndarray) -> Any:
        """Train Random Forest model."""
        param_grid = {
            'n_estimators': [100, 200, 300],
            'max_depth': [10, 20, None],
            'min_samples_split': [2, 5, 10],
            'min_samples_leaf': [1, 2, 4]
        }
        
        if self.config.hyperparameter_tuning:
            cv = StratifiedKFold(n_splits=3, shuffle=True, random_state=self.config.random_state)
            grid_search = GridSearchCV(
                RandomForestClassifier(random_state=self.config.random_state, n_jobs=-1),
                param_grid, cv=cv, scoring='accuracy', n_jobs=-1, verbose=0
            )
            grid_search.fit(X_train, y_train)
            
            model = grid_search.best_estimator_
            self.best_params = grid_search.best_params_
        else:
            model = RandomForestClassifier(
                n_estimators=200,
                max_depth=20,
                random_state=self.config.random_state,
                n_jobs=-1
            )
            model.fit(X_train, y_train)
        
        self.models['random_forest'] = model
        return model
    
    def _train_svm(self, X_train: np.ndarray, y_train: np.ndarray) -> Any:
        """Train SVM model."""
        param_grid = {
            'C': [0.1, 1, 10, 100],
            'gamma': ['scale', 'auto', 0.001, 0.01, 0.1],
            'kernel': ['rbf', 'linear']
        }
        
        if self.config.hyperparameter_tuning:
            cv = StratifiedKFold(n_splits=3, shuffle=True, random_state=self.config.random_state)
            grid_search = GridSearchCV(
                SVC(random_state=self.config.random_state),
                param_grid, cv=cv, scoring='accuracy', n_jobs=-1, verbose=0
            )
            grid_search.fit(X_train, y_train)
            
            model = grid_search.best_estimator_
            self.best_params = grid_search.best_params_
        else:
            model = SVC(C=1.0, kernel='rbf', random_state=self.config.random_state)
            model.fit(X_train, y_train)
        
        self.models['svm'] = model
        return model
    
    def _train_logistic(self, X_train: np.ndarray, y_train: np.ndarray) -> Any:
        """Train Logistic Regression model."""
        param_grid = {
            'C': [0.1, 1, 10, 100],
            'penalty': ['l1', 'l2'],
            'solver': ['liblinear', 'saga']
        }
        
        if self.config.hyperparameter_tuning:
            cv = StratifiedKFold(n_splits=3, shuffle=True, random_state=self.config.random_state)
            grid_search = GridSearchCV(
                LogisticRegression(random_state=self.config.random_state, max_iter=1000),
                param_grid, cv=cv, scoring='accuracy', n_jobs=-1, verbose=0
            )
            grid_search.fit(X_train, y_train)
            
            model = grid_search.best_estimator_
            self.best_params = grid_search.best_params_
        else:
            model = LogisticRegression(C=1.0, random_state=self.config.random_state, max_iter=1000)
            model.fit(X_train, y_train)
        
        self.models['logistic'] = model
        return model
    
    def _cross_validate(self, X: np.ndarray, y: np.ndarray, 
                        groups: Optional[List[int]] = None) -> Dict[str, Any]:
        """Perform cross-validation."""
        cv = StratifiedKFold(n_splits=self.config.cv_folds, shuffle=True, random_state=self.config.random_state)
        
        # Get the best model for cross-validation
        best_model = list(self.models.values())[0]
        
        # Cross-validation scores
        cv_scores = cross_val_score(best_model, X, y, cv=cv, scoring='accuracy', n_jobs=-1)
        
        results = {
            'cv_scores': cv_scores.tolist(),
            'cv_mean': cv_scores.mean(),
            'cv_std': cv_scores.std(),
            'cv_min': cv_scores.min(),
            'cv_max': cv_scores.max()
        }
        
        log.info(f"Cross-validation: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
        return results
    
    def _extract_feature_importance(self, model: Any) -> Dict[str, float]:
        """Extract feature importance from the model."""
        importance = {}
        
        if hasattr(model, 'feature_importances_'):
            # Tree-based models
            importance = {f"feature_{i}": float(imp) for i, imp in enumerate(model.feature_importances_)}
        elif hasattr(model, 'coef_'):
            # Linear models
            importance = {f"feature_{i}": float(abs(coef)) for i, coef in enumerate(model.coef_[0])}
        
        # Sort by importance
        importance = dict(sorted(importance.items(), key=lambda x: x[1], reverse=True))
        return importance
    
    def _save_model(self, model: Any, X_val: np.ndarray, y_val: np.ndarray):
        """Save the trained model and metadata."""
        if not JOBLIB_AVAILABLE:
            log.warning("Joblib not available, skipping model save")
            return
        
        # Create output directory
        output_dir = Path(__file__).parent
        output_dir.mkdir(exist_ok=True)
        
        # Save model
        model_path = output_dir / f"enhanced_ranker_{self.config.family}.joblib"
        joblib.dump(model, model_path)
        
        # Save scaler
        scaler_path = output_dir / f"enhanced_scaler_{self.config.family}.joblib"
        joblib.dump(self.scaler, scaler_path)
        
        # Save metadata
        metadata = {
            "family": self.config.family,
            "model_type": self.config.model_type,
            "feature_count": X_val.shape[1],
            "best_params": self.best_params,
            "feature_importance": self.feature_importance,
            "cv_scores": self.cv_scores
        }
        
        metadata_path = output_dir / f"enhanced_metadata_{self.config.family}.json"
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        log.info(f"Model saved to {model_path}")
        log.info(f"Scaler saved to {scaler_path}")
        log.info(f"Metadata saved to {metadata_path}")
    
    def ensemble_predict(self, X: np.ndarray) -> np.ndarray:
        """Make ensemble predictions using multiple models."""
        if not self.config.ensemble_method or len(self.models) < 2:
            # Use single best model
            best_model = list(self.models.values())[0]
            return best_model.predict(X)
        
        # Ensemble prediction
        predictions = []
        for model in self.models.values():
            pred = model.predict(X)
            predictions.append(pred)
        
        # Average predictions
        ensemble_pred = np.mean(predictions, axis=0)
        
        # Convert to binary for classification
        if len(np.unique(ensemble_pred)) == 2:
            ensemble_pred = (ensemble_pred > 0.5).astype(int)
        
        return ensemble_pred
