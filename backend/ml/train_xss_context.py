#!/usr/bin/env python3
"""
XSS Context ML Training Pipeline

Trains two models:
1. Context classifier: html_body, attr, js_string, url, css
2. Escaping classifier: raw, html, url, js

Uses TF-IDF character n-grams (2-5) plus binary features.
"""

import pandas as pd
import numpy as np
import json
from pathlib import Path
from typing import Dict, List, Tuple, Any
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.dummy import DummyClassifier
from sklearn.preprocessing import LabelEncoder
import joblib

from backend.app_state import DATA_DIR, MODEL_DIR

def extract_text_features(df: pd.DataFrame) -> np.ndarray:
    """Extract TF-IDF features from text windows."""
    # Combine text window with context features
    text_data = []
    for _, row in df.iterrows():
        text = row['text_window']
        # Add feature indicators to text
        if row['has_script_tag']:
            text += " SCRIPT_TAG"
        if row['has_style_tag']:
            text += " STYLE_TAG"
        if row['has_quotes']:
            text += f" QUOTES_{row['quote_type']}"
        if row['has_equals']:
            text += " EQUALS"
        if row['has_angle_brackets']:
            text += " ANGLE_BRACKETS"
        if row['has_url_attrs']:
            text += " URL_ATTRS"
        if row['has_style_attr']:
            text += " STYLE_ATTR"
        if row['attr_name_feature']:
            text += f" ATTR_{row['attr_name_feature']}"
        
        text_data.append(text)
    
    # TF-IDF with character n-grams
    vectorizer = TfidfVectorizer(
        analyzer='char',
        ngram_range=(2, 5),
        max_features=5000,
        lowercase=True,
        min_df=2,
        max_df=0.95
    )
    
    tfidf_features = vectorizer.fit_transform(text_data)
    return tfidf_features, vectorizer

def extract_binary_features(df: pd.DataFrame) -> np.ndarray:
    """Extract binary features."""
    binary_features = []
    
    for _, row in df.iterrows():
        features = [
            int(row['has_script_tag']),
            int(row['has_style_tag']),
            int(row['has_quotes']),
            int(row['has_equals']),
            int(row['has_angle_brackets']),
            int(row['has_url_attrs']),
            int(row['has_style_attr']),
            int(row['in_script_tag']),
            int(row['in_attr']),
            int(row['in_style']),
            # Quote type encoding
            1 if row['quote_type'] == 'double' else 0,
            1 if row['quote_type'] == 'single' else 0,
            # Content type indicators
            1 if 'text/html' in str(row['content_type']) else 0,
            1 if 'application/json' in str(row['content_type']) else 0,
        ]
        binary_features.append(features)
    
    return np.array(binary_features)

def train_context_model(df: pd.DataFrame) -> Tuple[Any, Any, Dict[str, Any]]:
    """Train context classification model."""
    print("Training context model...")
    
    # Extract features
    tfidf_features, vectorizer = extract_text_features(df)
    binary_features = extract_binary_features(df)
    
    # Combine features
    X = np.hstack([tfidf_features.toarray(), binary_features])
    y = df['label_context'].values
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Train model
    model = LogisticRegression(
        random_state=42,
        max_iter=1000,
        class_weight='balanced'
    )
    
    model.fit(X_train, y_train)
    
    # Evaluate
    y_pred = model.predict(X_test)
    y_pred_labels = y_pred
    y_test_labels = y_test
    
    # Cross-validation score
    cv_scores = cross_val_score(model, X, y, cv=5, scoring='f1_weighted')
    
    metrics = {
        'accuracy': model.score(X_test, y_test),
        'cv_mean': cv_scores.mean(),
        'cv_std': cv_scores.std(),
        'classification_report': classification_report(y_test_labels, y_pred_labels, output_dict=True),
        'confusion_matrix': confusion_matrix(y_test_labels, y_pred_labels).tolist(),
        'classes': sorted(list(set(y.tolist())))
    }
    
    print(f"Context model accuracy: {metrics['accuracy']:.3f}")
    print(f"Context model CV score: {metrics['cv_mean']:.3f} ± {metrics['cv_std']:.3f}")
    
    return model, vectorizer, metrics

def train_escaping_model(df: pd.DataFrame) -> Tuple[Any, Any, Dict[str, Any]]:
    """Train escaping classification model."""
    print("Training escaping model...")
    
    # Extract features
    tfidf_features, vectorizer = extract_text_features(df)
    binary_features = extract_binary_features(df)
    
    # Combine features
    X = np.hstack([tfidf_features.toarray(), binary_features])
    y = df['label_escaping'].values
    
    # Handle degenerate case: only one class present
    unique = np.unique(y)
    if len(unique) < 2:
        # Fit a constant predictor so inference has a usable model
        constant_label = unique[0]
        model = DummyClassifier(strategy='constant', constant=constant_label)
        model.fit(X, y)
        metrics = {
            'accuracy': 1.0,
            'cv_mean': 1.0,
            'cv_std': 0.0,
            'classification_report': {constant_label: {'precision': 1.0, 'recall': 1.0, 'f1-score': 1.0, 'support': int((y == constant_label).sum())}},
            'confusion_matrix': [[int((y == constant_label).sum())]],
            'classes': [constant_label]
        }
        print("Escaping dataset has a single class; using constant predictor.")
        return model, vectorizer, metrics
    
    # Encode labels
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
    )
    
    # Train model
    model = LogisticRegression(
        random_state=42,
        max_iter=1000,
        class_weight='balanced'
    )
    
    model.fit(X_train, y_train)
    
    # Evaluate
    y_pred = model.predict(X_test)
    y_pred_labels = label_encoder.inverse_transform(y_pred)
    y_test_labels = label_encoder.inverse_transform(y_test)
    
    # Cross-validation score
    cv_scores = cross_val_score(model, X, y_encoded, cv=5, scoring='f1_weighted')
    
    metrics = {
        'accuracy': model.score(X_test, y_test),
        'cv_mean': cv_scores.mean(),
        'cv_std': cv_scores.std(),
        'classification_report': classification_report(y_test_labels, y_pred_labels, output_dict=True),
        'confusion_matrix': confusion_matrix(y_test_labels, y_pred_labels).tolist(),
        'classes': label_encoder.classes_.tolist()
    }
    
    print(f"Escaping model accuracy: {metrics['accuracy']:.3f}")
    print(f"Escaping model CV score: {metrics['cv_mean']:.3f} ± {metrics['cv_std']:.3f}")
    
    return model, vectorizer, metrics

def save_models(context_model: Any, context_vectorizer: Any, context_metrics: Dict[str, Any],
                escaping_model: Any, escaping_vectorizer: Any, escaping_metrics: Dict[str, Any]) -> None:
    """Save trained models and metrics."""
    
    # Save context model
    context_model_path = MODEL_DIR / "xss_context_model.joblib"
    context_vectorizer_path = MODEL_DIR / "xss_context_vectorizer.joblib"
    context_metrics_path = MODEL_DIR / "metrics_xss_context.json"
    
    joblib.dump(context_model, context_model_path)
    joblib.dump(context_vectorizer, context_vectorizer_path)
    
    with open(context_metrics_path, 'w') as f:
        json.dump(context_metrics, f, indent=2)
    
    # Save escaping model
    escaping_model_path = MODEL_DIR / "xss_escaping_model.joblib"
    escaping_vectorizer_path = MODEL_DIR / "xss_escaping_vectorizer.joblib"
    escaping_metrics_path = MODEL_DIR / "metrics_xss_escaping.json"
    
    joblib.dump(escaping_model, escaping_model_path)
    joblib.dump(escaping_vectorizer, escaping_vectorizer_path)
    
    with open(escaping_metrics_path, 'w') as f:
        json.dump(escaping_metrics, f, indent=2)
    
    print(f"Models saved to {MODEL_DIR}")

def main():
    """Main training function."""
    # Load labeled data
    csv_path = DATA_DIR / "xss_context_labeled.csv"
    
    if not csv_path.exists():
        print(f"Labeled data not found: {csv_path}")
        print("Run xss_context_bootstrap.py first to generate labeled data")
        return
    
    print(f"Loading labeled data from {csv_path}")
    df = pd.read_csv(csv_path)
    
    if len(df) < 10:
        print(f"Not enough data for training: {len(df)} examples")
        print("Need at least 10 examples")
        return
    
    print(f"Loaded {len(df)} labeled examples")
    
    # Check data distribution
    print("\nContext distribution:")
    print(df['label_context'].value_counts())
    print("\nEscaping distribution:")
    print(df['label_escaping'].value_counts())
    
    # Train models
    context_model, context_vectorizer, context_metrics = train_context_model(df)
    escaping_model, escaping_vectorizer, escaping_metrics = train_escaping_model(df)
    
    # Save models
    save_models(
        context_model, context_vectorizer, context_metrics,
        escaping_model, escaping_vectorizer, escaping_metrics
    )
    
    print("\nTraining completed successfully!")

if __name__ == "__main__":
    main()
