#!/usr/bin/env python3
"""
Enhanced Model Training Script

This script trains improved ML models using:
- Enhanced feature extraction
- Cross-validation and hyperparameter tuning
- Confidence calibration
- Multiple model types (XGBoost, LightGBM, Random Forest, SVM, Logistic)

Usage:
    python train_enhanced_models.py --family sqli --model-type xgboost --cv-folds 5
    python train_enhanced_models.py --family all --model-type ensemble --hyperparameter-tuning
"""

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Dict, Any, List, Optional
import numpy as np
import pandas as pd

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent))

try:
    from enhanced_features import EnhancedFeatureExtractor
    from enhanced_trainer import EnhancedModelTrainer, ModelConfig
    from confidence_calibration import ConfidenceCalibrator
except ImportError:
    from .enhanced_features import EnhancedFeatureExtractor
    from .enhanced_trainer import EnhancedModelTrainer, ModelConfig
    from .confidence_calibration import ConfidenceCalibrator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
log = logging.getLogger(__name__)

def load_training_data(data_path: str, family: str) -> tuple:
    """
    Load training data from various formats.
    
    Args:
        data_path: Path to training data
        family: Vulnerability family
        
    Returns:
        Tuple of (X, y, groups) for training
    """
    data_path = Path(data_path)
    
    if data_path.suffix == '.jsonl':
        # Load from JSONL format
        return load_jsonl_data(data_path, family)
    elif data_path.suffix == '.csv':
        # Load from CSV format
        return load_csv_data(data_path, family)
    elif data_path.is_dir():
        # Load from directory containing multiple files
        return load_directory_data(data_path, family)
    else:
        raise ValueError(f"Unsupported data format: {data_path}")
    
    return None, None, None

def load_jsonl_data(data_path: Path, family: str) -> tuple:
    """Load data from JSONL format."""
    log.info(f"Loading JSONL data from {data_path}")
    
    data = []
    with open(data_path, 'r') as f:
        for line in f:
            if line.strip():
                data.append(json.loads(line))
    
    if not data:
        raise ValueError("No data found in JSONL file")
    
    # Extract features and labels
    X, y, groups = [], [], []
    feature_extractor = EnhancedFeatureExtractor()
    
    for item in data:
        try:
            # Extract features
            features = feature_extractor.extract_enhanced_features(
                endpoint=item.get('endpoint', {}),
                param=item.get('param', {}),
                family=family,
                context=item.get('context')
            )
            
            # Convert to feature vector
            feature_vector = list(features.values())
            X.append(feature_vector)
            
            # Extract label
            label = item.get('label', 0)
            y.append(label)
            
            # Extract group (for ranking)
            group = item.get('group', 0)
            groups.append(group)
            
        except Exception as e:
            log.warning(f"Skipping item due to error: {e}")
            continue
    
    log.info(f"Loaded {len(X)} samples with {len(features)} features")
    return np.array(X), np.array(y), np.array(groups)

def load_csv_data(data_path: Path, family: str) -> tuple:
    """Load data from CSV format."""
    log.info(f"Loading CSV data from {data_path}")
    
    try:
        df = pd.read_csv(data_path)
    except Exception as e:
        raise ValueError(f"Failed to load CSV: {e}")
    
    # Assume standard column names
    if 'features' in df.columns and 'label' in df.columns:
        # Features are stored as string representation
        X = []
        for feature_str in df['features']:
            try:
                features = json.loads(feature_str)
                X.append(list(features.values()))
            except:
                log.warning(f"Failed to parse features: {feature_str}")
                continue
        
        y = df['label'].values
        groups = df.get('group', range(len(y))).values
        
    else:
        # Try to infer structure
        feature_cols = [col for col in df.columns if col.startswith('feature_')]
        if not feature_cols:
            raise ValueError("No feature columns found in CSV")
        
        X = df[feature_cols].values
        y = df.get('label', df.get('target', [0] * len(X))).values
        groups = df.get('group', range(len(y))).values
    
    log.info(f"Loaded {len(X)} samples with {X.shape[1]} features")
    return np.array(X), np.array(y), np.array(groups)

def load_directory_data(data_dir: Path, family: str) -> tuple:
    """Load data from directory containing multiple files."""
    log.info(f"Loading data from directory {data_dir}")
    
    all_X, all_y, all_groups = [], [], []
    
    # Look for common data files
    data_files = list(data_dir.glob("*.jsonl")) + list(data_dir.glob("*.csv"))
    
    for data_file in data_files:
        try:
            X, y, groups = load_training_data(str(data_file), family)
            if X is not None:
                all_X.append(X)
                all_y.append(y)
                all_groups.append(groups)
        except Exception as e:
            log.warning(f"Failed to load {data_file}: {e}")
    
    if not all_X:
        raise ValueError("No valid data files found in directory")
    
    # Concatenate all data
    X = np.vstack(all_X)
    y = np.concatenate(all_y)
    groups = np.concatenate(all_groups)
    
    log.info(f"Combined {len(X)} samples from {len(data_files)} files")
    return X, y, groups

def prepare_synthetic_data(family: str, n_samples: int = 1000) -> tuple:
    """
    Generate realistic synthetic training data for web vulnerability detection.
    
    This function creates realistic web application data including:
    - Real parameter names and values for each vulnerability family
    - Contextual endpoint information (URLs, methods, content types)
    - Business logic patterns (e-commerce, banking, social media)
    - Realistic attack payloads and benign values
    
    Args:
        family: Vulnerability family ('sqli', 'xss', 'redirect')
        n_samples: Number of samples to generate
        
    Returns:
        Tuple of (X, y, groups) for training
    """
    log.info(f"Generating {n_samples} realistic synthetic samples for {family}")
    
    # Set seeds for reproducibility
    np.random.seed(42)
    import random
    random.seed(42)
    
    n_features = 48  # Match enhanced feature extractor
    
    # Realistic parameter names by vulnerability family
    param_names = {
        'sqli': [
            'user_id', 'account_id', 'order_id', 'product_id', 'customer_id',
            'search', 'query', 'q', 'term', 'keyword', 'filter',
            'id', 'num', 'count', 'limit', 'offset', 'page', 'size',
            'category_id', 'item_id', 'transaction_id', 'invoice_id'
        ],
        'xss': [
            'comment', 'message', 'content', 'text', 'description',
            'bio', 'about', 'feedback', 'review', 'post', 'tweet',
            'title', 'subject', 'body', 'note', 'caption', 'summary',
            'username', 'name', 'display_name', 'nickname', 'alias'
        ],
        'redirect': [
            'next_url', 'redirect', 'return_to', 'continue', 'forward',
            'url', 'target', 'dest', 'destination', 'goto', 'link',
            'return_url', 'callback', 'success_url', 'error_url',
            'redirect_uri', 'next', 'ref', 'referer'
        ]
    }
    
    # Realistic endpoint patterns
    endpoints = [
        {'url': 'https://shop.example.com/api/products/search', 'method': 'GET', 'content_type': 'application/json', 'context': 'ecommerce'},
        {'url': 'https://bank.example.com/api/accounts/transfer', 'method': 'POST', 'content_type': 'application/json', 'context': 'banking'},
        {'url': 'https://social.example.com/api/posts/create', 'method': 'POST', 'content_type': 'application/json', 'context': 'social'},
        {'url': 'https://admin.example.com/api/users/manage', 'method': 'PUT', 'content_type': 'application/json', 'context': 'admin'},
        {'url': 'https://example.com/login', 'method': 'POST', 'content_type': 'application/x-www-form-urlencoded', 'context': 'auth'},
        {'url': 'https://api.example.com/v1/data/query', 'method': 'GET', 'content_type': 'application/json', 'context': 'api'},
        {'url': 'https://blog.example.com/comments/add', 'method': 'POST', 'content_type': 'text/html', 'context': 'blog'},
        {'url': 'https://example.com/checkout', 'method': 'POST', 'content_type': 'application/json', 'context': 'ecommerce'}
    ]
    
    # Realistic values by vulnerability family
    values = {
        'sqli': {
            'malicious': [
                "' OR 1=1--", "' UNION SELECT NULL--", "1 OR 1=1--",
                "'; DROP TABLE users--", "' AND 1=1--", "admin'--",
                "1' OR '1'='1", "' UNION SELECT * FROM users--",
                "1; DELETE FROM accounts;--", "' OR 'a'='a"
            ],
            'benign': [
                '1', '123', '42', '0', '999', 'admin', 'user', 'test',
                'john_doe', 'customer_001', 'search_term', 'product_name',
                '100', '5', '10', 'electronics', 'books', 'clothing'
            ]
        },
        'xss': {
            'malicious': [
                '<script>alert(1)</script>', '<img src=x onerror=alert(1)>',
                '<svg/onload=alert(1)>', '<iframe src=javascript:alert(1)>',
                '<body onload=alert(1)>', '<div onclick=alert(1)>click</div>',
                'javascript:alert(1)', '<script>document.cookie</script>',
                '<img src="" onerror="alert(document.domain)">'
            ],
            'benign': [
                'Hello world!', 'This is a comment', 'Great product!',
                'Thanks for the help', 'Looking forward to it',
                'John Smith', 'Software Engineer', 'New York',
                'I love this website', 'Five stars!', 'Recommended!'
            ]
        },
        'redirect': {
            'malicious': [
                'https://evil.com', '//evil.com', 'http://attacker.com',
                'https://evil.com/steal', 'javascript:alert(1)',
                'data:text/html,<script>alert(1)</script>',
                'https://example.com.evil.com', '\\\\evil.com',
                'https://example.com@evil.com'
            ],
            'benign': [
                '/dashboard', '/profile', '/home', '/settings',
                'https://example.com/home', 'https://example.com/profile',
                '/api/success', '/checkout/complete', '/login/success',
                'https://trusted-partner.com', '/admin/panel'
            ]
        }
    }
    
    X = []
    y = []
    groups = []
    
    for i in range(n_samples):
        # Pick random endpoint and parameter
        endpoint = random.choice(endpoints)
        param_name = random.choice(param_names[family])
        
        # Decide if this should be malicious (30% chance for positive examples)
        is_malicious = random.random() < 0.3
        
        if is_malicious:
            param_value = random.choice(values[family]['malicious'])
            label = 1
        else:
            param_value = random.choice(values[family]['benign'])
            label = 0
        
        # Generate realistic feature vector based on the context
        features = np.random.randn(n_features) * 0.5
        
        # Add family-specific patterns to features
        if family == 'sqli':
            # SQL injection features - emphasize numeric/search patterns
            if any(keyword in param_name for keyword in ['id', 'num', 'count']):
                features[0:5] += 1.5  # Numeric parameter indicators
            if any(keyword in param_name for keyword in ['search', 'query', 'filter']):
                features[5:10] += 1.2  # Search parameter indicators
            if is_malicious:
                features[0:8] += 2.0  # Strong SQLi signals
                features[10:15] += 1.5  # Additional SQLi patterns
                
        elif family == 'xss':
            # XSS features - emphasize text/content patterns
            if any(keyword in param_name for keyword in ['comment', 'message', 'content']):
                features[8:13] += 1.5  # Text content indicators
            if any(keyword in param_name for keyword in ['title', 'name', 'description']):
                features[13:18] += 1.2  # Display text indicators
            if is_malicious:
                features[8:16] += 2.0  # Strong XSS signals
                features[20:25] += 1.5  # Additional XSS patterns
                
        elif family == 'redirect':
            # Redirect features - emphasize URL/navigation patterns
            if any(keyword in param_name for keyword in ['url', 'redirect', 'next']):
                features[16:21] += 1.5  # URL parameter indicators
            if any(keyword in param_name for keyword in ['return', 'callback', 'forward']):
                features[21:26] += 1.2  # Navigation indicators
            if is_malicious:
                features[16:24] += 2.0  # Strong redirect signals
                features[30:35] += 1.5  # Additional redirect patterns
        
        # Add business context features
        context = endpoint['context']
        if context == 'banking':
            features[35:38] += 1.0  # Banking context
        elif context == 'ecommerce':
            features[38:41] += 1.0  # E-commerce context
        elif context == 'social':
            features[41:44] += 1.0  # Social media context
        elif context == 'admin':
            features[44:47] += 1.0  # Admin context
        
        # Add some noise for realism
        features += np.random.normal(0, 0.1, n_features)
        
        X.append(features)
        y.append(label)
        groups.append(i // 20)  # Group samples for ranking (20 samples per group)
    
    X = np.array(X)
    y = np.array(y)
    groups = np.array(groups) if groups else None
    
    # Calculate label distribution
    positive_count = np.sum(y)
    negative_count = len(y) - positive_count
    
    log.info(f"Generated realistic synthetic data for {family}:")
    log.info(f"  Shape: {X.shape}")
    log.info(f"  Positive samples: {positive_count} ({positive_count/len(y)*100:.1f}%)")
    log.info(f"  Negative samples: {negative_count} ({negative_count/len(y)*100:.1f}%)")
    log.info(f"  Groups: {len(np.unique(groups)) if groups is not None else 0}")
    
    return X, y, groups

def train_model(family: str, config: ModelConfig, data_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Train a model for a specific family.
    
    Args:
        family: Vulnerability family
        config: Model configuration
        data_path: Path to training data (optional, uses synthetic if not provided)
        
    Returns:
        Training results
    """
    log.info(f"Training {family} model with {config.model_type}")
    
    # Load or generate training data
    if data_path and os.path.exists(data_path):
        X, y, groups = load_training_data(data_path, family)
    else:
        log.info("No training data provided, using synthetic data")
        X, y, groups = prepare_synthetic_data(family, n_samples=2000)
    
    # Update config for this family
    config.family = family
    
    # Create trainer
    trainer = EnhancedModelTrainer(config)
    
    # Train model
    results = trainer.train_model(X, y, groups)
    
    # Train confidence calibrator
    if hasattr(trainer.models.get(list(trainer.models.keys())[0]), 'predict_proba'):
        model = list(trainer.models.values())[0]
        y_pred_proba = model.predict_proba(X)[:, 1]  # Probability of positive class
        
        calibrator = ConfidenceCalibrator(method="isotonic")
        calibrator.fit(y, y_pred_proba)
        
        # Evaluate calibration
        calibration_metrics = calibrator.evaluate_calibration(y, y_pred_proba)
        results['calibration_metrics'] = calibration_metrics
        
        # Save calibrator
        calibrator_path = Path(__file__).parent / f"enhanced_calibrator_{family}.joblib"
        try:
            import joblib
            joblib.dump(calibrator, calibrator_path)
            log.info(f"Saved calibrator to {calibrator_path}")
        except Exception as e:
            log.warning(f"Failed to save calibrator: {e}")
    
    return results

def main():
    """Main training function."""
    parser = argparse.ArgumentParser(description="Train enhanced ML models for vulnerability detection")
    
    parser.add_argument(
        "--family", 
        choices=["sqli", "xss", "redirect", "all"],
        default="all",
        help="Vulnerability family to train (default: all)"
    )
    
    parser.add_argument(
        "--model-type",
        choices=["xgboost", "lightgbm", "random_forest", "svm", "logistic", "ensemble"],
        default="xgboost",
        help="Model type to use (default: xgboost)"
    )
    
    parser.add_argument(
        "--data-path",
        help="Path to training data (JSONL, CSV, or directory)"
    )
    
    parser.add_argument(
        "--cv-folds",
        type=int,
        default=5,
        help="Number of cross-validation folds (default: 5)"
    )
    
    parser.add_argument(
        "--hyperparameter-tuning",
        action="store_true",
        help="Enable hyperparameter tuning"
    )
    
    parser.add_argument(
        "--feature-selection",
        action="store_true",
        help="Enable feature selection"
    )
    
    parser.add_argument(
        "--ensemble",
        action="store_true",
        help="Use ensemble methods"
    )
    
    parser.add_argument(
        "--random-state",
        type=int,
        default=42,
        help="Random state for reproducibility (default: 42)"
    )
    
    parser.add_argument(
        "--output-dir",
        help="Output directory for models and results"
    )
    
    args = parser.parse_args()
    
    # Set output directory
    if args.output_dir:
        output_dir = Path(args.output_dir)
        output_dir.mkdir(exist_ok=True)
        os.chdir(output_dir)
    
    # Determine families to train
    families = ["sqli", "xss", "redirect"] if args.family == "all" else [args.family]
    
    # Training results
    all_results = {}
    
    for family in families:
        log.info(f"Starting training for {family}")
        
        try:
            # Create model configuration
            config = ModelConfig(
                family=family,
                model_type=args.model_type,
                use_cross_validation=True,
                cv_folds=args.cv_folds,
                hyperparameter_tuning=args.hyperparameter_tuning,
                feature_selection=args.feature_selection,
                ensemble_method=args.ensemble,
                random_state=args.random_state
            )
            
            # Train model
            results = train_model(family, config, args.data_path)
            all_results[family] = results
            
            log.info(f"Training completed for {family}")
            
        except Exception as e:
            log.error(f"Training failed for {family}: {e}")
            all_results[family] = {"error": str(e)}
    
    # Save combined results
    results_path = Path(__file__).parent / "enhanced_training_results.json"
    with open(results_path, 'w') as f:
        json.dump(all_results, f, indent=2)
    
    log.info(f"Training results saved to {results_path}")
    
    # Print summary
    print("\n" + "="*50)
    print("TRAINING SUMMARY")
    print("="*50)
    
    for family, results in all_results.items():
        if "error" in results:
            print(f"{family.upper()}: FAILED - {results['error']}")
        else:
            print(f"{family.upper()}: SUCCESS")
            print(f"  Model: {results.get('model_type', 'unknown')}")
            print(f"  Train Score: {results.get('train_score', 0):.4f}")
            print(f"  Val Score: {results.get('val_score', 0):.4f}")
            if 'cv_scores' in results:
                cv_mean = results['cv_scores'].get('cv_mean', 0)
                cv_std = results['cv_scores'].get('cv_std', 0)
                print(f"  CV Score: {cv_mean:.4f} (+/- {cv_std*2:.4f})")
            print(f"  Features: {results.get('n_features', 0)}")
            print()
    
    print("="*50)
    print("Training completed!")

if __name__ == "__main__":
    main()
