# Enhanced ML System for Elise

This directory contains an enhanced machine learning system for Elise that significantly improves upon the original ML implementation with better feature engineering, confidence calibration, and uncertainty quantification.

## 🚀 Key Improvements

### 1. **Enhanced Feature Engineering**
- **Semantic Analysis**: Parameter names, business context, security patterns
- **Context Awareness**: Previous responses, parameter history, cross-parameter relationships
- **Business Logic Detection**: E-commerce, banking, social media, admin patterns
- **Security Pattern Recognition**: Authentication, authorization, data access indicators

### 2. **Advanced Model Training**
- **Cross-Validation**: Robust model evaluation with k-fold cross-validation
- **Hyperparameter Tuning**: Automated optimization using GridSearchCV
- **Feature Selection**: Mutual information-based feature selection
- **Multiple Algorithms**: XGBoost, LightGBM, Random Forest, SVM, Logistic Regression
- **Ensemble Methods**: Combine multiple models for better performance

### 3. **Confidence Calibration**
- **Platt Scaling**: Logistic regression-based calibration
- **Isotonic Regression**: Non-parametric calibration
- **Temperature Scaling**: Optimal temperature parameter optimization
- **Uncertainty Estimation**: Entropy, variance, and confidence-based uncertainty

### 4. **Enhanced Inference**
- **Confidence Scores**: Reliable probability estimates
- **Uncertainty Quantification**: Measure prediction reliability
- **Fallback Mechanisms**: Graceful degradation when models fail
- **Payload Ranking**: Context-aware payload prioritization

## 📁 File Structure

```
ml/
├── enhanced_features.py          # Enhanced feature extraction
├── enhanced_trainer.py          # Advanced model training
├── confidence_calibration.py    # Confidence calibration
├── enhanced_inference.py        # Enhanced inference engine
├── train_enhanced_models.py     # Training script
├── integration_example.py       # Integration examples
├── requirements_enhanced.txt    # Enhanced dependencies
└── README_ENHANCED_ML.md       # This file
```

## 🛠️ Installation

### 1. Install Enhanced Dependencies

```bash
cd backend
pip install -r modules/ml/requirements_enhanced.txt
```

### 2. Verify Installation

```bash
python -c "import xgboost, lightgbm, sklearn, pandas, matplotlib; print('All packages installed successfully!')"
```

## 🎯 Quick Start

### 1. Train Enhanced Models

```bash
# Train all families with XGBoost
cd backend/modules/ml
python train_enhanced_models.py --family all --model-type xgboost --hyperparameter-tuning

# Train specific family with cross-validation
python train_enhanced_models.py --family sqli --model-type lightgbm --cv-folds 5

# Use ensemble methods
python train_enhanced_models.py --family xss --model-type ensemble --feature-selection
```

### 2. Test the System

```bash
# Run integration examples
python integration_example.py
```

### 3. Use in Your Code

```python
from enhanced_inference import EnhancedInferenceEngine

# Initialize engine
engine = EnhancedInferenceEngine()

# Make prediction with confidence
result = engine.predict_with_confidence(
    endpoint={"url": "https://example.com/api", "method": "GET"},
    param={"name": "user_id", "value": "123", "loc": "query"},
    family="sqli"
)

print(f"Prediction: {result['prediction']}")
print(f"Confidence: {result['confidence']:.4f}")
print(f"Uncertainty: {result['uncertainty']:.4f}")
```

## 🔧 Configuration

### Model Configuration

```python
from enhanced_trainer import ModelConfig

config = ModelConfig(
    family="sqli",
    model_type="xgboost",
    use_cross_validation=True,
    cv_folds=5,
    hyperparameter_tuning=True,
    feature_selection=True,
    ensemble_method=False,
    random_state=42
)
```

### Feature Extraction

```python
from enhanced_features import EnhancedFeatureExtractor

extractor = EnhancedFeatureExtractor()

features = extractor.extract_enhanced_features(
    endpoint=endpoint_info,
    param=param_info,
    family="sqli",
    context=additional_context
)
```

## 📊 Model Performance

### Current Results (Baseline)
- **SQL Injection**: NDCG@3: 0.36, Hit@1: 0.46
- **XSS**: NDCG@3: 0.54, Hit@1: 0.85
- **Redirect**: NDCG@3: 1.0, Hit@1: 1.0

### Expected Improvements
- **Feature Engineering**: +15-25% performance improvement
- **Cross-Validation**: More reliable model evaluation
- **Hyperparameter Tuning**: +10-20% performance improvement
- **Confidence Calibration**: Better probability estimates
- **Ensemble Methods**: +5-15% performance improvement

## 🔄 Integration with Existing System

### 1. Replace Basic Predictions

**Before:**
```python
from .ml_ranker import predict_proba
result = predict_proba(features)
```

**After:**
```python
from .enhanced_inference import EnhancedInferenceEngine
engine = EnhancedInferenceEngine()
result = engine.predict_with_confidence(endpoint, param, family)
```

### 2. Enhanced Payload Ranking

**Before:**
```python
# Basic ranking
ranked = sorted(payloads, key=lambda x: x['score'], reverse=True)
```

**After:**
```python
# Enhanced ranking with confidence
ranked = engine.rank_payloads(endpoint, param, family, payloads, context)
```

### 3. Feature Extraction

**Before:**
```python
from .feature_extractor import FeatureExtractor
features = FeatureExtractor().extract_endpoint_features(...)
```

**After:**
```python
from .enhanced_features import EnhancedFeatureExtractor
features = EnhancedFeatureExtractor().extract_enhanced_features(...)
```

## 📈 Training Data Formats

### JSONL Format
```json
{"endpoint": {"url": "...", "method": "GET"}, "param": {"name": "id", "value": "123"}, "label": 1, "group": 0}
{"endpoint": {"url": "...", "method": "POST"}, "param": {"name": "content", "value": "test"}, "label": 0, "group": 1}
```

### CSV Format
```csv
feature_0,feature_1,feature_2,...,label,group
0.5,0.3,0.8,...,1,0
0.2,0.7,0.1,...,0,1
```

## 🎨 Advanced Features

### 1. Confidence Calibration Methods

```python
from confidence_calibration import ConfidenceCalibrator

# Platt scaling
calibrator = ConfidenceCalibrator(method="platt")
calibrator.fit(y_true, y_pred_proba)
calibrated_probs = calibrator.calibrate(y_pred_proba)

# Isotonic regression
calibrator = ConfidenceCalibrator(method="isotonic")
calibrator.fit(y_true, y_pred_proba)
calibrated_probs = calibrator.calibrate(y_pred_proba)

# Temperature scaling
calibrator = ConfidenceCalibrator(method="temperature")
calibrator.fit(y_true, y_pred_proba)
calibrated_probs = calibrator.calibrate(y_pred_proba)
```

### 2. Uncertainty Estimation

```python
# Entropy-based uncertainty
uncertainty = calibrator.estimate_uncertainty(probs, method="entropy")

# Variance-based uncertainty
uncertainty = calibrator.estimate_uncertainty(probs, method="variance")

# Confidence-based uncertainty
uncertainty = calibrator.estimate_uncertainty(probs, method="confidence")
```

### 3. Model Interpretability

```python
# Feature importance
importance = trainer.feature_importance

# Top features
top_features = engine._get_top_features(family, features)

# Calibration evaluation
metrics = calibrator.evaluate_calibration(y_true, y_pred_proba)
```

## 🚨 Troubleshooting

### Common Issues

1. **Import Errors**
   ```bash
   # Make sure you're in the right directory
   cd backend/modules/ml
   export PYTHONPATH="${PYTHONPATH}:$(pwd)/.."
   ```

2. **Missing Dependencies**
   ```bash
   # Install enhanced requirements
   pip install -r requirements_enhanced.txt
   ```

3. **Model Loading Failures**
   ```bash
   # Check if models exist
   ls -la *.joblib *.json
   
   # Train models if missing
   python train_enhanced_models.py --family all
   ```

4. **Memory Issues**
   ```bash
   # Reduce batch size or use smaller models
   python train_enhanced_models.py --family sqli --model-type logistic
   ```

### Debug Mode

```bash
# Enable debug logging
export ELISE_ML_DEBUG=1
python train_enhanced_models.py --family sqli
```

## 🔮 Future Enhancements

### Planned Features
- **Active Learning**: Human-in-the-loop model improvement
- **Online Learning**: Continuous model updates
- **Transfer Learning**: Adapt models to new applications
- **Multi-modal Features**: Image, audio, and text analysis
- **Advanced Ensembles**: Stacking and blending methods

### Research Opportunities
- **Adversarial Training**: Improve robustness against evasion
- **Federated Learning**: Privacy-preserving model training
- **Explainable AI**: Better model interpretability
- **Causal Inference**: Understand vulnerability root causes

## 📚 References

- [XGBoost Documentation](https://xgboost.readthedocs.io/)
- [LightGBM Documentation](https://lightgbm.readthedocs.io/)
- [Scikit-learn User Guide](https://scikit-learn.org/stable/user_guide.html)
- [Calibration Methods](https://scikit-learn.org/stable/modules/calibration.html)
- [Feature Selection](https://scikit-learn.org/stable/modules/feature_selection.html)

## 🤝 Contributing

1. **Fork the repository**
2. **Create a feature branch**
3. **Make your changes**
4. **Add tests**
5. **Submit a pull request**

## 📄 License

This enhanced ML system is part of the Elise project and follows the same license terms.

---

**Note**: This enhanced ML system is designed to be backward compatible with your existing codebase. You can gradually migrate from the basic ML system to the enhanced one without breaking existing functionality.
