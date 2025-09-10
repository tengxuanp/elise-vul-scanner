#!/bin/bash

# XSS Context Classifier Training Script
# Generates synthetic data and trains ML models for XSS context classification

set -e

echo "🚀 Starting XSS Context Classifier Training..."

# Set up directories
OUT_DIR="${OUT_DIR:-backend/modules/ml/models}"
DATA_DIR="${DATA_DIR:-data/xss_ctx}"

echo "📁 Output directory: $OUT_DIR"
echo "📁 Data directory: $DATA_DIR"

# Generate synthetic training data
echo "📊 Generating synthetic XSS reflection data..."
python -m backend.ml.xss_ctx.generate_data

# Train the models
echo "🤖 Training XSS context and escaping models..."
OUT_DIR="$OUT_DIR" DATA="$DATA_DIR/train.jsonl" python -m backend.ml.xss_ctx.train

echo "✅ Training complete! Models saved to $OUT_DIR"
echo "📋 Generated files:"
ls -la "$OUT_DIR"/xss_*.joblib 2>/dev/null || echo "⚠️  No model files found in $OUT_DIR"

echo "🎯 XSS Context Classifier is now ready to use!"
