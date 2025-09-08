"""
Golden Manifest Test - Verify RANKER_MANIFEST.json loads and all referenced files exist.
"""
import json
import os
from pathlib import Path
import pytest

from backend.app_state import MODEL_DIR, USE_ML, REQUIRE_RANKER

def test_ranker_manifest_exists():
    """Test that RANKER_MANIFEST.json exists when ML is enabled."""
    if not USE_ML:
        pytest.skip("ML not enabled")
    
    manifest_path = MODEL_DIR / "RANKER_MANIFEST.json"
    assert manifest_path.exists(), f"RANKER_MANIFEST.json not found at {manifest_path}"

def test_ranker_manifest_valid_json():
    """Test that RANKER_MANIFEST.json is valid JSON."""
    if not USE_ML:
        pytest.skip("ML not enabled")
    
    manifest_path = MODEL_DIR / "RANKER_MANIFEST.json"
    with open(manifest_path, 'r') as f:
        manifest = json.load(f)
    
    assert isinstance(manifest, dict), "Manifest must be a dictionary"
    assert "models" in manifest, "Manifest must contain 'models' key"

def test_all_model_files_exist():
    """Test that all referenced model files exist."""
    if not USE_ML:
        pytest.skip("ML not enabled")
    
    manifest_path = MODEL_DIR / "RANKER_MANIFEST.json"
    with open(manifest_path, 'r') as f:
        manifest = json.load(f)
    
    models = manifest.get("models", {})
    for model_key, model_info in models.items():
        # Check model file
        model_path = MODEL_DIR / model_info["model_file"]
        assert model_path.exists(), f"Model file missing: {model_info['model_file']}"
        
        # Check calibration file
        cal_path = MODEL_DIR / model_info["calibration_file"]
        assert cal_path.exists(), f"Calibration file missing: {model_info['calibration_file']}"

def test_calibration_files_valid():
    """Test that calibration files are valid JSON."""
    if not USE_ML:
        pytest.skip("ML not enabled")
    
    manifest_path = MODEL_DIR / "RANKER_MANIFEST.json"
    with open(manifest_path, 'r') as f:
        manifest = json.load(f)
    
    models = manifest.get("models", {})
    for model_key, model_info in models.items():
        cal_path = MODEL_DIR / model_info["calibration_file"]
        with open(cal_path, 'r') as f:
            cal_data = json.load(f)
        
        assert isinstance(cal_data, dict), f"Calibration file {cal_path} must be a dictionary"
        assert "threshold" in cal_data, f"Calibration file {cal_path} must contain 'threshold'"

def test_env_flags_honored():
    """Test that environment flags are properly honored."""
    # This test verifies that the flags are accessible and have expected values
    assert isinstance(USE_ML, bool), "USE_ML must be a boolean"
    assert isinstance(REQUIRE_RANKER, bool), "REQUIRE_RANKER must be a boolean"
    
    if REQUIRE_RANKER:
        assert USE_ML, "REQUIRE_RANKER=1 requires USE_ML=1"

def test_manifest_structure():
    """Test that manifest has expected structure."""
    if not USE_ML:
        pytest.skip("ML not enabled")
    
    manifest_path = MODEL_DIR / "RANKER_MANIFEST.json"
    with open(manifest_path, 'r') as f:
        manifest = json.load(f)
    
    models = manifest.get("models", {})
    assert len(models) > 0, "Manifest must contain at least one model"
    
    for model_key, model_info in models.items():
        required_fields = ["model_file", "calibration_file", "family", "threshold"]
        for field in required_fields:
            assert field in model_info, f"Model {model_key} missing required field: {field}"
        
        assert model_info["family"] in ["xss", "sqli", "redirect"], f"Invalid family: {model_info['family']}"
        assert isinstance(model_info["threshold"], (int, float)), f"Threshold must be numeric: {model_info['threshold']}"
