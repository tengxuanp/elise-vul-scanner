from fastapi import APIRouter, status
from backend.app_state import DATA_DIR, MODEL_DIR, USE_ML, REQUIRE_RANKER
import json
from pathlib import Path

router = APIRouter()

@router.get("/healthz")
def healthz():
    fails = []
    
    # Check DATA_DIR is writable
    try:
        (DATA_DIR / "probe").mkdir(parents=True, exist_ok=True)
    except Exception as e:
        fails.append(f"DATA_DIR not writable: {e}")
    
    # Check ML models if USE_ML is enabled
    if USE_ML:
        if not MODEL_DIR.exists():
            fails.append("MODEL_DIR missing")
        else:
            # Check for RANKER_MANIFEST.json
            manifest_path = MODEL_DIR / "RANKER_MANIFEST.json"
            if not manifest_path.exists():
                if REQUIRE_RANKER:
                    fails.append("RANKER_MANIFEST.json missing (required)")
                else:
                    fails.append("RANKER_MANIFEST.json missing (optional)")
            else:
                try:
                    with open(manifest_path, 'r') as f:
                        manifest = json.load(f)
                    
                    # Check if required models exist
                    models = manifest.get("models", {})
                    for model_key, model_info in models.items():
                        model_path = MODEL_DIR / model_info["model_file"]
                        if not model_path.exists():
                            if REQUIRE_RANKER:
                                fails.append(f"Model file missing (required): {model_info['model_file']}")
                            else:
                                fails.append(f"Model file missing (optional): {model_info['model_file']}")
                        
                        cal_path = MODEL_DIR / model_info["calibration_file"]
                        if not cal_path.exists():
                            if REQUIRE_RANKER:
                                fails.append(f"Calibration file missing (required): {model_info['calibration_file']}")
                            else:
                                fails.append(f"Calibration file missing (optional): {model_info['calibration_file']}")
                            
                except Exception as e:
                    fails.append(f"Error reading RANKER_MANIFEST.json: {e}")
    
    # Check playwright import
    try:
        from backend.modules.playwright_crawler import crawl_site
    except Exception as e:
        fails.append(f"Playwright import failed: {e}")
    
    return {
        "ok": not bool(fails), 
        "data_dir": str(DATA_DIR), 
        "model_dir": str(MODEL_DIR),
        "use_ml": USE_ML,
        "require_ranker": REQUIRE_RANKER,
        "failed_checks": fails
    }, (status.HTTP_200_OK if not fails else status.HTTP_500_INTERNAL_SERVER_ERROR)