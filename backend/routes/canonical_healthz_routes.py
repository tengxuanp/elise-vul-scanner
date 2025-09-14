from fastapi import APIRouter, status
from backend.app_state import DATA_DIR, MODEL_DIR, USE_ML, REQUIRE_RANKER
import json, os
from pathlib import Path

router = APIRouter()

def get_healthz_data():
    """Get healthz data as a dictionary (without status code)."""
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
        import playwright  # noqa
        playwright_ok = True
    except Exception:
        playwright_ok = False
        fails.append("Playwright: Fail")
    
    # Check crawler import
    try:
        from backend.modules import playwright_crawler as _crawler  # noqa
        crawler_import_ok = True
    except Exception:
        crawler_import_ok = False
        fails.append("Crawler import: Fail")
    
    # Get ML model availability information
    ml_status = "disabled"
    available_models_info = {}
    defaults_in_use = False
    
    if USE_ML:
        try:
            from backend.modules.ml.infer_ranker import available_models, using_defaults
            available_models_info = available_models()
            
            # Check if we're using defaults
            has_any_models = any(info["has_model"] for info in available_models_info.values())
            has_any_defaults = any(info["has_defaults"] for info in available_models_info.values())
            
            if has_any_models:
                ml_status = "models_available"
            elif has_any_defaults:
                ml_status = "defaults_only"
                defaults_in_use = True
            else:
                ml_status = "no_models_or_defaults"
                
        except Exception as e:
            ml_status = "error"
            fails.append(f"ML status check failed: {e}")

    # SQLi dialect ML health
    sqli_dialect_ml = {
        "path_in_use": "unavailable",
        "has_text_model": False,
        "has_vectorizer": False,
        "has_alt_model": False,
        "dims_match": None,
    }
    try:
        from backend.modules.ml.sqli_dialect_infer import get_dialect_ml_health
        sqli_dialect_ml = get_dialect_ml_health()
        if USE_ML and not sqli_dialect_ml.get("has_text_model") and not sqli_dialect_ml.get("has_alt_model"):
            fails.append("SQLi dialect ML assets missing")
        if sqli_dialect_ml.get("has_text_model") and sqli_dialect_ml.get("has_vectorizer") and sqli_dialect_ml.get("dims_match") is False:
            fails.append("SQLi dialect model/vectorizer mismatch")
    except Exception as e:
        fails.append(f"SQLi dialect ML health failed: {e}")

    # SQLi dialect ML fallback note (rule -> ML surrogate)
    sqli_dialect_fallback = {"fallback_used_count": 0}
    try:
        from backend.modules.probes.sqli_triage import get_sqli_fallback_stats
        sqli_dialect_fallback = get_sqli_fallback_stats()
        # Surface a small note inside the ML block without failing health
        sqli_dialect_ml["fallback_active"] = sqli_dialect_fallback.get("fallback_used_count", 0) > 0
        sqli_dialect_ml["fallback_count"] = sqli_dialect_fallback.get("fallback_used_count", 0)
        sqli_dialect_ml["fallback_last_error"] = sqli_dialect_fallback.get("last_error")
    except Exception:
        pass
    
    return {
        "ok": not bool(fails), 
        "data_dir": str(DATA_DIR), 
        "model_dir": str(MODEL_DIR),
        "use_ml": USE_ML,
        "require_ranker": REQUIRE_RANKER,
        "ml_active": USE_ML,
        "models_available": available_models_info,
        "using_defaults": using_defaults() if USE_ML else True,
        "ml_status": ml_status,
        "available_models": available_models_info,
        "defaults_in_use": defaults_in_use,
        "thresholds": {
            "sqli_tau": float(os.getenv("ELISE_TAU_SQLI", "0.50")),
            "xss_tau": float(os.getenv("ELISE_TAU_XSS", "0.75")),
            "redirect_tau": float(os.getenv("ELISE_TAU_REDIRECT", "0.60")),
        },
        "playwright_ok": playwright_ok,
        "crawler_import_ok": crawler_import_ok,
        "checks": fails,
        "failed_checks": fails,
        "sqli_dialect_ml": sqli_dialect_ml,
        "sqli_dialect_fallback": sqli_dialect_fallback
    }

@router.get("/healthz")
def healthz():
    """Health check endpoint with status code."""
    data = get_healthz_data()
    status_code = status.HTTP_200_OK if data["ok"] else status.HTTP_500_INTERNAL_SERVER_ERROR
    return data, status_code
