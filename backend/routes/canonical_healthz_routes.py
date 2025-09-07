from fastapi import APIRouter, status
from backend.app_state import DATA_DIR, MODEL_DIR, USE_ML

router = APIRouter()

@router.get("/healthz")
def healthz():
    fails = []
    try:
        (DATA_DIR / "probe").mkdir(parents=True, exist_ok=True)
    except Exception as e:
        fails.append(f"DATA_DIR not writable: {e}")
    if USE_ML and not MODEL_DIR.exists():
        fails.append("MODEL_DIR missing")
    return {"ok": not bool(fails), "data_dir": str(DATA_DIR), "model_dir": str(MODEL_DIR), "failed_checks": fails}, (status.HTTP_200_OK if not fails else status.HTTP_500_INTERNAL_SERVER_ERROR)