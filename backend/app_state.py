import os
from pathlib import Path

DATA_DIR = Path(os.getenv("ELISE_DATA_DIR", "backend/data")).absolute()
MODEL_DIR = Path(os.getenv("ELISE_ML_MODEL_DIR", "backend/modules/ml/models")).absolute()
USE_ML = os.getenv("ELISE_USE_ML", "1") != "0"
REQUIRE_RANKER = os.getenv("ELISE_REQUIRE_RANKER", "0") == "1"
DATA_DIR.mkdir(parents=True, exist_ok=True)
MODEL_DIR.mkdir(parents=True, exist_ok=True)