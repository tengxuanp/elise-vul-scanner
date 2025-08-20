# backend/modules/recommender.py
from __future__ import annotations

from pathlib import Path
import os
import csv
import importlib
import sys
import pickle
from typing import Any, Dict, List, Tuple

DEFAULT_FALLBACK_PAYLOAD = "<script>alert(1)</script>"

def _repo_root() -> Path:
    # backend/modules/recommender.py -> .../repo_root
    return Path(__file__).resolve().parents[2]


class Recommender:
    """
    Lazy-loading recommender:
    - defers model & dataset IO until first use (or .load())
    - resolves paths from repo root or env vars (ML_MODEL_PATH / ML_DATASET_PATH)
    - never crashes the app at import time
    """

    def __init__(
        self,
        model_path: str | os.PathLike | None = None,
        dataset_path: str | os.PathLike | None = None,
    ):
        root = _repo_root()
        self.model_path = Path(
            model_path
            or os.getenv("ML_MODEL_PATH")
            or (root / "ml" / "recommender_model.pkl")
        )
        self.dataset_path = Path(
            dataset_path
            or os.getenv("ML_DATASET_PATH")
            or (root / "ml" / "train_xss.csv")
        )
        self.model: Any = None
        self.payload_map: Dict[int, str] = {}
        self._loaded = False

    # Public hook for callers that expect .load()
    def load(self) -> "Recommender":
        self._ensure_loaded()
        return self

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return

        # --- load model (and make sure any custom classes are importable) ---
        if not self.model_path.exists():
            raise FileNotFoundError(f"Model file not found: {self.model_path}")

        # Some pickles need 'simple_model' importable; make model dir importable.
        model_dir = self.model_path.parent
        if str(model_dir) not in sys.path:
            sys.path.append(str(model_dir))
        try:
            importlib.import_module("simple_model")
        except ModuleNotFoundError:
            # OK if the pickle doesn't reference it; otherwise pickle.load will raise.
            pass

        with self.model_path.open("rb") as f:
            self.model = pickle.load(f)

        # --- load dataset/payload map (non-fatal if missing; fallback is used) ---
        self.payload_map = {}
        if self.dataset_path.exists():
            with self.dataset_path.open(newline="", encoding="utf-8") as f:
                reader = csv.reader(f)
                # File has two header rows in your dataset:
                next(reader, None)
                next(reader, None)
                for row in reader:
                    # column 17 = label, 18 = payload (per your original code)
                    try:
                        label = int(row[17])
                        payload = row[18]
                        # first occurrence wins
                        self.payload_map.setdefault(label, payload)
                    except (ValueError, IndexError):
                        continue
        # else: leave payload_map empty → fallback used

        self._loaded = True

    # === public API ===
    def recommend(
        self,
        feature_vector: List[float],
        top_n: int = 3,
        threshold: float = 0.2,
    ) -> List[Tuple[str, float]]:
        self._ensure_loaded()

        if not hasattr(self.model, "predict_proba"):
            raise ValueError("Loaded model has no predict_proba().")

        probs = self.model.predict_proba([feature_vector])[0]

        def _payload_for(label: int) -> str:
            return self.payload_map.get(label, DEFAULT_FALLBACK_PAYLOAD)

        # Low-confidence → single fallback mapped from first label if present
        best = float(max(probs))
        if best < float(threshold):
            try:
                fallback_label = int(self.model.labels[0])  # your original behavior
                return [(_payload_for(fallback_label), best)]
            except Exception:
                return [(DEFAULT_FALLBACK_PAYLOAD, best)]

        # Rank & return top_n
        ranked = sorted(range(len(probs)), key=lambda i: probs[i], reverse=True)
        out: List[Tuple[str, float]] = []
        for idx in ranked[: int(top_n)]:
            try:
                label = int(self.model.labels[idx])
                out.append((_payload_for(label), probs[idx]))
            except Exception:
                out.append((DEFAULT_FALLBACK_PAYLOAD, probs[idx]))
        return out

    # Optional helper
    def available(self) -> bool:
        return self.model_path.exists() and self.dataset_path.exists()
