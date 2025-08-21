from __future__ import annotations
import pickle
from pathlib import Path

MODEL_PATH = Path(__file__).resolve().parents[2] / "models" / "delta_scorer.pkl"
MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)

class DeltaScorer:
    def __init__(self):
        self.model = None  # {"keys":[...], "w":[...], "b":float}

    def load(self):
        if MODEL_PATH.exists():
            with open(MODEL_PATH, "rb") as f:
                self.model = pickle.load(f)
        else:
            self.model = None

    def score(self, features: dict) -> float:
        # Heuristic fallback
        if self.model is None:
            score = 0.0
            if features.get("external_redirect"): score += 0.7
            if features.get("status_changed"): score += 0.3
            if features.get("is_5xx"): score += 0.3
            if features.get("is_4xx"): score += 0.15
            lr = abs(features.get("len_ratio", 1.0) - 1.0)
            score += min(0.4, lr)
            return 1.0 if score > 1.0 else score

        # Learned linear logit
        import numpy as np
        keys = self.model["keys"]; w = np.array(self.model["w"], dtype=float); b = float(self.model["b"])
        x = np.array([features.get(k, 0.0) for k in keys], dtype=float)
        z = float(w.dot(x) + b)
        return float(1.0 / (1.0 + np.exp(-z)))
