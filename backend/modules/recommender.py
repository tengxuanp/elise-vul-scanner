from __future__ import annotations
from typing import List, Tuple, Optional
try:
    import numpy as np
except Exception:
    np = None  # we'll degrade gracefully

from .ml.family_router import default_payloads_by_family

class Recommender:
    """
    Minimal recommender that can load a model (if you have one) and
    filter by payload family. Falls back to curated defaults.
    """
    def __init__(self):
        self.ready = False
        self.model = None  # your existing model object if any

    def load(self):
        # If you had a saved model, load it here. Keep API compatible.
        self.ready = True

    def recommend(
        self,
        feats,                      # whatever FeatureExtractor returns
        top_n: int = 3,
        threshold: float = 0.2,
        family: Optional[str] = None
    ) -> List[Tuple[str, float]]:
        # If you had a learned payload bank, score it here using feats.
        # Fallback: choose from curated family bank with nominal confidences.
        payloads = default_payloads_by_family(family or "sqli")
        out: List[Tuple[str, float]] = []
        base_conf = 0.6 if family else 0.4
        for p in payloads[:max(1, top_n)]:
            out.append((p, base_conf))
        return out
