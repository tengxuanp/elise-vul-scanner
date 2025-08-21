from __future__ import annotations
import os, pickle, re
from pathlib import Path
from typing import Dict
from collections import Counter

MODEL_PATH = Path(__file__).resolve().parents[2] / "models" / "param_prioritizer.pkl"
MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)

TOKENS_RE = re.compile(r"[A-Za-z0-9]+")

# Weak, high-signal names and path hints (used when no model file exists)
WEAK_POS = {"id","ids","uid","user","user_id","pid","productid","order","page",
            "sort","q","query","search","s","to","return_to","redirect","url",
            "next","callback","continue","path","target","link","dest"}
WEAK_PATH = {"login","auth","admin","product","search","redirect","report","download","profile","cart","order"}

def featurize(method: str, url: str, param: str) -> Dict[str, float]:
    method = (method or "GET").upper()
    toks = TOKENS_RE.findall((url or "").lower())
    feats = Counter()
    feats[f"m:{method}"] += 1
    feats[f"p:{(param or '').lower()}"] += 1
    for t in toks[-6:]:
        feats[f"path:{t}"] += 1
    return dict(feats)

class ParamPrioritizer:
    def __init__(self):
        self.model = None  # {"w": np.array, "b": float}
        self.vocab = []    # list[str]

    def load(self):
        if MODEL_PATH.exists():
            with open(MODEL_PATH, "rb") as f:
                obj = pickle.load(f)
            self.model = obj.get("model")
            self.vocab = obj.get("vocab", [])
        else:
            self.model = None
            self.vocab = []

    def predict_proba(self, method: str, url: str, param: str) -> float:
        # Heuristic fallback (fast + surprisingly decent)
        if self.model is None:
            score = 0.0
            p = (param or "").lower()
            if p in WEAK_POS: score += 0.6
            if any(x in (url or "").lower() for x in WEAK_PATH): score += 0.2
            if (method or "").upper() == "GET": score += 0.1
            return min(1.0, score)

        # Tiny LR: sigma(w·x + b)
        import numpy as np
        x = featurize(method, url, param)
        vec = np.array([x.get(w, 0.0) for w in self.vocab], dtype=float)
        w = self.model["w"]; b = float(self.model["b"])
        z = float(w.dot(vec) + b)
        return float(1.0 / (1.0 + np.exp(-z)))
