import joblib
import numpy as np
import pandas as pd
import os

class Recommender:
    def __init__(self, model_path="ml/recommender_model.pkl", dataset_path="ml/train_xss.csv"):
        # Load trained model
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model file not found: {model_path}")
        self.model = joblib.load(model_path)

        # Load training dataset to extract payload_map
        if not os.path.exists(dataset_path):
            raise FileNotFoundError(f"Dataset file not found: {dataset_path}")
        df = pd.read_csv(dataset_path)

        if "label" not in df.columns or "inspection_strings" not in df.columns:
            raise ValueError("Dataset must contain 'label' and 'inspection_strings' columns.")

        # Map: label → one payload example
        self.payload_map = df.groupby("label")["inspection_strings"].first().to_dict()

    def recommend(self, feature_vector, top_n=3):
        pred_probs = self.model.predict_proba([feature_vector])[0]
        top_indices = np.argsort(pred_probs)[::-1][:top_n]
        return [
            (self.payload_map.get(i, f"[Unknown label {i}]"), pred_probs[i])
            for i in top_indices
        ]
