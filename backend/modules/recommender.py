import os
import csv
import pickle

class Recommender:
    def __init__(self, model_path="ml/recommender_model.pkl", dataset_path="ml/train_xss.csv"):
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model file not found: {model_path}")
        model_dir = os.path.dirname(model_path)
        import sys
        sys.path.append(model_dir)
        import simple_model  # ensures class is available for unpickling
        with open(model_path, "rb") as f:
            self.model = pickle.load(f)
            
        if not os.path.exists(dataset_path):
            raise FileNotFoundError(f"Dataset file not found: {dataset_path}")

        payload_map = {}
        with open(dataset_path) as f:
            reader = csv.reader(f)
            next(reader)
            next(reader)
            for row in reader:
                label = int(row[17])
                if label not in payload_map:
                    payload_map[label] = row[18]
        self.payload_map = payload_map
    
    def recommend(self, feature_vector, top_n=3, threshold=0.2):
        probs = self.model.predict_proba([feature_vector])[0]
        if max(probs) < threshold:
            fallback_label = self.model.labels[0]
            payload = self.payload_map.get(fallback_label, "<script>alert(1)</script>")
            return [(payload, max(probs))]
            
        ranked = sorted(range(len(probs)), key=lambda i: probs[i], reverse=True)
        results = []
        for idx in ranked[:top_n]:
            label = self.model.labels[idx]
            results.append((self.payload_map.get(label, f"[Unknown label {label}]"), probs[idx]))
        return results