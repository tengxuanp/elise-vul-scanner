import csv
import os
import pickle
import sys
from collections import defaultdict

BASE_DIR = os.path.dirname(__file__)
sys.path.append(BASE_DIR)
from simple_model import SimpleModel
DATA_FILE = os.path.join(BASE_DIR, "train_xss.csv")
MODEL_FILE = os.path.join(BASE_DIR, "recommender_model.pkl")

# === Load dataset ===
if not os.path.exists(DATA_FILE):
    raise FileNotFoundError(f"Dataset not found: {DATA_FILE}")

sums = defaultdict(lambda: [0.0] * 17)
counts = defaultdict(int)
with open(DATA_FILE) as f:
    reader = csv.reader(f)
    next(reader)  # header part 1
    next(reader)  # header part 2
    for row in reader:
        features = list(map(int, row[:17]))
        label = int(row[17])
        sums[label] = [s + v for s, v in zip(sums[label], features)]
        counts[label] += 1
        
centroids = {lbl: [v / counts[lbl] for v in sums[lbl]] for lbl in sums}
model = SimpleModel(centroids)

os.makedirs("ml", exist_ok=True)
with open(MODEL_FILE, "wb") as f:
    pickle.dump(model, f)
