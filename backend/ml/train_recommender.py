import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import joblib
import os

# === Paths ===
DATA_FILE = "ml/train_xss.csv"
MODEL_FILE = "ml/recommender_model.pkl"

# === Load dataset ===
# Expected format: f1..f17, label (integer)
df = pd.read_csv(DATA_FILE)

# === Input and target ===
X = df.iloc[:, :17]           # First 17 features
y = df["label"].astype(int)   # Target label column

# === Train model ===
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X, y)

# === Save model ===
os.makedirs("ml", exist_ok=True)
joblib.dump(model, MODEL_FILE)

print(f"✅ Model trained and saved to {MODEL_FILE}")
