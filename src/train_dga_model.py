import pandas as pd
import numpy as np
import math
from collections import Counter
from pathlib import Path

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import joblib


BASE_DIR = Path(__file__).resolve().parent.parent

input_file = (
    BASE_DIR
    / "datasets"
    / "processed"
    / "dga_sample.csv"
)

model_dir = BASE_DIR / "models"
model_dir.mkdir(exist_ok=True)

model_file = model_dir / "dga_random_forest.joblib"


# -------------------------
# FEATURE FUNCTIONS
# -------------------------

def calculate_entropy(domain):
    if not domain:
        return 0

    counts = Counter(domain)
    length = len(domain)

    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def extract_features(domain):

    domain = str(domain).lower()

    length = len(domain)

    digits = sum(char.isdigit() for char in domain)

    vowels = sum(char in "aeiou" for char in domain)

    unique_chars = len(set(domain))

    entropy = calculate_entropy(domain)

    return [
        length,
        entropy,
        digits / length if length else 0,
        vowels / length if length else 0,
        unique_chars / length if length else 0
    ]


# -------------------------
# LOAD DATASET
# -------------------------

print("Loading dataset...")

df = pd.read_csv(input_file)

print("Total samples:", len(df))


# -------------------------
# FEATURE EXTRACTION
# -------------------------

print("Extracting features...")

X = np.array(
    [extract_features(domain) for domain in df["domain"]]
)

y = df["threat"].map({
    "benign": 0,
    "dga": 1
})

print("Feature extraction complete!")

print("Feature shape:", X.shape)


# -------------------------
# TRAIN / TEST SPLIT
# -------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)


# -------------------------
# TRAIN RANDOM FOREST
# -------------------------

print("\nTraining Random Forest...")

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)


# -------------------------
# EVALUATE MODEL
# -------------------------

print("\nTesting model...")

predictions = model.predict(X_test)

accuracy = accuracy_score(
    y_test,
    predictions
)

print("\nAccuracy:", accuracy)

print("\nClassification Report:")

print(
    classification_report(
        y_test,
        predictions,
        target_names=["benign", "dga"]
    )
)


# -------------------------
# SAVE MODEL
# -------------------------

joblib.dump(model, model_file)

print("\nModel saved successfully!")
print("Location:", model_file)