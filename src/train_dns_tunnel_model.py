import pandas as pd
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
    / "dns_tunnel_features.csv"
)

model_dir = BASE_DIR / "models"
model_dir.mkdir(exist_ok=True)

model_file = model_dir / "dns_tunnel_random_forest.joblib"


# Features used by the model
FEATURE_COLUMNS = [
    "query_length",
    "subdomain_length",
    "entropy",
    "digit_ratio",
    "unique_char_ratio"
]


print("Loading DNS dataset...")

df = pd.read_csv(input_file)

print("Total records:", len(df))

print("\nLabel counts:")
print(df["label"].value_counts())


# Convert labels to numbers
X = df[FEATURE_COLUMNS]

y = df["label"].map({
    "benign": 0,
    "tunnel": 1
})


# Split data
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)


print("\nTraining DNS Tunnel Random Forest...")

model = RandomForestClassifier(
    n_estimators=150,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced"
)

model.fit(X_train, y_train)


# Test model
print("\nTesting model...")

predictions = model.predict(X_test)

accuracy = accuracy_score(y_test, predictions)

print("\nAccuracy:", accuracy)

print("\nClassification Report:")

print(
    classification_report(
        y_test,
        predictions,
        target_names=["benign", "tunnel"]
    )
)


# Feature importance
print("\nFeature Importance:")

for feature, importance in sorted(
    zip(FEATURE_COLUMNS, model.feature_importances_),
    key=lambda x: x[1],
    reverse=True
):
    print(f"{feature}: {importance:.4f}")


# Save model
joblib.dump(model, model_file)

print("\nModel saved successfully!")
print("Location:", model_file)
