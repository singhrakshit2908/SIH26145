import math
from collections import Counter
from pathlib import Path

import joblib
import numpy as np


BASE_DIR = Path(__file__).resolve().parent.parent

MODEL_PATH = (
    BASE_DIR
    / "models"
    / "dga_random_forest.joblib"
)

model = joblib.load(MODEL_PATH)


def calculate_entropy(text):
    if not text:
        return 0

    counts = Counter(text)
    length = len(text)

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


def detect_dga(domain):

    features = np.array(
        [extract_features(domain)]
    )

    prediction = model.predict(features)[0]

    probabilities = model.predict_proba(features)[0]

    confidence = float(max(probabilities))

    threat_type = "DGA" if prediction == 1 else "BENIGN"

    return {
        "domain": domain,
        "threat_type": threat_type,
        "confidence": round(confidence, 4),
        "evidence": {
            "domain_length": len(domain),
            "entropy": round(calculate_entropy(domain), 4)
        }
    }


if __name__ == "__main__":

    test_domains = [
        "google",
        "ocymmekqogkw",
        "bankinvestmentaccount"
    ]

    for domain in test_domains:
        result = detect_dga(domain)
        print(result)