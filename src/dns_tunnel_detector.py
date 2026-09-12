from pathlib import Path
from collections import Counter
import math

import joblib
import pandas as pd


BASE_DIR = Path(__file__).resolve().parent.parent

MODEL_PATH = (
    BASE_DIR
    / "models"
    / "dns_tunnel_random_forest.joblib"
)

FEATURE_COLUMNS = [
    "query_length",
    "subdomain_length",
    "entropy",
    "digit_ratio",
    "unique_char_ratio"
]

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


def extract_features(query):

    query = str(query).rstrip(".")
    parts = query.split(".")

    subdomain = parts[0] if parts else query

    subdomain_length = len(subdomain)

    digits = sum(char.isdigit() for char in subdomain)
    unique_chars = len(set(subdomain))

    return {
        "query_length": len(query),
        "subdomain_length": subdomain_length,
        "entropy": calculate_entropy(subdomain),
        "digit_ratio": (
            digits / subdomain_length
            if subdomain_length else 0
        ),
        "unique_char_ratio": (
            unique_chars / subdomain_length
            if subdomain_length else 0
        )
    }


def detect_dns_tunnel(query):

    features = extract_features(query)

    feature_df = pd.DataFrame(
        [[features[column] for column in FEATURE_COLUMNS]],
        columns=FEATURE_COLUMNS
    )

    prediction = model.predict(feature_df)[0]
    probabilities = model.predict_proba(feature_df)[0]

    confidence = float(max(probabilities))

    threat_type = (
        "DNS_TUNNEL"
        if prediction == 1
        else "BENIGN"
    )

    return {
        "query": query,
        "threat_type": threat_type,
        "confidence": round(confidence, 4),
        "evidence": {
            "query_length": features["query_length"],
            "subdomain_length": features["subdomain_length"],
            "entropy": round(features["entropy"], 4),
            "digit_ratio": round(features["digit_ratio"], 4)
        }
    }


if __name__ == "__main__":

    test_queries = [
        "www.google.com",
        "vaaaakardli.pirate.sea",
        "ce7e01cccd96c95965437b031e65fa8655.bot.hackbiji.top"
    ]

    for query in test_queries:
        result = detect_dns_tunnel(query)
        print(result)