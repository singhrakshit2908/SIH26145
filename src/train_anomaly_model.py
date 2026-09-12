from __future__ import annotations

import argparse
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

FEATURES = [
    "duration",
    "packet_count",
    "total_bytes",
    "packets_per_second",
    "bytes_per_second",
    "syn_count",
    "syn_ratio",
    "ack_count",
    "rst_count",
    "udp_count",
]


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _default_model_path() -> Path:
    return _project_root() / "models" / "isolation_forest.joblib"


def validate_and_prepare(dataframe: pd.DataFrame) -> pd.DataFrame:
    missing = [c for c in FEATURES if c not in dataframe.columns]
    if missing:
        raise ValueError(f"Missing required feature columns: {missing}")

    x = dataframe[FEATURES].copy()
    for col in FEATURES:
        x[col] = pd.to_numeric(x[col], errors="coerce")

    # Replace infinities, then fill missing values with feature medians.
    x = x.replace([np.inf, -np.inf], np.nan)
    medians = x.median(numeric_only=True)

    if medians.isna().any():
        bad = medians[medians.isna()].index.tolist()
        raise ValueError(
            "Cannot train because these features contain no usable numeric values: "
            f"{bad}"
        )

    x = x.fillna(medians)

    if (x["duration"] < 0).any():
        raise ValueError("duration cannot be negative")
    if (x["packet_count"] < 0).any() or (x["total_bytes"] < 0).any():
        raise ValueError("packet_count and total_bytes cannot be negative")
    if (x["syn_count"] < 0).any() or (x["ack_count"] < 0).any() or (x["rst_count"] < 0).any():
        raise ValueError("packet counters cannot be negative")

    # Keep ratios/rates numerically bounded and finite.
    x["syn_ratio"] = x["syn_ratio"].clip(0, 1)
    x["packets_per_second"] = x["packets_per_second"].clip(lower=0)
    x["bytes_per_second"] = x["bytes_per_second"].clip(lower=0)
    x["udp_count"] = x["udp_count"].clip(lower=0)

    return x


def train_anomaly_model(
    csv_path: str | Path,
    contamination: float = 0.02,
    random_state: int = 42,
    n_estimators: int = 200,
    model_path: str | Path | None = None,
) -> Path:
    csv_path = Path(csv_path)
    model_path = Path(model_path) if model_path else _default_model_path()

    if not csv_path.exists():
        raise FileNotFoundError(f"Training CSV not found: {csv_path}")
    if not (0 < contamination <= 0.5):
        raise ValueError("contamination must be > 0 and <= 0.5")

    df = pd.read_csv(csv_path)
    x = validate_and_prepare(df)

    start = time.perf_counter()
    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=random_state,
        n_jobs=-1,
    )
    model.fit(x[FEATURES])
    elapsed = time.perf_counter() - start

    model_path.parent.mkdir(parents=True, exist_ok=True)
    artifact = {
        "model": model,
        "features": FEATURES,
        "medians": x[FEATURES].median().to_dict(),
        "contamination": contamination,
        "random_state": random_state,
        "n_estimators": n_estimators,
        "training_samples": int(len(x)),
    }
    joblib.dump(artifact, model_path)

    print(f"Training samples: {len(x)}")
    print(f"Features: {len(FEATURES)}")
    print(f"Model path: {model_path}")
    print(f"Training time: {elapsed:.6f} seconds")

    return model_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Train SentinelFlow Isolation Forest anomaly model.")
    parser.add_argument("--data", required=True, help="CSV containing BENIGN/normal flow features.")
    parser.add_argument("--contamination", type=float, default=0.02)
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument("--n-estimators", type=int, default=200)
    parser.add_argument("--model", default=str(_default_model_path()))
    args = parser.parse_args()

    train_anomaly_model(
        csv_path=args.data,
        contamination=args.contamination,
        random_state=args.random_state,
        n_estimators=args.n_estimators,
        model_path=args.model,
    )


if __name__ == "__main__":
    main()
