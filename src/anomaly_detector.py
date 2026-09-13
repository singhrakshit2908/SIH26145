from __future__ import annotations

import math
from pathlib import Path
from time import perf_counter
from typing import Any, Mapping

import joblib
import numpy as np
import pandas as pd


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


DEFAULT_MODEL_PATH = (
    Path(__file__).resolve().parents[1]
    / "models"
    / "isolation_forest.joblib"
)


def load_anomaly_model(
    model_path: str | Path | None = None,
) -> dict[str, Any]:

    path = Path(model_path) if model_path else DEFAULT_MODEL_PATH

    if not path.exists():
        raise FileNotFoundError(
            f"Isolation Forest model not found at {path}. "
            "Train it first with src/train_anomaly_model.py."
        )

    artifact = joblib.load(path)

    if not isinstance(artifact, dict) or "model" not in artifact:
        raise ValueError("Invalid anomaly model artifact.")

    if artifact.get("features") != FEATURES:
        raise ValueError(
            "Model feature schema does not match detector schema."
        )

    return artifact


def prepare_features(
    flow: Mapping[str, Any]
    | pd.Series
    | pd.DataFrame,
    model_artifact: dict[str, Any] | None = None,
) -> pd.DataFrame:

    if isinstance(flow, pd.DataFrame):
        df = flow.copy()

    elif isinstance(flow, pd.Series):
        df = flow.to_frame().T

    elif isinstance(flow, Mapping):
        df = pd.DataFrame([dict(flow)])

    else:
        raise TypeError(
            "flow must be a dict-like object, pandas Series, "
            "or pandas DataFrame"
        )

    missing = [
        column
        for column in FEATURES
        if column not in df.columns
    ]

    if missing:
        raise ValueError(
            f"Missing required feature(s): {missing}"
        )

    x = df[FEATURES].copy()

    for column in FEATURES:
        x[column] = pd.to_numeric(
            x[column],
            errors="coerce"
        )

    x = x.replace(
        [np.inf, -np.inf],
        np.nan
    )

    medians = {}

    if model_artifact:
        medians.update(
            model_artifact.get("medians", {})
        )

    for column in FEATURES:

        if x[column].isna().any():

            if (
                column not in medians
                or pd.isna(medians[column])
            ):
                raise ValueError(
                    f"Invalid/missing value for feature "
                    f"'{column}' and no training median "
                    f"is available."
                )

            x[column] = x[column].fillna(
                float(medians[column])
            )

    if (x < 0).any().any():

        negative = x.columns[
            (x < 0).any()
        ].tolist()

        raise ValueError(
            f"Negative values are invalid for: {negative}"
        )

    x["syn_ratio"] = x["syn_ratio"].clip(0, 1)

    x["packets_per_second"] = (
        x["packets_per_second"].clip(lower=0)
    )

    x["bytes_per_second"] = (
        x["bytes_per_second"].clip(lower=0)
    )

    x["udp_count"] = (
        x["udp_count"].clip(lower=0)
    )

    return x[FEATURES]


def _bounded_confidence(
    decision_score: float,
    model: Any,
) -> float:

    threshold = float(
        getattr(model, "offset_", 0.0)
    )

    scale = max(
        abs(threshold),
        0.05
    )

    confidence = min(
        1.0,
        abs(decision_score) / scale
    )

    return round(
        float(confidence),
        4
    )


def detect_anomalies(
    flows: list[Mapping[str, Any]]
    | pd.DataFrame,
    model: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """
    Run Isolation Forest on multiple flows in one batch.

    This is much faster than calling detect_anomaly()
    once for every flow.
    """

    artifact = model or load_anomaly_model()

    clf = artifact["model"]

    if isinstance(flows, pd.DataFrame):
        original_flows = flows.to_dict(
            orient="records"
        )
        input_data = flows

    else:
        original_flows = [
            dict(flow)
            for flow in flows
        ]

        input_data = pd.DataFrame(
            original_flows
        )

    if input_data.empty:
        return []

    x = prepare_features(
        input_data,
        artifact
    )

    start = perf_counter()

    raw_predictions = clf.predict(x)

    decision_scores = clf.decision_function(x)

    elapsed_ms = (
        perf_counter() - start
    ) * 1000.0

    prediction_time_ms = (
        elapsed_ms / len(x)
    )

    results = []

    for index, raw_prediction in enumerate(
        raw_predictions
    ):

        decision_score = float(
            decision_scores[index]
        )

        confidence = _bounded_confidence(
            decision_score,
            clf
        )

        # Isolation Forest normally returns:
        #   1  = normal
        #  -1  = anomaly
        prediction = (
            "BENIGN"
            if int(raw_prediction) == 1
            else "ANOMALY"
        )

        evidence = {
            feature: _json_number(
                x.iloc[index][feature]
            )
            for feature in FEATURES
        }

        results.append({
            "prediction": prediction,
            "anomaly_score": round(
                decision_score,
                6
            ),
            "confidence": confidence,
            "evidence": evidence,
            "prediction_time_ms": round(
                prediction_time_ms,
                4
            )
        })

    return results


def detect_anomaly(
    flow: Mapping[str, Any]
    | pd.Series
    | pd.DataFrame,
    model: dict[str, Any] | None = None,
) -> dict[str, Any]:

    results = detect_anomalies(
        flow
        if isinstance(flow, pd.DataFrame)
        else [flow],
        model
    )

    if not results:
        raise ValueError(
            "No flow data supplied."
        )

    return results[0]


def _json_number(
    value: Any,
) -> int | float:

    value = float(value)

    if value.is_integer():
        return int(value)

    return value


def result_to_alert(
    result: Mapping[str, Any],
    flow: Mapping[str, Any] | pd.Series,
    timestamp: str | None = None,
) -> dict[str, Any]:

    if isinstance(flow, pd.Series):
        flow = flow.to_dict()

    alert = {
        "timestamp": (
            timestamp
            if timestamp is not None
            else flow.get("timestamp")
        ),

        "source_ip": flow.get(
            "source_ip"
        ),

        "destination_ip": flow.get(
            "destination_ip"
        ),

        "source_port": flow.get(
            "source_port"
        ),

        "destination_port": flow.get(
            "destination_port"
        ),

        "protocol": flow.get(
            "protocol"
        ),

        "threat_type": "ANOMALY",

        "confidence": result.get(
            "confidence"
        ),

        "severity": (
            "MEDIUM"
            if result.get("prediction")
            == "ANOMALY"
            else "INFO"
        ),

        "detection_source": "ISOLATION_FOREST",

        "evidence": result.get(
            "evidence",
            {}
        ),
    }

    return alert