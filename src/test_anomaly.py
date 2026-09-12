from __future__ import annotations

import sys
from pathlib import Path
from time import perf_counter

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.anomaly_detector import detect_anomaly, load_anomaly_model, result_to_alert
from src.train_anomaly_model import FEATURES, train_anomaly_model


ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "data" / "synthetic_benign_flows.csv"
MODEL_PATH = ROOT / "models" / "isolation_forest.joblib"


def make_benign_training_data(n: int = 1200, seed: int = 42) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    duration = np.clip(rng.lognormal(mean=-0.2, sigma=0.8, size=n), 0.02, 30)
    packet_count = np.clip(rng.poisson(lam=35, size=n) + 2, 1, None)
    avg_packet_size = np.clip(rng.normal(750, 180, size=n), 100, 1500)
    total_bytes = np.maximum(packet_count * avg_packet_size, 100)
    pps = packet_count / duration
    bps = total_bytes / duration
    syn_count = rng.binomial(packet_count.astype(int), 0.04)
    ack_count = rng.binomial(packet_count.astype(int), 0.55)
    rst_count = rng.binomial(packet_count.astype(int), 0.01)
    udp_count = rng.binomial(packet_count.astype(int), 0.20)

    return pd.DataFrame({
        "duration": duration,
        "packet_count": packet_count,
        "total_bytes": total_bytes,
        "packets_per_second": pps,
        "bytes_per_second": bps,
        "syn_count": syn_count,
        "syn_ratio": syn_count / packet_count,
        "ack_count": ack_count,
        "rst_count": rst_count,
        "udp_count": udp_count,
    })[FEATURES]


def make_test_flows() -> list[dict]:
    normal = [
        dict(duration=1.2, packet_count=38, total_bytes=28000, packets_per_second=31.7, bytes_per_second=23333, syn_count=2, syn_ratio=0.053, ack_count=21, rst_count=0, udp_count=7),
        dict(duration=4.0, packet_count=52, total_bytes=41000, packets_per_second=13, bytes_per_second=10250, syn_count=1, syn_ratio=0.019, ack_count=31, rst_count=1, udp_count=12),
        dict(duration=0.8, packet_count=25, total_bytes=18000, packets_per_second=31.25, bytes_per_second=22500, syn_count=1, syn_ratio=0.04, ack_count=14, rst_count=0, udp_count=4),
        dict(duration=8.5, packet_count=71, total_bytes=62000, packets_per_second=8.35, bytes_per_second=7294, syn_count=3, syn_ratio=0.042, ack_count=39, rst_count=1, udp_count=15),
    ]
    # TEST/SYNTHETIC unusual examples only; not real attack traffic.
    unusual = [
        dict(duration=0.01, packet_count=5000, total_bytes=250000, packets_per_second=500000, bytes_per_second=25000000, syn_count=4800, syn_ratio=0.96, ack_count=2, rst_count=150, udp_count=0),
        dict(duration=0.02, packet_count=3500, total_bytes=4200000, packets_per_second=175000, bytes_per_second=210000000, syn_count=0, syn_ratio=0.0, ack_count=5, rst_count=0, udp_count=3450),
        dict(duration=90.0, packet_count=2, total_bytes=120, packets_per_second=0.022, bytes_per_second=1.33, syn_count=1, syn_ratio=0.5, ack_count=0, rst_count=0, udp_count=0),
        dict(duration=0.005, packet_count=2, total_bytes=20000000, packets_per_second=400, bytes_per_second=4000000000, syn_count=2, syn_ratio=1.0, ack_count=0, rst_count=0, udp_count=0),
    ]
    return normal + unusual


def main() -> None:
    if not DATA_PATH.exists():
        df = make_benign_training_data()
        df.to_csv(DATA_PATH, index=False)

    # Ensure the test is independently runnable.
    train_anomaly_model(DATA_PATH, contamination=0.02, random_state=42, n_estimators=200, model_path=MODEL_PATH)

    print("\nModel loading test")
    artifact = load_anomaly_model(MODEL_PATH)
    print("Model loaded: OK")

    flows = make_test_flows()
    benign_count = 0
    anomaly_count = 0
    total_prediction_ms = 0.0

    print("\nPrediction results")
    for idx, flow in enumerate(flows, start=1):
        result = detect_anomaly(flow, artifact)
        total_prediction_ms += result["prediction_time_ms"]

        if result["prediction"] == "BENIGN":
            benign_count += 1
        else:
            anomaly_count += 1

        print(f"\nSample {idx}")
        print(f"Prediction: {result['prediction']}")
        print(f"Score: {result['anomaly_score']}")
        print(f"Confidence: {result['confidence']}")
        print(f"Prediction time: {result['prediction_time_ms']} ms")

    print("\nMissing/invalid feature handling test")
    try:
        detect_anomaly({"duration": 1.0}, artifact)
    except ValueError as exc:
        print(f"Missing feature test: PASS ({exc})")

    invalid = make_test_flows()[0].copy()
    invalid["packet_count"] = -1
    try:
        detect_anomaly(invalid, artifact)
    except ValueError as exc:
        print(f"Invalid value test: PASS ({exc})")

    # Alert conversion smoke test.
    sample_result = detect_anomaly(flows[-1], artifact)
    sample_flow = dict(flows[-1], source_ip="192.0.2.10", destination_ip="192.0.2.20",
                       source_port=12345, destination_port=443, protocol="TCP",
                       timestamp="2026-09-13T01:00:00+05:30")
    alert = result_to_alert(sample_result, sample_flow)
    assert alert["threat_type"] == "ANOMALY"
    assert alert["detection_source"] == "ISOLATION_FOREST"
    print("Alert format test: PASS")

    print("\nSummary")
    print(f"Total samples: {len(flows)}")
    print(f"BENIGN count: {benign_count}")
    print(f"ANOMALY count: {anomaly_count}")
    print(f"Average prediction time: {total_prediction_ms / len(flows):.4f} ms")

    print("\nNOTE: unusual examples above are TEST/SYNTHETIC behavioural cases.")
    print("They are not real attack traffic and are not an accuracy benchmark.")


if __name__ == "__main__":
    main()
