from typing import Any, Mapping

from src.anomaly_detector import detect_anomaly, result_to_alert


def analyze_flow_for_anomaly(
    flow: Mapping[str, Any],
) -> dict[str, Any]:
    """
    Run the Isolation Forest anomaly detector on one flow result.

    Returns the raw anomaly detection result plus the original flow.
    """

    result = detect_anomaly(flow)

    return {
        "flow": dict(flow),
        "prediction": result.get("prediction"),
        "anomaly_score": result.get("anomaly_score"),
        "confidence": result.get("confidence"),
        "evidence": result.get("evidence", {}),
        "prediction_time_ms": result.get("prediction_time_ms"),
    }


def create_anomaly_alert(
    flow: Mapping[str, Any],
) -> dict[str, Any] | None:
    """
    Run anomaly detection and convert an ANOMALY result
    into SENTINELFLOW's standard alert schema.

    BENIGN flows return None.
    """

    result = detect_anomaly(flow)

    if result.get("prediction") != "ANOMALY":
        return None

    return result_to_alert(
        result=result,
        flow=flow,
        timestamp=flow.get("timestamp"),
    )