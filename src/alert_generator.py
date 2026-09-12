from datetime import datetime, timezone


def get_severity(threat_type, confidence):
    """
    Assign severity based on threat type and confidence.
    """

    if threat_type == "BENIGN":
        return "NONE"

    if confidence >= 0.90:
        return "HIGH"

    if confidence >= 0.70:
        return "MEDIUM"

    return "LOW"


def create_alert(result):
    """
    Convert detector output into a standard alert format.
    """

    threat_type = result.get("threat_type", "UNKNOWN")
    confidence = result.get("confidence", 0)

    alert = {
        "timestamp": result.get(
            "timestamp",
            datetime.now(timezone.utc).isoformat()
        ),
        "source_ip": result.get("source_ip", "UNKNOWN"),
        "destination_ip": result.get("destination_ip", "UNKNOWN"),
        "source_port": result.get("source_port"),
        "destination_port": result.get("destination_port"),
        "protocol": result.get("protocol", "UNKNOWN"),
        "threat_type": threat_type,
        "detection_source": result.get("detection_source", "UNKNOWN"),
        "confidence": confidence,
        "severity": get_severity(
            threat_type,
            confidence
        ),
        "evidence": result.get("evidence", {})
    }

    # Add domain if it comes from DGA detector
    if "domain" in result:
        alert["domain"] = result["domain"]

    # Add query if it comes from DNS tunnel detector
    if "query" in result:
        alert["query"] = result["query"]

    return alert