import sqlite3
from datetime import datetime
from pathlib import Path


DB_PATH = Path("data/cyberdhristi.db")
DEFAULT_TIME_WINDOW = 300  # 5 minutes


def get_connection():
    """Create a connection to the CYBERDHRISTI SQLite database."""
    return sqlite3.connect(DB_PATH)


def parse_timestamp(timestamp):
    """Convert an alert timestamp into a datetime object."""
    if isinstance(timestamp, datetime):
        return timestamp

    timestamp = str(timestamp)

    try:
        return datetime.fromisoformat(
            timestamp.replace("Z", "+00:00")
        )
    except ValueError:
        return None


def calculate_correlation_score(alerts):
    """
    Calculate a simple correlation score.

    More alerts and more distinct threat types increase the score.
    """
    if not alerts:
        return 0.0

    alert_count = len(alerts)

    threat_types = {
        alert["threat_type"]
        for alert in alerts
        if alert["threat_type"]
    }

    score = 0.4

    score += min(0.3, (alert_count - 1) * 0.1)
    score += min(0.3, (len(threat_types) - 1) * 0.15)

    return round(min(score, 1.0), 3)


def get_severity(score):
    """Convert correlation score into severity."""
    if score >= 0.8:
        return "HIGH"

    if score >= 0.6:
        return "MEDIUM"

    return "LOW"


def correlate_alerts(time_window=DEFAULT_TIME_WINDOW):
    """
    Find alerts from the same source IP occurring within
    the configured time window and create correlated alerts.
    """

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            id,
            timestamp,
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            protocol,
            threat_type,
            confidence,
            severity,
            evidence,
            detection_source
        FROM alerts
        ORDER BY timestamp
    """)

    rows = cursor.fetchall()

    alerts = []

    for row in rows:
        alerts.append({
            "id": row[0],
            "timestamp": row[1],
            "source_ip": row[2],
            "destination_ip": row[3],
            "source_port": row[4],
            "destination_port": row[5],
            "protocol": row[6],
            "threat_type": row[7],
            "confidence": row[8],
            "severity": row[9],
            "evidence": row[10],
            "detection_source": row[11],
            "_datetime": parse_timestamp(row[1])
        })

    groups = {}

    for alert in alerts:
        source_ip = alert["source_ip"]

        if not source_ip or alert["_datetime"] is None:
            continue

        added_to_group = False

        for group in groups.get(source_ip, []):
            last_alert = group[-1]

            time_difference = (
                alert["_datetime"] - last_alert["_datetime"]
            ).total_seconds()

            if time_difference <= time_window:
                group.append(alert)
                added_to_group = True
                break

        if not added_to_group:
            groups.setdefault(source_ip, []).append([alert])

    correlated_count = 0

    for source_ip, source_groups in groups.items():

        for group in source_groups:

            # At least two suspicious alerts are required.
            if len(group) < 2:
                continue

            score = calculate_correlation_score(group)
            severity = get_severity(score)

            timestamps = [
                alert["_datetime"]
                for alert in group
                if alert["_datetime"] is not None
            ]

            start_time = min(timestamps)
            end_time = max(timestamps)

            actual_window = int(
                (end_time - start_time).total_seconds()
            )

            threat_types = sorted({
                alert["threat_type"]
                for alert in group
                if alert["threat_type"]
            })

            threat_type_text = ", ".join(threat_types)

            # Check whether this correlation already exists.
            existing = cursor.execute("""
                SELECT id
                FROM correlated_alerts
                WHERE timestamp = ?
                  AND source_ip = ?
                  AND threat_type = ?
            """, (
                start_time.isoformat(),
                source_ip,
                threat_type_text
            )).fetchone()

            if existing:
                continue

            evidence = {
                "alert_count": len(group),
                "threat_types": threat_types,
                "alerts": [
                    {
                        "id": alert["id"],
                        "threat_type": alert["threat_type"],
                        "confidence": alert["confidence"],
                        "severity": alert["severity"],
                        "destination_ip": alert["destination_ip"]
                    }
                    for alert in group
                ]
            }

            cursor.execute("""
                INSERT INTO correlated_alerts (
                    timestamp,
                    source_ip,
                    threat_type,
                    correlation_score,
                    severity,
                    time_window,
                    evidence
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                start_time.isoformat(),
                source_ip,
                threat_type_text,
                score,
                severity,
                actual_window,
                str(evidence)
            ))

            correlated_count += 1

    conn.commit()
    conn.close()

    return correlated_count


if __name__ == "__main__":
    count = correlate_alerts()

    print(
        f"Correlation complete. "
        f"Created {count} correlated alert(s)."
    )