from pathlib import Path
import pandas as pd
import json

from src.database import initialize_database, insert_alert
from src.alert_generator import create_alert

def export_alerts_json(alerts, output_path):
    """Export structured alerts to JSON."""
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(alerts, f, indent=4, default=str)


def export_flow_results(results, source_file=None):
    """
    Convert flow-analyzer results into standardized alerts
    and store confirmed alerts in SQLite.

    Handles:
    - SYN_FLOOD
    - UDP_FLOOD
    - SLOWLORIS
    - ANOMALY

    BENIGN results are ignored.
    """

    initialize_database()

    standard_alerts = []

    for result in results:

        threat_type = result.get(
            "threat_type",
            "BENIGN"
        )

        if threat_type == "BENIGN":
            continue

        alert = create_alert(result)

        standard_alerts.append(alert)

        insert_alert(alert)

    if source_file:

        flow_alerts_file = (
            OUTPUT_DIR / "flow_alerts.csv"
        )

        if standard_alerts:
            pd.DataFrame(
                standard_alerts
            ).to_csv(
                flow_alerts_file,
                index=False
            )

        flow_json_file = (
            OUTPUT_DIR / "flow_alerts.json"
        )

        export_alerts_json(
            standard_alerts,
            flow_json_file
        )

    return standard_alerts
    """
    Convert flow-analyzer results into standardized alerts
    and store confirmed alerts in SQLite.
    Handles:
    - SYN_FLOOD
    - UDP_FLOOD
    - SLOWLORIS

    BENIGN results are ignored.
    """
    initialize_database()

    standard_alerts = []

    for result in results:
        threat_type = result.get("threat_type", "BENIGN")

        if threat_type == "BENIGN":
            continue

        alert = create_alert(result)
        standard_alerts.append(alert)

        insert_alert(alert)

    # Save flow alerts separately for now.
    # The final pipeline can combine these with DNS alerts.
    if source_file:
        flow_alerts_file = (
            OUTPUT_DIR / "flow_alerts.csv"
        )

        if standard_alerts:
            pd.DataFrame(standard_alerts).to_csv(
                flow_alerts_file,
                index=False
            )

        flow_json_file = (
            OUTPUT_DIR / "flow_alerts.json"
        )

        export_alerts_json(
            standard_alerts,
            flow_json_file
        )

    return standard_alerts


BASE_DIR = Path(__file__).resolve().parent.parent

OUTPUT_DIR = BASE_DIR / "outputs"
OUTPUT_DIR.mkdir(exist_ok=True)


# ============================================================
# CONFIDENCE THRESHOLDS
# ============================================================

DGA_ALERT_THRESHOLD = 0.70
DNS_TUNNEL_ALERT_THRESHOLD = 0.80


def get_severity(confidence, is_alert):
    """Determine alert severity from confidence."""
    if not is_alert:
        return "NONE"

    if confidence >= 0.90:
        return "HIGH"

    elif confidence >= 0.80:
        return "MEDIUM"

    return "LOW"


def export_results(results, source_file):
    """
    Save DNS analysis results and confidence-filtered
    DGA/DNS tunnel alerts as CSV, JSON, and SQLite records.
    """
    initialize_database()

    if not results:
        print("No results to export.")
        return

    # =========================================================
    # CONVERT RESULTS INTO DATAFRAME
    # =========================================================

    df = pd.DataFrame(results)

    df["timestamp"] = pd.to_datetime(
        df["timestamp"],
        unit="s",
        errors="coerce"
    )

    # Add source information
    df["source_file"] = Path(source_file).name

    # =========================================================
    # ALERT DECISIONS
    # =========================================================

    df["dga_alert"] = (
        (df["dga_prediction"] == "DGA")
        &
        (df["dga_confidence"] >= DGA_ALERT_THRESHOLD)
    )

    df["dns_tunnel_alert"] = (
        (df["dns_tunnel_prediction"] == "DNS_TUNNEL")
        &
        (
            df["dns_tunnel_confidence"]
            >= DNS_TUNNEL_ALERT_THRESHOLD
        )
    )

    # Final alert decision
    df["is_alert"] = (
        df["dga_alert"]
        |
        df["dns_tunnel_alert"]
    )

    # =========================================================
    # THREAT CATEGORY
    # =========================================================

    def get_threat_category(row):

        if (
            row["dga_alert"]
            and row["dns_tunnel_alert"]
        ):
            return "DGA_AND_DNS_TUNNEL"

        elif row["dns_tunnel_alert"]:
            return "DNS_TUNNEL"

        elif row["dga_alert"]:
            return "DGA"

        return "BENIGN"

    df["threat_category"] = df.apply(
        get_threat_category,
        axis=1
    )

    # =========================================================
    # FINAL CONFIDENCE
    # =========================================================

    df["final_confidence"] = df.apply(
        lambda row: max(
            row["dga_confidence"]
            if row["dga_alert"] else 0,

            row["dns_tunnel_confidence"]
            if row["dns_tunnel_alert"] else 0
        ),
        axis=1
    )

    df["final_confidence"] = (
        df["final_confidence"].round(4)
    )

    # =========================================================
    # SEVERITY
    # =========================================================

    df["severity"] = df.apply(
        lambda row: get_severity(
            row["final_confidence"],
            row["is_alert"]
        ),
        axis=1
    )

    # =========================================================
    # SAVE ALL RESULTS
    # =========================================================

    analysis_file = (
        OUTPUT_DIR
        / "analysis_results.csv"
    )

    df.to_csv(
        analysis_file,
        index=False
    )

    print("\nAll results saved successfully!")
    print("Location:", analysis_file)

    # =========================================================
    # CONFIRMED ALERTS
    # =========================================================

    alerts_df = df[
        df["is_alert"] == True
    ].copy()

    alerts_file = (
        OUTPUT_DIR
        / "alerts.csv"
    )

    standard_alerts = []

    for _, row in alerts_df.iterrows():

        alert = {
            "timestamp": str(row.get("timestamp")),
            "source_ip": row.get("source_ip"),
            "destination_ip": row.get("destination_ip"),
            "source_port": row.get("source_port"),
            "destination_port": row.get("destination_port"),
            "protocol": row.get("protocol", "DNS"),
            "threat_type": row.get("threat_category"),
            "confidence": row.get("final_confidence"),
            "severity": row.get("severity"),

            "evidence": {
                "query": row.get("query"),
                "dga_prediction": row.get(
                    "dga_prediction"
                ),
                "dns_tunnel_prediction": row.get(
                    "dns_tunnel_prediction"
                ),
                "entropy": row.get("entropy"),
                "query_length": row.get(
                    "query_length"
                ),
                "subdomain_length": row.get(
                    "subdomain_length"
                ),
                "digit_ratio": row.get(
                    "digit_ratio"
                )
            },

            "detection_source": "DGA/DNS Tunnel"
        }

        standard_alerts.append(alert)

    alerts_df.to_csv(
        alerts_file,
        index=False
    )

    # =========================================================
    # JSON EXPORT
    # =========================================================

    json_path = (
        OUTPUT_DIR / "alerts.json"
    )

    export_alerts_json(
        standard_alerts,
        json_path
    )

    # =========================================================
    # SQLITE INSERTION
    # =========================================================

    for alert in standard_alerts:
        insert_alert(alert)

    # =========================================================
    # SUMMARY
    # =========================================================

    print("\nConfirmed alerts saved successfully!")
    print("Location:", alerts_file)

    print("\nSummary:")
    print(
        "Total DNS events:",
        len(df)
    )

    print(
        "DGA alert events:",
        df["dga_alert"].sum()
    )

    print(
        "DNS tunnel alert events:",
        df["dns_tunnel_alert"].sum()
    )

    print(
        "Total suspicious events:",
        len(alerts_df)
    )

    print(
        "Unique suspicious queries:",
        alerts_df["query"].nunique()
    )

    # =========================================================
    # CREATE SUMMARY REPORT
    # =========================================================

    summary_data = {
        "Metric": [
            "Source File",
            "Total DNS Events",
            "DGA Alert Events",
            "DNS Tunnel Alert Events",
            "Total Suspicious Events",
            "Unique Suspicious Queries"
        ],

        "Value": [
            Path(source_file).name,
            len(df),
            int(df["dga_alert"].sum()),
            int(df["dns_tunnel_alert"].sum()),
            len(alerts_df),
            alerts_df["query"].nunique()
        ]
    }

    summary_df = pd.DataFrame(
        summary_data
    )

    summary_file = (
        OUTPUT_DIR
        / "analysis_summary.csv"
    )

    summary_df.to_csv(
        summary_file,
        index=False
    )

    print(
        "\nAnalysis summary saved successfully!"
    )

    print(
        "Location:",
        summary_file
    )