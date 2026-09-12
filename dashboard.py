import streamlit as st
import pandas as pd
from pathlib import Path
import sys

from src.pcap_analyzer import analyze_pcap, analyze_csv
from src.export_results import export_results
from src.database import initialize_database, get_connection
from src.correlation_engine import correlate_alerts


# =========================================================
# PATHS
# =========================================================

BASE_DIR = Path(__file__).resolve().parent

SRC_DIR = BASE_DIR / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.append(str(SRC_DIR))

OUTPUT_DIR = BASE_DIR / "outputs"

STATIC_DATA_DIR = (
    BASE_DIR
    / "datasets"
    / "static"
)

RAW_DATA_DIR = (
    BASE_DIR
    / "datasets"
    / "raw"
)

SUMMARY_FILE = OUTPUT_DIR / "analysis_summary.csv"
ALERTS_FILE = OUTPUT_DIR / "alerts.csv"
RESULTS_FILE = OUTPUT_DIR / "analysis_results.csv"
JSON_ALERTS_FILE = OUTPUT_DIR / "alerts.json"


# =========================================================
# DATABASE
# =========================================================

initialize_database()


def load_database_alerts():
    """Load standardized alerts from SQLite."""

    conn = get_connection()

    try:
        query = """
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
            ORDER BY id DESC
        """

        return pd.read_sql_query(query, conn)

    finally:
        conn.close()


def load_correlated_alerts():
    """Load correlated alerts from SQLite."""

    conn = get_connection()

    try:
        query = """
            SELECT
                id,
                timestamp,
                source_ip,
                threat_type,
                correlation_score,
                severity,
                time_window,
                evidence
            FROM correlated_alerts
            ORDER BY id DESC
        """

        return pd.read_sql_query(query, conn)

    finally:
        conn.close()


# =========================================================
# PAGE CONFIGURATION
# =========================================================

st.set_page_config(
    page_title="SENTINELFLOW",
    page_icon="Shield",
    layout="wide"
)


# =========================================================
# SIDEBAR
# =========================================================

st.sidebar.title("SENTINELFLOW")

st.sidebar.write(
    "AI-powered cybersecurity threat detection and analysis."
)

st.sidebar.divider()

st.sidebar.subheader("Detection Modules")

st.sidebar.write("- DGA Detection")
st.sidebar.write("- DNS Tunnelling Detection")
st.sidebar.write("- Alert Correlation")
st.sidebar.write("- SQLite Alert Storage")

st.sidebar.divider()

st.sidebar.subheader("Output Files")

st.sidebar.write("- analysis_results.csv")
st.sidebar.write("- alerts.csv")
st.sidebar.write("- alerts.json")
st.sidebar.write("- analysis_summary.csv")
st.sidebar.write("- sentinelflow.db")

st.sidebar.divider()

st.sidebar.subheader("Analysis Mode")

analysis_mode = st.sidebar.radio(
    "Choose input type:",
    [
        "PCAP / PCAPNG",
        "Static CSV"
    ]
)


# =========================================================
# TITLE
# =========================================================

st.title("SENTINELFLOW")

st.write(
    "AI-powered detection of DGA domains, DNS tunnelling activity, "
    "and correlated suspicious behaviour."
)


# =========================================================
# RUN PCAP ANALYSIS
# =========================================================

st.divider()

st.subheader("Run PCAP Analysis")

pcap_files = list(
    RAW_DATA_DIR.glob("*.pcap")
)

pcap_files += list(
    RAW_DATA_DIR.glob("*.pcapng")
)

if not pcap_files:

    st.warning("No PCAP files found in datasets/raw.")

else:

    selected_file = st.selectbox(
        "Select a PCAP file",
        pcap_files,
        format_func=lambda file: file.name
    )

    if st.button("Run PCAP Analysis"):

        with st.spinner(
            "Analyzing network traffic..."
        ):

            results = analyze_pcap(
                selected_file
            )

            export_results(
                results,
                selected_file
            )

            # Run correlation after alerts have been
            # inserted into SQLite.
            correlated_count = correlate_alerts()

        st.success(
            f"Analysis completed for "
            f"{selected_file.name}"
        )

        st.info(
            f"New correlated alerts created: "
            f"{correlated_count}"
        )

        st.rerun()


# =========================================================
# RUN STATIC CSV ANALYSIS
# =========================================================

if analysis_mode == "Static CSV":

    st.divider()

    st.subheader("Run Static CSV Analysis")

    csv_files = list(
        STATIC_DATA_DIR.glob("*.csv")
    )

    if not csv_files:

        st.warning(
            "No CSV files found in datasets/static."
        )

    else:

        selected_csv = st.selectbox(
            "Select a CSV file",
            csv_files,
            format_func=lambda file: file.name
        )

        if st.button("Run CSV Analysis"):

            with st.spinner(
                "Analyzing static DNS queries..."
            ):

                results = analyze_csv(
                    selected_csv
                )

                export_results(
                    results,
                    selected_csv
                )

                correlated_count = correlate_alerts()

            st.success(
                f"Analysis completed for "
                f"{selected_csv.name}"
            )

            st.info(
                f"New correlated alerts created: "
                f"{correlated_count}"
            )

            st.rerun()


# =========================================================
# LOAD SUMMARY
# =========================================================

summary = {}

if SUMMARY_FILE.exists():

    summary_df = pd.read_csv(
        SUMMARY_FILE
    )

    if (
        "Metric" in summary_df.columns
        and "Value" in summary_df.columns
    ):

        summary = dict(
            zip(
                summary_df["Metric"],
                summary_df["Value"]
            )
        )


# =========================================================
# LOAD SQLITE DATA
# =========================================================

alerts_df = load_database_alerts()

correlated_df = load_correlated_alerts()


# =========================================================
# CURRENT ANALYSIS
# =========================================================

source_file = summary.get(
    "Source File",
    "Database / current session"
)

st.caption(
    f"Currently displaying results for: {source_file}"
)


# =========================================================
# DASHBOARD METRICS
# =========================================================

st.subheader("Security Overview")

total_events = int(
    summary.get(
        "Total DNS Events",
        0
    )
)

dga_alerts = len(
    alerts_df[
        alerts_df["threat_type"] == "DGA"
    ]
) if not alerts_df.empty else 0

dns_tunnel_alerts = len(
    alerts_df[
        alerts_df["threat_type"] == "DNS_TUNNEL"
    ]
) if not alerts_df.empty else 0

total_alerts = len(alerts_df)

high_alerts = len(
    alerts_df[
        alerts_df["severity"] == "HIGH"
    ]
) if not alerts_df.empty else 0

col1, col2, col3, col4, col5 = st.columns(5)

with col1:

    st.metric(
        "Total Events",
        total_events
    )

with col2:

    st.metric(
        "Total Alerts",
        total_alerts
    )

with col3:

    st.metric(
        "DGA Alerts",
        dga_alerts
    )

with col4:

    st.metric(
        "DNS Tunnel Alerts",
        dns_tunnel_alerts
    )

with col5:

    st.metric(
        "High Severity",
        high_alerts
    )


# =========================================================
# ALERT DISTRIBUTION
# =========================================================

st.divider()

st.subheader("Alert Distribution")

if alerts_df.empty:

    st.info(
        "No alerts are currently stored in SQLite."
    )

else:

    distribution = (
        alerts_df["threat_type"]
        .value_counts()
        .rename_axis("Threat Type")
        .reset_index(name="Alerts")
    )

    st.bar_chart(
        distribution.set_index("Threat Type")
    )


# =========================================================
# SEVERITY DISTRIBUTION
# =========================================================

if not alerts_df.empty:

    st.subheader("Severity Distribution")

    severity_data = (
        alerts_df["severity"]
        .value_counts()
        .rename_axis("Severity")
        .reset_index(name="Alerts")
    )

    st.bar_chart(
        severity_data.set_index("Severity")
    )


# =========================================================
# DOMAIN ALERTS
# =========================================================

st.divider()

st.subheader("Domain Alerts")

if alerts_df.empty:

    st.info(
        "No domain alerts found."
    )

else:

    filter_options = [
        "All Alerts",
        "DGA",
        "DNS_TUNNEL",
        "HIGH Severity",
        "MEDIUM Severity",
        "LOW Severity"
    ]

    selected_filter = st.selectbox(
        "Filter domain alerts",
        filter_options
    )

    filtered_df = alerts_df.copy()

    if selected_filter == "DGA":

        filtered_df = alerts_df[
            alerts_df["threat_type"] == "DGA"
        ]

    elif selected_filter == "DNS_TUNNEL":

        filtered_df = alerts_df[
            alerts_df["threat_type"] == "DNS_TUNNEL"
        ]

    elif selected_filter == "HIGH Severity":

        filtered_df = alerts_df[
            alerts_df["severity"] == "HIGH"
        ]

    elif selected_filter == "MEDIUM Severity":

        filtered_df = alerts_df[
            alerts_df["severity"] == "MEDIUM"
        ]

    elif selected_filter == "LOW Severity":

        filtered_df = alerts_df[
            alerts_df["severity"] == "LOW"
        ]

    st.dataframe(
        filtered_df,
        use_container_width=True
    )


# =========================================================
# ALERT DETAILS
# =========================================================

if not alerts_df.empty:

    st.divider()

    st.subheader("Alert Details")

    selected_alert_id = st.selectbox(
        "Select alert ID",
        alerts_df["id"].tolist()
    )

    selected_alert = alerts_df[
        alerts_df["id"] == selected_alert_id
    ].iloc[0]

    detail_col1, detail_col2 = st.columns(2)

    with detail_col1:

        st.write(
            "**Threat Type:**",
            selected_alert["threat_type"]
        )

        st.write(
            "**Source IP:**",
            selected_alert["source_ip"]
        )

        st.write(
            "**Destination IP:**",
            selected_alert["destination_ip"]
        )

        st.write(
            "**Protocol:**",
            selected_alert["protocol"]
        )

        st.write(
            "**Detection Source:**",
            selected_alert["detection_source"]
        )

    with detail_col2:

        st.write(
            "**Confidence:**",
            selected_alert["confidence"]
        )

        st.write(
            "**Severity:**",
            selected_alert["severity"]
        )

        st.write(
            "**Timestamp:**",
            selected_alert["timestamp"]
        )

        st.write(
            "**Source Port:**",
            selected_alert["source_port"]
        )

        st.write(
            "**Destination Port:**",
            selected_alert["destination_port"]
        )

    st.write("**Evidence:**")

    st.code(
        str(selected_alert["evidence"]),
        language="json"
    )


# =========================================================
# CORRELATED ALERTS
# =========================================================

st.divider()

st.subheader("Correlated Alerts")

if correlated_df.empty:

    st.info(
        "No correlated alerts are currently stored."
    )

else:

    st.dataframe(
        correlated_df,
        use_container_width=True
    )

    st.subheader("Correlation Details")

    selected_correlation_id = st.selectbox(
        "Select correlation ID",
        correlated_df["id"].tolist()
    )

    selected_correlation = correlated_df[
        correlated_df["id"] == selected_correlation_id
    ].iloc[0]

    corr_col1, corr_col2 = st.columns(2)

    with corr_col1:

        st.write(
            "**Source IP:**",
            selected_correlation["source_ip"]
        )

        st.write(
            "**Threat Types:**",
            selected_correlation["threat_type"]
        )

        st.write(
            "**Severity:**",
            selected_correlation["severity"]
        )

    with corr_col2:

        st.write(
            "**Correlation Score:**",
            selected_correlation["correlation_score"]
        )

        st.write(
            "**Time Window:**",
            f"{selected_correlation['time_window']} seconds"
        )

        st.write(
            "**Timestamp:**",
            selected_correlation["timestamp"]
        )

    st.write("**Correlation Evidence:**")

    st.code(
        str(selected_correlation["evidence"]),
        language="json"
    )


# =========================================================
# DOWNLOAD ALERTS
# =========================================================

st.divider()

st.subheader("Downloads")

download_col1, download_col2, download_col3 = st.columns(3)


with download_col1:

    if not alerts_df.empty:

        sqlite_alert_csv = alerts_df.to_csv(
            index=False
        ).encode("utf-8")

        st.download_button(
            label="Download SQLite Alerts CSV",
            data=sqlite_alert_csv,
            file_name="sqlite_alerts.csv",
            mime="text/csv"
        )


with download_col2:

    if JSON_ALERTS_FILE.exists():

        st.download_button(
            label="Download Alerts JSON",
            data=JSON_ALERTS_FILE.read_bytes(),
            file_name="alerts.json",
            mime="application/json"
        )


with download_col3:

    if RESULTS_FILE.exists():

        st.download_button(
            label="Download Analysis CSV",
            data=RESULTS_FILE.read_bytes(),
            file_name="analysis_results.csv",
            mime="text/csv"
        )


# =========================================================
# ORIGINAL OUTPUT FILES
# =========================================================

st.divider()

st.subheader("Analysis Files")

if ALERTS_FILE.exists():

    st.download_button(
        label="Download alerts.csv",
        data=ALERTS_FILE.read_bytes(),
        file_name="alerts.csv",
        mime="text/csv"
    )

if SUMMARY_FILE.exists():

    st.download_button(
        label="Download analysis_summary.csv",
        data=SUMMARY_FILE.read_bytes(),
        file_name="analysis_summary.csv",
        mime="text/csv"
    )