import streamlit as st
import pandas as pd
from pathlib import Path
import sys
from src.pcap_analyzer import analyze_pcap, analyze_csv

from src.export_results import export_results

SRC_DIR = Path(__file__).resolve().parent / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.append(str(SRC_DIR))




# -------------------------------------------------
# PAGE CONFIGURATION
# -------------------------------------------------

st.set_page_config(
    page_title="AI Cyber Threat Detection",
    page_icon="🛡️",
    layout="wide"
)


# -------------------------------------------------
# PROJECT PATHS
# -------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent

OUTPUT_DIR = BASE_DIR / "outputs"

STATIC_DATA_DIR = BASE_DIR / "datasets" / "static"

SUMMARY_FILE = OUTPUT_DIR / "analysis_summary.csv"
ALERTS_FILE = OUTPUT_DIR / "alerts.csv"
RESULTS_FILE = OUTPUT_DIR / "analysis_results.csv"


# -------------------------------------------------
# SIDEBAR
# -------------------------------------------------

st.sidebar.title("🛡️ Threat Detection")

st.sidebar.write(
    "AI-powered cybersecurity analysis prototype."
)

st.sidebar.divider()

st.sidebar.subheader("Detection Modules")

st.sidebar.write("• DGA Detection")
st.sidebar.write("• DNS Tunnelling Detection")

st.sidebar.divider()

st.sidebar.subheader("Output Files")

st.sidebar.write("📄 analysis_results.csv")
st.sidebar.write("🚨 alerts.csv")
st.sidebar.write("📊 analysis_summary.csv")
st.sidebar.divider()

st.sidebar.subheader("Analysis Mode")

analysis_mode = st.sidebar.radio(
    "Choose input type:",
    [
        "PCAP / PCAPNG",
        "Static CSV"
    ]
)
if analysis_mode == "Static CSV":

    csv_files = list(
        STATIC_DATA_DIR.glob("*.csv")
    )

    if csv_files:

        selected_csv = st.sidebar.selectbox(
            "Select CSV file:",
            csv_files,
            format_func=lambda x: x.name
        )

    else:

        st.sidebar.warning(
            "No CSV files found in datasets/static."
        )


# -------------------------------------------------
# TITLE
# -------------------------------------------------

st.title("🛡️ AI Cyber Threat Detection System")

st.write(
    "AI-powered detection of DGA domains and DNS tunnelling activity."
)
# -------------------------------------------------
# RUN NEW ANALYSIS
# -------------------------------------------------

st.divider()

st.subheader("🔍 Run PCAP Analysis")

RAW_DATA_DIR = (
    BASE_DIR
    / "datasets"
    / "raw"
)

pcap_files = list(RAW_DATA_DIR.glob("*.pcap"))
pcap_files += list(RAW_DATA_DIR.glob("*.pcapng"))

if not pcap_files:

    st.warning("No PCAP files found.")

else:

    selected_file = st.selectbox(
        "Select a PCAP file",
        pcap_files,
        format_func=lambda file: file.name
    )

    if st.button("▶️ Run Analysis"):

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

        st.success(
            f"Analysis completed for "
            f"{selected_file.name}!"
        )

        st.rerun()
        # -------------------------------------------------
# RUN STATIC CSV ANALYSIS
# -------------------------------------------------

if analysis_mode == "Static CSV":

    st.subheader("📄 Run Static CSV Analysis")

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

        if st.button("▶️ Run CSV Analysis"):

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

            st.success(
                f"Analysis completed for "
                f"{selected_csv.name}!"
            )

            st.rerun()


# -------------------------------------------------
# CHECK FOR RESULTS
# -------------------------------------------------

if not SUMMARY_FILE.exists():

    st.warning(
        "No analysis results found. "
        "Run pcap_analyzer.py first."
    )

    st.stop()


# -------------------------------------------------
# LOAD SUMMARY
# -------------------------------------------------

summary_df = pd.read_csv(SUMMARY_FILE)

summary = dict(
    zip(
        summary_df["Metric"],
        summary_df["Value"]
    )
)


# -------------------------------------------------
# CURRENT ANALYSIS
# -------------------------------------------------

source_file = summary.get(
    "Source File",
    "Unknown"
)

st.caption(
    f"Currently displaying analysis results for: {source_file}"
)


# -------------------------------------------------
# DASHBOARD METRICS
# -------------------------------------------------

st.subheader("📊 Analysis Overview")

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric(
        "Total DNS Events",
        summary.get("Total DNS Events", 0)
    )

with col2:
    st.metric(
        "DGA Alerts",
        summary.get("DGA Alert Events", 0)
    )

with col3:
    st.metric(
        "DNS Tunnel Alerts",
        summary.get("DNS Tunnel Alert Events", 0)
    )

with col4:
    st.metric(
        "Suspicious Events",
        summary.get("Total Suspicious Events", 0)
    )


# -------------------------------------------------
# ALERT DISTRIBUTION CHART
# -------------------------------------------------

st.divider()

st.subheader("📈 Alert Distribution")

chart_data = pd.DataFrame(
    {
        "Threat Type": [
            "DGA",
            "DNS Tunnel"
        ],
        "Alerts": [
            int(summary.get("DGA Alert Events", 0)),
            int(
                summary.get(
                    "DNS Tunnel Alert Events",
                    0
                )
            )
        ]
    }
)

st.bar_chart(
    chart_data.set_index("Threat Type")
)


# -------------------------------------------------
# SUSPICIOUS ALERTS
# -------------------------------------------------

st.divider()

st.subheader("🚨 Suspicious DNS Alerts")


if ALERTS_FILE.exists():

    alerts_df = pd.read_csv(ALERTS_FILE)

    # ---------------------------------------------
    # ALERT FILTERS
    # ---------------------------------------------

    filter_options = [
        "All Alerts",
        "DGA Only",
        "DNS Tunnel Only"
    ]

    selected_filter = st.selectbox(
        "Filter alerts",
        filter_options
    )

    filtered_df = alerts_df.copy()

    if selected_filter == "DGA Only":

        filtered_df = alerts_df[
            alerts_df["dga_alert"] == True
        ]

    elif selected_filter == "DNS Tunnel Only":

        filtered_df = alerts_df[
            alerts_df["dns_tunnel_alert"] == True
        ]


    # ---------------------------------------------
    # DISPLAY TABLE
    # ---------------------------------------------

    st.dataframe(
        filtered_df,
        use_container_width=True
    )


    # ---------------------------------------------
    # DOWNLOAD FILTERED ALERTS
    # ---------------------------------------------

    csv_data = filtered_df.to_csv(
        index=False
    ).encode("utf-8")

    st.download_button(
        label="⬇️ Download Filtered Alerts CSV",
        data=csv_data,
        file_name="filtered_alerts.csv",
        mime="text/csv"
    )


else:

    st.info("No alerts found.")


# -------------------------------------------------
# DOWNLOAD ALL RESULTS
# -------------------------------------------------

st.divider()

st.subheader("📥 Download Analysis Results")


if RESULTS_FILE.exists():

    results_data = RESULTS_FILE.read_bytes()

    st.download_button(
        label="⬇️ Download Complete Analysis CSV",
        data=results_data,
        file_name="analysis_results.csv",
        mime="text/csv"
    )


if SUMMARY_FILE.exists():

    summary_data = SUMMARY_FILE.read_bytes()

    st.download_button(
        label="⬇️ Download Analysis Summary CSV",
        data=summary_data,
        file_name="analysis_summary.csv",
        mime="text/csv"
    )