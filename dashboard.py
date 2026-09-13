import ast
import json
from pathlib import Path

import pandas as pd
import streamlit as st

from src.pcap_analyzer import analyze_pcap, analyze_csv
from src.flow_analyzer import analyze_flow_pcap
from src.export_results import export_results, export_flow_results
from src.database import initialize_database, get_connection, clear_analysis_data
from src.correlation_engine import correlate_alerts


# =========================================================
# CYBERDRISTI // CONFIG
# =========================================================

BASE_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = BASE_DIR / "outputs"
STATIC_DATA_DIR = BASE_DIR / "datasets" / "static"
RAW_DATA_DIR = BASE_DIR / "datasets" / "raw"

OUTPUT_DIR.mkdir(exist_ok=True)

SUMMARY_FILE = OUTPUT_DIR / "analysis_summary.csv"
ALERTS_FILE = OUTPUT_DIR / "alerts.csv"
RESULTS_FILE = OUTPUT_DIR / "analysis_results.csv"
JSON_ALERTS_FILE = OUTPUT_DIR / "alerts.json"

THREATS = {
    "SYN_FLOOD": {
        "name": "SYN FLOOD",
        "short": "SYN",
        "family": "FLOW",
        "icon": "◈",
        "desc": "TCP handshake exhaustion / half-open connection surge",
    },
    "UDP_FLOOD": {
        "name": "UDP FLOOD",
        "short": "UDP",
        "family": "FLOW",
        "icon": "◇",
        "desc": "High-volume UDP traffic targeting a service",
    },
    "SLOWLORIS": {
        "name": "SLOWLORIS",
        "short": "SLOW",
        "family": "FLOW",
        "icon": "◌",
        "desc": "Slow HTTP connection exhaustion pattern",
    },
    "ANOMALY": {
        "name": "ANOMALY",
        "short": "AI",
        "family": "AI",
        "icon": "✦",
        "desc": "Isolation Forest behavioral outlier detection",
    },
    "DGA": {
        "name": "DGA",
        "short": "DGA",
        "family": "DNS",
        "icon": "⌁",
        "desc": "Suspicious algorithmically generated domain activity",
    },
    "DNS_TUNNEL": {
        "name": "DNS TUNNELLING",
        "short": "DNS",
        "family": "DNS",
        "icon": "⌬",
        "desc": "Potential covert data transfer over DNS",
    },
}

THREAT_ORDER = list(THREATS)


# =========================================================
# DATABASE
# =========================================================

initialize_database()


def load_database_alerts():
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
# DATA DISCOVERY
# =========================================================

def get_pcap_files():
    files = list(RAW_DATA_DIR.rglob("*.pcap"))
    files += list(RAW_DATA_DIR.rglob("*.pcapng"))
    return sorted(set(files), key=lambda p: str(p).lower())


def get_csv_files():
    return sorted(STATIC_DATA_DIR.glob("*.csv"), key=lambda p: p.name.lower())


def display_path(path):
    try:
        return str(path.relative_to(BASE_DIR))
    except ValueError:
        return path.name


def filter_dns_results(results, enable_dga, enable_dns_tunnel):
    filtered = []

    for result in results:
        result = dict(result)

        if not enable_dga:
            if "dga_prediction" in result:
                result["dga_prediction"] = "BENIGN"
            if "dga_confidence" in result:
                result["dga_confidence"] = 0.0

        if not enable_dns_tunnel:
            if "dns_tunnel_prediction" in result:
                result["dns_tunnel_prediction"] = "BENIGN"
            if "dns_tunnel_confidence" in result:
                result["dns_tunnel_confidence"] = 0.0

        filtered.append(result)

    return filtered


def filter_flow_results(
    results,
    enable_syn,
    enable_udp,
    enable_slowloris,
    enable_anomaly,
):
    allowed = set()

    if enable_syn:
        allowed.add("SYN_FLOOD")
    if enable_udp:
        allowed.add("UDP_FLOOD")
    if enable_slowloris:
        allowed.add("SLOWLORIS")
    if enable_anomaly:
        allowed.add("ANOMALY")

    return [
        result for result in results
        if result.get("threat_type") in allowed
    ]


def threat_label(value):
    value = str(value)
    return THREATS.get(value, {}).get("name", value.replace("_", " "))


def parse_evidence(value):
    if isinstance(value, dict):
        return value

    if value is None:
        return {}

    text = str(value)

    try:
        return json.loads(text)
    except Exception:
        pass

    try:
        parsed = ast.literal_eval(text)
        return parsed if isinstance(parsed, dict) else {"value": parsed}
    except Exception:
        return {"raw": text}


def _pretty_evidence_key(key):
    return str(key).replace("_", " ").replace("-", " ").upper()


def _format_evidence_value(value):
    if isinstance(value, bool):
        return "YES" if value else "NO"
    if value is None:
        return "N/A"
    if isinstance(value, float):
        return f"{value:.4f}" if 0 < abs(value) < 1 else f"{value:.2f}"
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, indent=2, default=str)
    return str(value)


def render_evidence_cards(evidence, incident=None):
    """Render detector/correlation evidence as readable SOC cards."""
    data = parse_evidence(evidence)
    if not isinstance(data, dict):
        data = {"value": data}

    items = []
    if incident is not None:
        items.extend([
            ("SOURCE IP", incident.get("source_ip", "N/A")),
            ("THREAT CHAIN", str(incident.get("threat_type", "N/A")).replace("_", " + ")),
            ("TIME WINDOW", f"{incident.get('time_window', 'N/A')} seconds"),
            ("CORRELATION SCORE", incident.get("correlation_score", "N/A")),
            ("SEVERITY", incident.get("severity", "N/A")),
        ])

    for key, value in data.items():
        label = _pretty_evidence_key(key)
        if incident is not None and label in {
            "SOURCE IP", "THREAT CHAIN", "TIME WINDOW",
            "CORRELATION SCORE", "SEVERITY"
        }:
            continue
        items.append((label, _format_evidence_value(value)))

    if not items:
        st.info("No structured evidence is available for this record.")
        return

    cols_per_row = 3
    for start in range(0, len(items), cols_per_row):
        row = items[start:start + cols_per_row]
        cols = st.columns(cols_per_row)
        for col, (label, value) in zip(cols, row):
            with col:
                safe_value = str(value).replace("<", "&lt;").replace(">", "&gt;")
                st.markdown(
                    f"""
                    <div class=\"evidence-card\">
                        <div class=\"evidence-label\">{label}</div>
                        <div class=\"evidence-value\">{safe_value}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

    if incident is not None:
        signals = str(incident.get("threat_type", "")).replace("_", " + ")
        score = incident.get("correlation_score", "N/A")
        window = incident.get("time_window", "N/A")
        st.markdown(
            f"""
            <div class=\"correlation-explanation\">
                <div class=\"evidence-label\">WHY THIS INCIDENT WAS CORRELATED</div>
                <div class=\"evidence-value\">
                    Multiple suspicious signals ({signals}) were observed for the same source
                    inside a {window}-second window, producing a correlation score of {score}.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with st.expander("RAW EVIDENCE // DEBUG", expanded=False):
        st.json(data)


# =========================================================
# CSS // ORIGINAL ANIME-CYBER SOC THEME
# =========================================================

st.set_page_config(
    page_title="CYBERDRISTI // SOC",
    page_icon="◈",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
<style>
@import url('https://fonts.googleapis.com/css2?family=Rajdhani:wght@400;500;600;700&family=Share+Tech+Mono&display=swap');

:root {
    --bg: #03070d;
    --panel: #07111a;
    --panel2: #0a1721;
    --line: #123442;
    --cyan: #47f3ff;
    --pink: #ff4fd8;
    --violet: #9b6cff;
    --green: #54ff9b;
    --yellow: #ffd45c;
    --red: #ff5575;
    --text: #eafcff;
    --muted: #7895a2;
}

html, body, [class*="css"] {
    font-family: 'Rajdhani', sans-serif;
}

.stApp {
    background:
        radial-gradient(circle at 75% 10%, rgba(71,243,255,.09), transparent 25%),
        radial-gradient(circle at 15% 85%, rgba(255,79,216,.07), transparent 25%),
        linear-gradient(135deg, #02050a 0%, #030a11 55%, #02050a 100%);
    color: var(--text);
}

.stApp:before {
    content: "";
    position: fixed;
    inset: 0;
    pointer-events: none;
    opacity: .13;
    background-image:
        linear-gradient(rgba(71,243,255,.12) 1px, transparent 1px),
        linear-gradient(90deg, rgba(71,243,255,.12) 1px, transparent 1px);
    background-size: 42px 42px;
    mask-image: linear-gradient(to bottom, black, transparent);
}

section[data-testid="stSidebar"] {
    background:
        linear-gradient(180deg, #040a10 0%, #061018 55%, #04080d 100%);
    border-right: 1px solid #123642;
}

section[data-testid="stSidebar"] > div {
    padding-top: 1.2rem;
}

.cyber-logo {
    padding: 8px 0 18px 0;
}

.cyber-mark {
    color: var(--cyan);
    font-size: 1.8rem;
    text-shadow: 0 0 18px rgba(71,243,255,.7);
}

.cyber-name {
    font-family: 'Share Tech Mono', monospace;
    font-size: 2rem;
    font-weight: 700;
    letter-spacing: .08em;
    color: #f3fdff;
    text-shadow:
        2px 0 var(--pink),
        -2px 0 var(--cyan),
        0 0 22px rgba(71,243,255,.35);
}

.cyber-sub {
    color: var(--muted);
    font-size: .82rem;
    letter-spacing: .16em;
    text-transform: uppercase;
}

.nav-caption {
    color: var(--cyan);
    font-family: 'Share Tech Mono', monospace;
    font-size: .72rem;
    letter-spacing: .16em;
    margin: 18px 0 7px;
}

div[data-testid="stRadio"] label {
    border-radius: 8px;
    padding: 6px 8px;
    transition: .2s ease;
}

div[data-testid="stRadio"] label:hover {
    background: rgba(71,243,255,.08);
}

div[data-testid="stButton"] button,
.stDownloadButton button {
    border: 1px solid #1a6675 !important;
    background: linear-gradient(135deg, #07151e, #0b202a) !important;
    color: var(--cyan) !important;
    font-family: 'Share Tech Mono', monospace !important;
    letter-spacing: .04em;
    box-shadow: 0 0 16px rgba(71,243,255,.08);
}

div[data-testid="stButton"] button:hover,
.stDownloadButton button:hover {
    border-color: var(--cyan) !important;
    box-shadow: 0 0 22px rgba(71,243,255,.22);
}

div[data-testid="stMetric"] {
    background: linear-gradient(145deg, rgba(8,22,31,.94), rgba(3,10,16,.94));
    border: 1px solid #123846;
    border-radius: 12px;
    padding: 16px;
    box-shadow: inset 0 0 22px rgba(71,243,255,.025);
}

div[data-testid="stMetricLabel"] {
    color: #70a8b7 !important;
    font-family: 'Share Tech Mono', monospace;
    letter-spacing: .06em;
}

div[data-testid="stMetricValue"] {
    color: #efffff !important;
    text-shadow: 0 0 14px rgba(71,243,255,.25);
}

.cyber-hero {
    position: relative;
    overflow: hidden;
    border: 1px solid #155063;
    border-radius: 18px;
    padding: 28px 30px;
    margin: 4px 0 22px;
    background:
        linear-gradient(120deg, rgba(5,24,33,.96), rgba(6,12,22,.96)),
        repeating-linear-gradient(0deg, transparent, transparent 3px, rgba(71,243,255,.03) 4px);
    box-shadow:
        0 0 45px rgba(71,243,255,.06),
        inset 0 0 35px rgba(155,108,255,.035);
}

.cyber-hero:after {
    content: "電脳 // THREAT INTELLIGENCE // ONLINE";
    position: absolute;
    right: 24px;
    top: 18px;
    color: rgba(71,243,255,.42);
    font-family: 'Share Tech Mono', monospace;
    font-size: .68rem;
    letter-spacing: .12em;
}

.hero-kicker {
    color: var(--pink);
    font-family: 'Share Tech Mono', monospace;
    letter-spacing: .18em;
    font-size: .75rem;
}

.hero-title {
    font-family: 'Share Tech Mono', monospace;
    font-size: 3.1rem;
    line-height: 1;
    margin: 7px 0;
    letter-spacing: .07em;
    text-shadow: 2px 0 var(--pink), -2px 0 var(--cyan);
}

.hero-desc {
    color: #89aab5;
    max-width: 780px;
    font-size: 1rem;
}

.status-chip {
    display: inline-block;
    border: 1px solid rgba(84,255,155,.35);
    color: var(--green);
    background: rgba(84,255,155,.06);
    padding: 5px 10px;
    border-radius: 999px;
    font-family: 'Share Tech Mono', monospace;
    font-size: .72rem;
    letter-spacing: .08em;
}

.section-head {
    display: flex;
    align-items: center;
    gap: 10px;
    margin: 24px 0 10px;
    color: #ecfdff;
    font-family: 'Share Tech Mono', monospace;
    letter-spacing: .06em;
}

.section-head span {
    color: var(--cyan);
}

.threat-card {
    min-height: 176px;
    border: 1px solid #123744;
    border-radius: 14px;
    padding: 18px;
    margin-bottom: 12px;
    background:
        linear-gradient(145deg, rgba(8,24,34,.95), rgba(4,11,17,.96));
    box-shadow: inset 0 0 25px rgba(71,243,255,.025);
    position: relative;
    overflow: hidden;
    transition: transform .25s ease, border-color .25s ease, box-shadow .25s ease;
}

.threat-card:hover {
    transform: translateY(-8px) scale(1.035);
    border-color: var(--cyan);
    box-shadow:
        0 12px 30px rgba(71,243,255,.18),
        0 0 24px rgba(255,79,216,.10),
        inset 0 0 30px rgba(71,243,255,.06);
    z-index: 10;
}

.threat-card:before {
    content: "";
    position: absolute;
    left: 0;
    top: 0;
    width: 3px;
    height: 100%;
    background: linear-gradient(var(--cyan), var(--pink));
    box-shadow: 0 0 16px rgba(71,243,255,.45);
}

.threat-icon {
    color: var(--cyan);
    font-size: 1.6rem;
}

.threat-title {
    font-family: 'Share Tech Mono', monospace;
    font-size: 1rem;
    letter-spacing: .08em;
}

.threat-desc {
    color: #6f909d;
    font-size: .82rem;
}

.threat-count {
    font-family: 'Share Tech Mono', monospace;
    font-size: 2rem;
    color: #efffff;
}

.mini-tag {
    color: #77a9b6;
    font-family: 'Share Tech Mono', monospace;
    font-size: .65rem;
    letter-spacing: .08em;
}

.soc-panel {
    border: 1px solid #113542;
    border-radius: 14px;
    padding: 18px;
    background: rgba(5,15,22,.78);
    box-shadow: inset 0 0 24px rgba(71,243,255,.025);
    position: relative; overflow: hidden;
    transition: transform .25s ease, border-color .25s ease, box-shadow .25s ease;
}

.soc-panel:hover {
    transform: translateY(-6px) scale(1.018); border-color: var(--cyan); z-index:10;
    box-shadow: 0 10px 28px rgba(71,243,255,.14), 0 0 20px rgba(255,79,216,.07), inset 0 0 26px rgba(71,243,255,.045);
}

.signal {
    color: var(--green);
    font-family: 'Share Tech Mono', monospace;
}

.danger {
    color: var(--red);
}

.warn {
    color: var(--yellow);
}

.muted {
    color: var(--muted);
}

[data-testid="stMetric"] { border:1px solid #113542; border-radius:12px; padding:12px 14px; background:rgba(5,15,22,.68); transition:transform .25s ease,border-color .25s ease,box-shadow .25s ease; position:relative; z-index:1; }
[data-testid="stMetric"]:hover { transform:translateY(-6px) scale(1.025); border-color:var(--cyan); box-shadow:0 10px 26px rgba(71,243,255,.15),0 0 20px rgba(255,79,216,.08); z-index:20; }
.evidence-card { min-height:92px; border:1px solid #123744; border-radius:12px; padding:14px; margin-bottom:10px; background:linear-gradient(145deg,rgba(8,24,34,.92),rgba(4,11,17,.96)); transition:transform .22s ease,border-color .22s ease,box-shadow .22s ease; }
.evidence-card:hover { transform:translateY(-5px) scale(1.018); border-color:var(--cyan); box-shadow:0 8px 24px rgba(71,243,255,.12),0 0 18px rgba(255,79,216,.07); }
.evidence-label { color:#5d8794; font-family:'Share Tech Mono',monospace; font-size:.65rem; letter-spacing:.10em; }
.evidence-value { color:#eaffff; font-family:'Share Tech Mono',monospace; font-size:.95rem; margin-top:5px; word-break:break-word; }
.correlation-explanation { margin:4px 0 14px; padding:16px; border:1px solid #264653; border-radius:12px; background:linear-gradient(145deg,rgba(9,27,38,.94),rgba(4,12,18,.96)); box-shadow:inset 0 0 24px rgba(71,243,255,.025); transition:transform .22s ease,border-color .22s ease,box-shadow .22s ease; }
.correlation-explanation:hover { transform:translateY(-5px); border-color:var(--cyan); box-shadow:0 8px 24px rgba(71,243,255,.12),0 0 18px rgba(255,79,216,.07); }

div[data-testid="stDataFrame"] {
    border: 1px solid #123744;
    border-radius: 10px;
}

.stAlert {
    border-radius: 10px;
}

footer {
    visibility: hidden;
}

#MainMenu {
    visibility: hidden;
}
</style>
""",
    unsafe_allow_html=True,
)


# =========================================================
# SIDEBAR NAVIGATION
# =========================================================

with st.sidebar:
    st.markdown(
        """
        <div class="cyber-logo">
            <div class="cyber-mark">◈</div>
            <div class="cyber-name">CYBERDRISTI</div>
            <div class="cyber-sub">AI-POWERED SECURITY OPERATIONS CENTER</div>
            <div class="cyber-sub" style="margin-top:8px;color:#3f7180;">
                NETWORK THREAT DETECTION // RESPONSE
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.divider()

    st.markdown('<div class="nav-caption">CORE SYSTEM</div>', unsafe_allow_html=True)

    page = st.radio(
        "Navigation",
        [
            "SOC Overview",
            "Detection Center",
            "Threat Analysis",
            "Correlated Incidents",
            "Alert Database",
            "Exports",
        ],
        label_visibility="collapsed",
    )

    st.markdown('<div class="nav-caption">SYSTEM STATUS</div>', unsafe_allow_html=True)

    st.markdown(
        """
        <div class="soc-panel">
            <div class="signal">● FLOW ENGINE &nbsp; ONLINE</div>
            <div class="signal">● DNS ENGINE &nbsp;&nbsp; ONLINE</div>
            <div class="signal">● AI ANOMALY &nbsp;&nbsp; ONLINE</div>
            <div class="signal">● ALERT ENGINE &nbsp; ONLINE</div>
            <div class="signal">● SQLITE &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; ONLINE</div>
            <div class="signal">● CORRELATION &nbsp; ONLINE</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown('<div class="nav-caption">THREAT MATRIX</div>', unsafe_allow_html=True)

    for key in THREAT_ORDER:
        t = THREATS[key]
        st.caption(f"{t['icon']} {t['name']}  //  {t['family']}")


# =========================================================
# LOAD DATA
# =========================================================

try:
    alerts_df = load_database_alerts()
except Exception as error:
    st.error(f"Could not load SQLite alerts: {error}")
    alerts_df = pd.DataFrame()

try:
    correlated_df = load_correlated_alerts()
except Exception as error:
    st.error(f"Could not load correlated alerts: {error}")
    correlated_df = pd.DataFrame()

summary = {}

if SUMMARY_FILE.exists():
    try:
        summary_df = pd.read_csv(SUMMARY_FILE)
        if {"Metric", "Value"}.issubset(summary_df.columns):
            summary = dict(zip(summary_df["Metric"], summary_df["Value"]))
    except Exception:
        summary = {}


# =========================================================
# HERO
# =========================================================

st.markdown(
    """
    <div class="cyber-hero">
        <div class="hero-kicker">PROJECT // SIH26145 // CYBER DEFENSE GRID</div>
        <div class="hero-title">CYBERDRISTI</div>
        <div class="hero-desc">
            Anime-inspired security operations console for flow analysis,
            DNS intelligence, AI anomaly detection, alert generation,
            SQLite persistence, and multi-signal correlation.
        </div>
        <br>
        <span class="status-chip">● ALL DETECTION SERVICES OPERATIONAL</span>
    </div>
    """,
    unsafe_allow_html=True,
)


# =========================================================
# SOC OVERVIEW
# =========================================================

if page == "SOC Overview":
    st.markdown(
        '<div class="section-head"><span>◈</span> COMMAND CENTER // LIVE SECURITY OVERVIEW</div>',
        unsafe_allow_html=True,
    )

    total_alerts = len(alerts_df)
    high_alerts = (
        int((alerts_df["severity"] == "HIGH").sum())
        if not alerts_df.empty and "severity" in alerts_df
        else 0
    )
    medium_alerts = (
        int((alerts_df["severity"] == "MEDIUM").sum())
        if not alerts_df.empty and "severity" in alerts_df
        else 0
    )
    low_alerts = (
        int((alerts_df["severity"] == "LOW").sum())
        if not alerts_df.empty and "severity" in alerts_df
        else 0
    )

    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.metric("TOTAL ALERTS", total_alerts)
    with m2:
        st.metric("HIGH SEVERITY", high_alerts)
    with m3:
        st.metric("MEDIUM SEVERITY", medium_alerts)
    with m4:
        st.metric("CORRELATED INCIDENTS", len(correlated_df))

    st.markdown(
        '<div class="section-head"><span>✦</span> THREAT MATRIX</div>',
        unsafe_allow_html=True,
    )

    counts = (
        alerts_df["threat_type"].value_counts()
        if not alerts_df.empty and "threat_type" in alerts_df
        else pd.Series(dtype=int)
    )

    card_cols = st.columns(3)

    for index, key in enumerate(THREAT_ORDER):
        t = THREATS[key]
        count = int(counts.get(key, 0))

        with card_cols[index % 3]:
            st.markdown(
                f"""
                <div class="threat-card">
                    <div class="threat-icon">{t['icon']}</div>
                    <div class="threat-title">{t['name']}</div>
                    <div class="mini-tag">{t['family']} DETECTOR</div>
                    <div class="threat-count">{count:,}</div>
                    <div class="threat-desc">{t['desc']}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    st.markdown(
        '<div class="section-head"><span>⌁</span> THREAT DISTRIBUTION</div>',
        unsafe_allow_html=True,
    )

    if counts.empty:
        st.info("No stored alerts yet. Run an analysis from Detection Center.")
    else:
        distribution = counts.rename("Alerts").to_frame()
        distribution.index = [
            threat_label(index) for index in distribution.index
        ]
        st.bar_chart(distribution)

    if not alerts_df.empty:
        st.markdown(
            '<div class="section-head"><span>◌</span> RECENT SECURITY EVENTS</div>',
            unsafe_allow_html=True,
        )
        recent = alerts_df.head(10).copy()
        recent["threat_type"] = recent["threat_type"].map(threat_label)
        st.dataframe(
            recent[
                [
                    "id",
                    "timestamp",
                    "source_ip",
                    "destination_ip",
                    "threat_type",
                    "confidence",
                    "severity",
                    "detection_source",
                ]
            ],
            use_container_width=True,
            hide_index=True,
        )


# =========================================================
# DETECTION CENTER
# =========================================================

elif page == "Detection Center":
    st.markdown(
        '<div class="section-head"><span>◈</span> DETECTION CENTER // ANALYSIS CONTROL</div>',
        unsafe_allow_html=True,
    )

    input_mode = st.radio(
        "Input channel",
        ["PCAP / PCAPNG", "Static CSV"],
        horizontal=True,
    )

    st.markdown(
        '<div class="soc-panel">',
        unsafe_allow_html=True,
    )

    if input_mode == "PCAP / PCAPNG":
        pcap_files = get_pcap_files()

        if not pcap_files:
            st.warning("No PCAP/PCAPNG files found in datasets/raw.")
        else:
            selected_file = st.selectbox(
                "TARGET CAPTURE",
                pcap_files,
                format_func=display_path,
            )

            st.caption(f"Target: {display_path(selected_file)}")

            st.markdown("**ACTIVE DETECTORS**")

            c1, c2, c3, c4, c5, c6 = st.columns(6)
            with c1:
                syn = st.checkbox("SYN", value=True)
            with c2:
                udp = st.checkbox("UDP", value=True)
            with c3:
                slow = st.checkbox("SLOW", value=True)
            with c4:
                anomaly = st.checkbox("AI", value=True)
            with c5:
                dga = st.checkbox("DGA", value=True)
            with c6:
                tunnel = st.checkbox("DNS", value=True)

            if st.button("⚡ EXECUTE ANALYSIS", type="primary", use_container_width=True):
                # Do not silently do nothing when every detector is disabled.
                if not (syn or udp or slow or anomaly or dga or tunnel):
                    st.warning(
                        "⚠️ Select at least one detection engine before executing analysis."
                    )
                    st.stop()

                clear_analysis_data()

                # Always initialize result counters before any detector runs.
                flow_count = 0
                dns_count = 0
                correlation_count = 0

                with st.spinner("CYBERDRISTI neural analysis in progress..."):
                    # -------------------------------
                    # DNS ANALYSIS
                    # -------------------------------
                    if dga or tunnel:
                        try:
                            dns_results = analyze_pcap(selected_file)
                            dns_results = filter_dns_results(
                                dns_results, dga, tunnel
                            )
                            export_results(dns_results, selected_file)
                            dns_count = sum(
                                1
                                for result in dns_results
                                if (
                                    result.get("dga_prediction") == "DGA"
                                    or result.get("dns_tunnel_prediction") == "DNS_TUNNEL"
                                )
                            )
                        except Exception as error:
                            st.error(f"DNS analysis failed: {error}")

                    # -------------------------------
                    # FLOW ANALYSIS
                    # -------------------------------
                    if syn or udp or slow or anomaly:
                        try:
                            # Pass detector toggles into the analyzer so disabled
                            # engines are not executed.
                            flow_results = analyze_flow_pcap(
                                selected_file,
                                syn,
                                udp,
                                slow,
                                anomaly,
                            )
                            flow_results = filter_flow_results(
                                flow_results,
                                syn,
                                udp,
                                slow,
                                anomaly,
                            )
                            flow_alerts = export_flow_results(
                                flow_results, selected_file
                            )
                            flow_count = len(flow_alerts)
                        except Exception as error:
                            st.error(f"Flow analysis failed: {error}")

                    # -------------------------------
                    # CORRELATION
                    # -------------------------------
                    try:
                        correlation_count = correlate_alerts()
                    except Exception as error:
                        st.error(f"Correlation failed: {error}")

                st.success(f"Analysis complete // {selected_file.name}")
                st.info(
                    f"FLOW ALERTS: {flow_count}  |  DNS ALERT EVENTS: {dns_count}  |  "
                    f"NEW CORRELATIONS: {correlation_count}"
                )
                #st.rerun()

    else:
        csv_files = get_csv_files()

        if not csv_files:
            st.warning("No CSV files found in datasets/static.")
        else:
            selected_csv = st.selectbox(
                "TARGET DATASET",
                csv_files,
                format_func=lambda p: p.name,
            )

            dga = st.checkbox("DGA", value=True)
            tunnel = st.checkbox("DNS Tunnelling", value=True)

            if st.button("⚡ EXECUTE CSV ANALYSIS", type="primary"):
                with st.spinner("Parsing DNS intelligence dataset..."):
                    try:
                        results = analyze_csv(selected_csv)
                        results = filter_dns_results(results, dga, tunnel)
                        export_results(results, selected_csv)
                        correlation_count = correlate_alerts()

                        st.success(f"Analysis complete // {selected_csv.name}")
                        st.info(
                            f"NEW CORRELATED INCIDENTS: {correlation_count}"
                        )
                        st.rerun()
                    except Exception as error:
                        st.error(f"CSV analysis failed: {error}")

    st.markdown("</div>", unsafe_allow_html=True)


# =========================================================
# THREAT ANALYSIS
# =========================================================

elif page == "Threat Analysis":
    st.markdown(
        '<div class="section-head"><span>✦</span> THREAT ANALYSIS // DETECTOR-SPECIFIC INTELLIGENCE</div>',
        unsafe_allow_html=True,
    )

    selected_key = st.selectbox(
        "SELECT THREAT MODULE",
        THREAT_ORDER,
        format_func=lambda key: THREATS[key]["name"],
    )

    threat = THREATS[selected_key]

    if alerts_df.empty:
        threat_df = pd.DataFrame()
    else:
        threat_df = alerts_df[
            alerts_df["threat_type"] == selected_key
        ].copy()

    if threat_df.empty:
        st.info(
            f"No {threat['name']} alerts stored yet. "
            "Run the detector from Detection Center."
        )
    else:
        total = len(threat_df)
        avg_conf = float(threat_df["confidence"].mean())
        high = int((threat_df["severity"] == "HIGH").sum())
        sources = threat_df["source_ip"].nunique()

        a, b, c, d = st.columns(4)
        with a:
            st.metric("DETECTIONS", total)
        with b:
            st.metric("AVG CONFIDENCE", f"{avg_conf:.1%}")
        with c:
            st.metric("HIGH SEVERITY", high)
        with d:
            st.metric("UNIQUE SOURCES", sources)

        st.markdown(
            f"""
            <div class="soc-panel">
                <div class="threat-icon">{threat['icon']}</div>
                <h3>{threat['name']}</h3>
                <p class="muted">{threat['desc']}</p>
                <div class="mini-tag">
                    DETECTION FAMILY // {threat['family']} &nbsp;&nbsp;
                    MODULE STATUS // ONLINE
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown(
            '<div class="section-head"><span>⌁</span> SOURCE ACTIVITY</div>',
            unsafe_allow_html=True,
        )

        source_counts = (
            threat_df["source_ip"]
            .value_counts()
            .head(15)
            .rename("Alerts")
        )
        st.bar_chart(source_counts)

        st.markdown(
            '<div class="section-head"><span>◌</span> DETECTION RECORDS</div>',
            unsafe_allow_html=True,
        )

        display_df = threat_df.copy()
        display_df["threat_type"] = display_df["threat_type"].map(threat_label)

        st.dataframe(
            display_df,
            use_container_width=True,
            hide_index=True,
        )

        selected_id = st.selectbox(
            "INSPECT ALERT ID",
            threat_df["id"].tolist(),
        )
        selected = threat_df[
            threat_df["id"] == selected_id
        ].iloc[0]

        left, right = st.columns(2)

        with left:
            st.markdown("### EVENT TELEMETRY")
            st.write(f"**Source:** `{selected['source_ip']}`")
            st.write(f"**Destination:** `{selected['destination_ip']}`")
            st.write(f"**Protocol:** `{selected['protocol']}`")
            st.write(f"**Detection Source:** `{selected['detection_source']}`")
            st.write(f"**Timestamp:** `{selected['timestamp']}`")

        with right:
            st.markdown("### CLASSIFICATION")
            st.write(f"**Confidence:** `{selected['confidence']}`")
            st.write(f"**Severity:** `{selected['severity']}`")
            st.write(f"**Source Port:** `{selected['source_port']}`")
            st.write(f"**Destination Port:** `{selected['destination_port']}`")

        st.markdown("### EVIDENCE MATRIX")
        render_evidence_cards(parse_evidence(selected["evidence"]))


# =========================================================
# CORRELATED INCIDENTS
# =========================================================

elif page == "Correlated Incidents":
    st.markdown(
        '<div class="section-head"><span>⌬</span> CORRELATED INCIDENTS // MULTI-SIGNAL ANALYSIS</div>',
        unsafe_allow_html=True,
    )

    if correlated_df.empty:
        st.info("No correlated incidents are currently stored.")
    else:
        high_corr = int(
            (correlated_df["severity"] == "HIGH").sum()
        )

        c1, c2, c3 = st.columns(3)
        with c1:
            st.metric("INCIDENTS", len(correlated_df))
        with c2:
            st.metric("HIGH RISK", high_corr)
        with c3:
            st.metric(
                "AVG SCORE",
                f"{correlated_df['correlation_score'].mean():.2f}",
            )

        display_corr = correlated_df.copy()
        display_corr["threat_type"] = display_corr["threat_type"].apply(
            lambda x: str(x).replace("_", " + ")
        )

        st.dataframe(
            display_corr,
            use_container_width=True,
            hide_index=True,
        )

        selected_id = st.selectbox(
            "INSPECT INCIDENT ID",
            correlated_df["id"].tolist(),
        )
        incident = correlated_df[
            correlated_df["id"] == selected_id
        ].iloc[0]

        st.markdown(
            f"""
            <div class="threat-card">
                <div class="threat-icon">⌬</div>
                <div class="threat-title">INCIDENT #{int(incident['id']):04d}</div>
                <div class="mini-tag">
                    SOURCE // {incident['source_ip']} &nbsp;&nbsp;
                    SCORE // {float(incident['correlation_score']):.2f} &nbsp;&nbsp;
                    SEVERITY // {incident['severity']}
                </div>
                <br>
                <div class="threat-desc">
                    Suspicious signals detected inside a
                    {int(incident['time_window'])}-second correlation window.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        l, r = st.columns(2)

        with l:
            st.write(f"**Source IP:** `{incident['source_ip']}`")
            st.write(f"**Threat Chain:** `{incident['threat_type']}`")
            st.write(f"**Severity:** `{incident['severity']}`")

        with r:
            st.write(
                f"**Correlation Score:** `{incident['correlation_score']}`"
            )
            st.write(
                f"**Time Window:** `{incident['time_window']} seconds`"
            )
            st.write(f"**Timestamp:** `{incident['timestamp']}`")

        st.markdown("### CORRELATION EVIDENCE")
        render_evidence_cards(parse_evidence(incident["evidence"]), incident=incident)


# =========================================================
# ALERT DATABASE
# =========================================================

elif page == "Alert Database":
    st.markdown(
        '<div class="section-head"><span>▣</span> ALERT DATABASE // SQLITE TELEMETRY</div>',
        unsafe_allow_html=True,
    )

    if alerts_df.empty:
        st.info("No alerts are currently stored in SQLite.")
    else:
        f1, f2, f3 = st.columns(3)

        with f1:
            threat_filter = st.selectbox(
                "THREAT",
                ["ALL"] + THREAT_ORDER,
                format_func=lambda x: (
                    "ALL THREATS" if x == "ALL" else threat_label(x)
                ),
            )

        with f2:
            severity_filter = st.selectbox(
                "SEVERITY",
                ["ALL", "HIGH", "MEDIUM", "LOW", "NONE"],
            )

        with f3:
            search_ip = st.text_input(
                "SOURCE IP SEARCH",
                placeholder="10.0.0.34",
            )

        filtered = alerts_df.copy()

        if threat_filter != "ALL":
            filtered = filtered[
                filtered["threat_type"] == threat_filter
            ]

        if severity_filter != "ALL":
            filtered = filtered[
                filtered["severity"] == severity_filter
            ]

        if search_ip.strip():
            filtered = filtered[
                filtered["source_ip"]
                .astype(str)
                .str.contains(search_ip.strip(), case=False, na=False)
            ]

        display_df = filtered.copy()

        if not display_df.empty:
            display_df["threat_type"] = display_df["threat_type"].map(
                threat_label
            )

        st.metric("VISIBLE ALERTS", len(display_df))

        st.dataframe(
            display_df,
            use_container_width=True,
            hide_index=True,
        )

        if not display_df.empty:
            selected_id = st.selectbox(
                "INSPECT ALERT",
                display_df["id"].tolist(),
            )

            raw_id = selected_id
            selected = alerts_df[
                alerts_df["id"] == raw_id
            ].iloc[0]

            st.markdown("### ALERT EVIDENCE")
            render_evidence_cards(parse_evidence(selected["evidence"]))


# =========================================================
# EXPORTS
# =========================================================

elif page == "Exports":
    st.markdown(
        '<div class="section-head"><span>⇩</span> DATA VAULT // EXPORT & EVIDENCE</div>',
        unsafe_allow_html=True,
    )

    st.markdown(
        """
        <div class="soc-panel">
            <div class="threat-title">CYBERDRISTI DATA VAULT</div>
            <div class="threat-desc">
                Structured evidence generated by the alert engine,
                DNS/flow analysis pipeline, and SQLite persistence layer.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    d1, d2, d3 = st.columns(3)

    with d1:
        if not alerts_df.empty:
            st.download_button(
                "⇩ VISIBLE ALERTS CSV",
                alerts_df.to_csv(index=False).encode("utf-8"),
                "cyberdhristi_alerts.csv",
                "text/csv",
                use_container_width=True,
            )

    with d2:
        if JSON_ALERTS_FILE.exists():
            st.download_button(
                "⇩ ALERTS JSON",
                JSON_ALERTS_FILE.read_bytes(),
                "cyberdhristi_alerts.json",
                "application/json",
                use_container_width=True,
            )

    with d3:
        if RESULTS_FILE.exists():
            st.download_button(
                "⇩ ANALYSIS CSV",
                RESULTS_FILE.read_bytes(),
                "cyberdhristi_analysis.csv",
                "text/csv",
                use_container_width=True,
            )

    st.markdown("### GENERATED FILES")

    files = [
        SUMMARY_FILE,
        ALERTS_FILE,
        RESULTS_FILE,
        JSON_ALERTS_FILE,
        OUTPUT_DIR / "flow_alerts.csv",
        OUTPUT_DIR / "flow_alerts.json",
    ]

    rows = []

    for file in files:
        rows.append(
            {
                "FILE": file.name,
                "STATUS": "ONLINE" if file.exists() else "NOT GENERATED",
                "SIZE": (
                    f"{file.stat().st_size / 1024:.1f} KB"
                    if file.exists()
                    else "-"
                ),
            }
        )

    st.dataframe(
        pd.DataFrame(rows),
        use_container_width=True,
        hide_index=True,
    )

st.caption(
    "CYBERDRISTI // SIH26145 // AI-POWERED NETWORK DEFENSE GRID"
)
