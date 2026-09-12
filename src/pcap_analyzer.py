from pathlib import Path
from collections import Counter
import math
import tldextract

import numpy as np
import pandas as pd

import joblib

from scapy.all import rdpcap, DNS
from src.export_results import export_results
from src.correlation_engine import correlate_alerts


BASE_DIR = Path(__file__).resolve().parent.parent


# ============================================================
# LOAD MODELS
# ============================================================

DGA_MODEL_PATH = (
    BASE_DIR / "models" / "dga_random_forest.joblib"
)

DNS_MODEL_PATH = (
    BASE_DIR / "models" / "dns_tunnel_random_forest.joblib"
)

dga_model = joblib.load(DGA_MODEL_PATH)
dns_model = joblib.load(DNS_MODEL_PATH)


# ============================================================
# FEATURE FUNCTIONS
# ============================================================

def calculate_entropy(text):

    if not text:
        return 0.0

    counts = Counter(text)
    length = len(text)

    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def extract_dga_features(domain):

    domain = str(domain).lower()

    length = len(domain)
    digits = sum(char.isdigit() for char in domain)
    vowels = sum(char in "aeiou" for char in domain)
    unique_chars = len(set(domain))
    entropy = calculate_entropy(domain)

    return [
        length,
        entropy,
        digits / length if length else 0,
        vowels / length if length else 0,
        unique_chars / length if length else 0
    ]


def extract_dns_features(query):

    query = str(query).rstrip(".")
    parts = query.split(".")

    subdomain = parts[0] if parts else query

    subdomain_length = len(subdomain)

    digits = sum(char.isdigit() for char in subdomain)
    unique_chars = len(set(subdomain))

    return [
        len(query),
        subdomain_length,
        calculate_entropy(subdomain),
        digits / subdomain_length if subdomain_length else 0,
        unique_chars / subdomain_length
        if subdomain_length else 0
    ]


def get_dga_domain(query):
    """
    Extract the registered domain label for DGA analysis.
    """

    extracted = tldextract.extract(query)

    # Example:
    # fbcdn-profile-a.akamaihd.net
    # domain = akamaihd

    if extracted.domain:
        return extracted.domain

    # Fallback if domain extraction fails
    return query.split(".")[0]


# ============================================================
# EXTRACT DNS QUERIES
# ============================================================

def extract_dns_queries(pcap_path):

    packets = rdpcap(str(pcap_path))

    queries = []

    for packet in packets:

        if packet.haslayer(DNS):

            dns_layer = packet[DNS]

            if dns_layer.qd is not None:

                try:
                    query = (
                        dns_layer.qd.qname
                        .decode(errors="ignore")
                        .rstrip(".")
                    )

                    source_ip = (
                        packet["IP"].src
                        if packet.haslayer("IP")
                        else "UNKNOWN"
                    )

                    destination_ip = (
                        packet["IP"].dst
                        if packet.haslayer("IP")
                        else "UNKNOWN"
                    )

                    timestamp = float(packet.time)

                    queries.append({
                        "query": query,
                        "source_ip": source_ip,
                        "destination_ip": destination_ip,
                        "timestamp": timestamp
                    })

                except Exception:
                    continue

    return queries


# ============================================================
# ANALYZE PCAP USING BATCH PREDICTION
# ============================================================

def analyze_queries(queries):

    if not queries:
        print("No DNS queries found.")
        return []

    query_values = [
        item["query"] if isinstance(item, dict) else item
        for item in queries
    ]

    # -------------------------
    # DGA FEATURES
    # -------------------------

    domain_parts = [
        get_dga_domain(query)
        for query in query_values
    ]

    dga_features = np.array([
        extract_dga_features(domain)
        for domain in domain_parts
    ])

    print("Running DGA detection...")

    dga_predictions = dga_model.predict(
        dga_features
    )

    dga_probabilities = dga_model.predict_proba(
        dga_features
    )

    # -------------------------
    # DNS TUNNEL FEATURES
    # -------------------------

    dns_features = np.array([
        extract_dns_features(query)
        for query in query_values
    ])

    dns_feature_columns = [
        "query_length",
        "subdomain_length",
        "entropy",
        "digit_ratio",
        "unique_char_ratio"
    ]

    dns_feature_df = pd.DataFrame(
        dns_features,
        columns=dns_feature_columns
    )

    print("Running DNS tunnel detection...")

    dns_predictions = dns_model.predict(
        dns_feature_df
    )

    dns_probabilities = dns_model.predict_proba(
        dns_feature_df
    )

    # -------------------------
    # COMBINE RESULTS
    # -------------------------

    results = []

    for i, query in enumerate(query_values):

        dga_confidence = float(
            max(dga_probabilities[i])
        )

        dns_confidence = float(
            max(dns_probabilities[i])
        )

        results.append({
            "query": query,

            "source_ip": (
                queries[i]["source_ip"]
                if isinstance(queries[i], dict)
                else "UNKNOWN"
            ),

            "destination_ip": (
                queries[i]["destination_ip"]
                if isinstance(queries[i], dict)
                else "UNKNOWN"
            ),

            "timestamp": (
                queries[i]["timestamp"]
                if isinstance(queries[i], dict)
                else None
            ),

            "dga_prediction":
                "DGA"
                if dga_predictions[i] == 1
                else "BENIGN",

            "dga_confidence":
                round(dga_confidence, 4),

            "dns_tunnel_prediction":
                "DNS_TUNNEL"
                if dns_predictions[i] == 1
                else "BENIGN",

            "dns_tunnel_confidence":
                round(dns_confidence, 4),

            "query_length":
                int(dns_features[i][0]),

            "subdomain_length":
                int(dns_features[i][1]),

            "entropy":
                round(float(dns_features[i][2]), 4),

            "digit_ratio":
                round(float(dns_features[i][3]), 4)
        })

    print("Analysis complete!")

    return results


def analyze_pcap(pcap_path):

    pcap_path = Path(pcap_path)

    print("\nAnalyzing:", pcap_path.name)

    queries = extract_dns_queries(pcap_path)

    print("DNS queries found:", len(queries))

    return analyze_queries(queries)


def analyze_csv(csv_path):

    csv_path = Path(csv_path)

    print("\nAnalyzing CSV:", csv_path.name)

    df = pd.read_csv(csv_path)

    if "query" not in df.columns:
        print("CSV must contain a 'query' column.")
        return []

    queries = (
        df["query"]
        .dropna()
        .astype(str)
        .tolist()
    )

    print("DNS queries found:", len(queries))

    return analyze_queries(queries)


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    RAW_DATA_DIR = (
        BASE_DIR
        / "datasets"
        / "raw"
    )

    print("\nAvailable PCAP files:\n")

    files = list(RAW_DATA_DIR.glob("*.pcap"))
    files += list(RAW_DATA_DIR.glob("*.pcapng"))

    if not files:
        print("No PCAP files found.")
        exit()

    for index, file in enumerate(files, start=1):
        print(f"{index}. {file.name}")

    print()

    choice = input(
        "Enter the number of the file to analyze: "
    )

    try:
        choice = int(choice)

        if choice < 1 or choice > len(files):
            print("Invalid selection.")
            exit()

    except ValueError:
        print("Please enter a valid number.")
        exit()

    test_file = files[choice - 1]

    print(
        f"\nSelected file: {test_file.name}"
    )

    results = analyze_pcap(test_file)

    export_results(results, test_file)

    correlated_count = correlate_alerts()

    print(
        f"\nCorrelation complete. "
        f"Created {correlated_count} new correlated alert(s)."
    )

    print("\nFirst 5 results:\n")

    for result in results[:5]:
        print(result)