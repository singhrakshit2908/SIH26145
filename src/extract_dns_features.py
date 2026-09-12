from pathlib import Path
from collections import Counter
import math
import pandas as pd

from scapy.all import rdpcap, DNS

BASE_DIR = Path(__file__).resolve().parent.parent

pcap_files = {
    "dns-tunnel-iodine.pcap": ("tunnel", "iodine"),
    "iodine_1.1.pcapng": ("tunnel", "iodine"),
    "dnscat2_1.pcapng": ("tunnel", "dnscat2"),
    "normal_dns.pcap": ("benign", "normal")
}


def calculate_entropy(text):
    if not text:
        return 0

    counts = Counter(text)
    length = len(text)

    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def extract_dns_features(query):
    query = query.rstrip(".")
    parts = query.split(".")
    subdomain = parts[0] if parts else query

    subdomain_length = len(subdomain)
    digits = sum(char.isdigit() for char in subdomain)
    unique_chars = len(set(subdomain))

    return {
        "query": query,
        "query_length": len(query),
        "subdomain_length": subdomain_length,
        "entropy": calculate_entropy(subdomain),
        "digit_ratio": digits / subdomain_length if subdomain_length else 0,
        "unique_char_ratio": unique_chars / subdomain_length if subdomain_length else 0
    }


all_records = []

for filename, (label, tunnel_type) in pcap_files.items():

    file_path = BASE_DIR / "datasets" / "raw" / filename

    print("\nProcessing:", filename)

    packets = rdpcap(str(file_path))
    dns_records = 0

    for packet in packets:

        if packet.haslayer(DNS):

            dns_layer = packet[DNS]

            # Check that this packet actually contains a DNS query
            if dns_layer.qd is not None:

                try:
                    query = dns_layer.qd.qname.decode(errors="ignore")

                    features = extract_dns_features(query)

                    features["label"] = label
                    features["tunnel_type"] = tunnel_type

                    all_records.append(features)
                    dns_records += 1

                except Exception as e:
                    print("Skipped packet:", e)

    print("DNS records extracted:", dns_records)


print("\nCreating DataFrame...")

df = pd.DataFrame(all_records)

output_file = (
    BASE_DIR
    / "datasets"
    / "processed"
    / "dns_tunnel_features.csv"
)

df.to_csv(output_file, index=False)

print("\nFeature extraction complete!")
print("Total records:", len(df))

print("\nFirst 5 records:")
print(df.head())

print("\nSaved to:")
print(output_file)