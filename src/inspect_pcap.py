from pathlib import Path
from scapy.all import rdpcap, DNS

BASE_DIR = Path(__file__).resolve().parent.parent

pcap_files = [
    BASE_DIR / "datasets" / "raw" / "dns-tunnel-iodine.pcap",
    BASE_DIR / "datasets" / "raw" / "iodine_1.1.pcapng",
    BASE_DIR / "datasets" / "raw" / "dnscat2_1.pcapng"
]

for file_path in pcap_files:

    print("\n" + "=" * 60)
    print("File:", file_path.name)

    try:
        packets = rdpcap(str(file_path))

        print("Total packets:", len(packets))

        dns_count = 0
        examples = []

        for packet in packets:
            if packet.haslayer(DNS):
                dns_count += 1

                if len(examples) < 5:
                    dns_layer = packet[DNS]

                    if dns_layer.qd:
                        query = dns_layer.qd.qname
                        examples.append(query.decode(errors="ignore"))

        print("DNS packets:", dns_count)

        print("Example DNS queries:")
        for query in examples:
            print(" -", query)

    except Exception as e:
        print("ERROR:", e)