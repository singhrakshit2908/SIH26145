from pathlib import Path
from collections import defaultdict

from scapy.all import rdpcap, IP, TCP, UDP
def get_flow_key(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if packet.haslayer(TCP):
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

        elif packet.haslayer(UDP):
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        else:
            return None

        return (
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol
        )

    return None
def load_pcap(pcap_path):
    packets = rdpcap(str(pcap_path))
    return packets
def extract_flow_features(packets):
    flows = defaultdict(list)

    for packet in packets:
        flow_key = get_flow_key(packet)

        if flow_key is not None:
            flows[flow_key].append(packet)

    flow_features = []

    for flow_key, flow_packets in flows.items():
        start_time = float(flow_packets[0].time)
        end_time = float(flow_packets[-1].time)

        duration = end_time - start_time
        packet_count = len(flow_packets)
        syn_count = sum(
            
    1
    for packet in flow_packets
    if packet.haslayer(TCP)
    and packet[TCP].flags & 0x02
)
        syn_ratio = syn_count / packet_count if packet_count else 0

        ack_count = sum(
            1
            for packet in flow_packets
            if packet.haslayer(TCP)
            and packet[TCP].flags & 0x10
        )

        rst_count = sum(
            1
            for packet in flow_packets
            if packet.haslayer(TCP)
            and packet[TCP].flags & 0x04
        )
        udp_count = sum(
            1
            for packet in flow_packets
            if packet.haslayer(UDP)
        )
        
        

        total_bytes = sum(
            len(packet)
            for packet in flow_packets
        )

        packets_per_second = (
            packet_count / duration
            if duration > 0
            else packet_count
        )

        bytes_per_second = (
            total_bytes / duration
            if duration > 0
            else total_bytes
        )

        (
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            protocol
        ) = flow_key

        flow_features.append({
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "source_port": source_port,
            "destination_port": destination_port,
            "protocol": protocol,
            "duration": round(duration, 4),
            "packet_count": packet_count,
            "total_bytes": total_bytes,
            "packets_per_second": round(packets_per_second, 4),
            "bytes_per_second": round(bytes_per_second, 4),
"syn_count": syn_count,
"syn_ratio": round(syn_ratio, 4),
"ack_count": ack_count,
"rst_count": rst_count,
"udp_count": udp_count
        })

    return flow_features
def detect_flow_threat(flow):
    """
    Basic rule-based flow classification.
    """

    protocol = flow["protocol"]
    packet_count = flow["packet_count"]
    syn_ratio = flow["syn_ratio"]
    udp_count = flow["udp_count"]
    packets_per_second = flow["packets_per_second"]
    duration = flow["duration"]
    ack_count = flow["ack_count"]

    # SYN flood
    if (
        protocol == "TCP"
        and syn_ratio >= 0.5
        and packet_count >= 1
        and packets_per_second >= 100
    ):
        return "SYN_FLOOD", 0.90

    # UDP flood
    if (
        protocol == "UDP"
        and udp_count >= 1
    ):
        return "BENIGN", 0.50

    # Slowloris
    if (
        protocol == "TCP"
        and duration >= 10
        and packet_count <= 20
        and ack_count >= 5
    ):
        return "SLOWLORIS", 0.85

    # Everything else
    return "BENIGN", 0.50

def analyze_flow_pcap(pcap_path):
    """
    Analyze a PCAP and return alert-ready flow records.
    """

    pcap_path = Path(pcap_path)

    packets = load_pcap(pcap_path)
    flows = extract_flow_features(packets)

    # Aggregate SYN traffic
    syn_sources = {}

    for flow in flows:
        if (
            flow["protocol"] == "TCP"
            and flow["syn_count"] > 0
        ):
            pair = (
                flow["source_ip"],
                flow["destination_ip"]
            )

            syn_sources[pair] = (
                syn_sources.get(pair, 0)
                + flow["syn_count"]
            )

    syn_flood_sources = {
        pair
        for pair, count in syn_sources.items()
        if count >= 100
    }

    # Aggregate UDP traffic
    udp_targets = {}

    for flow in flows:
        if flow["protocol"] == "UDP":

            target = (
                flow["destination_ip"],
                flow["destination_port"]
            )

            udp_targets[target] = (
                udp_targets.get(target, 0)
                + flow["udp_count"]
            )

    udp_flood_targets = {
        target
        for target, count in udp_targets.items()
        if count >= 100
    }

    results = []

    for flow in flows:

        syn_pair = (
            flow["source_ip"],
            flow["destination_ip"]
        )

        udp_target = (
            flow["destination_ip"],
            flow["destination_port"]
        )

        if syn_pair in syn_flood_sources:
            threat_type = "SYN_FLOOD"
            confidence = 0.90

        elif udp_target in udp_flood_targets:
            threat_type = "UDP_FLOOD"
            confidence = 0.90

        else:
            threat_type, confidence = detect_flow_threat(flow)

        results.append({
            "timestamp": float(packets[0].time),
            "source_ip": flow["source_ip"],
            "destination_ip": flow["destination_ip"],
            "source_port": flow["source_port"],
            "destination_port": flow["destination_port"],
            "protocol": flow["protocol"],
            "threat_type": threat_type,
            "confidence": confidence,
            "detection_source": "FLOW_RULE_ENGINE",
            "evidence": {
                "duration": flow["duration"],
                "packet_count": flow["packet_count"],
                "total_bytes": flow["total_bytes"],
                "packets_per_second": flow["packets_per_second"],
                "bytes_per_second": flow["bytes_per_second"],
                "syn_count": flow["syn_count"],
                "syn_ratio": flow["syn_ratio"],
                "ack_count": flow["ack_count"],
                "rst_count": flow["rst_count"],
                "udp_count": flow["udp_count"]
            }
        })

    return results

    return results   
if __name__ == "__main__":
    BASE_DIR = Path(__file__).resolve().parent.parent

    pcap_path = (
        BASE_DIR
        / "datasets"
        / "raw"
        / "attacks"
        / "syn_flood"
        / "syn_flood.pcap"
    )

    packets = load_pcap(pcap_path)

    print("PCAP:", pcap_path.name)
    print("Packets:", len(packets))

    flows = extract_flow_features(packets)

    print("Flows:", len(flows))

    threat_counts = {
        "BENIGN": 0,
        "SYN_FLOOD": 0,
        "UDP_FLOOD": 0,
        "SLOWLORIS": 0
    }

    for flow in flows:
        threat_type, confidence = detect_flow_threat(flow)
        threat_counts[threat_type] += 1

    print("\nThreat Summary:")

    for threat, count in threat_counts.items():
        print(f"{threat}: {count}")