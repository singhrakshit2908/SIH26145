from pathlib import Path

from src.flow_analyzer import (
    load_pcap,
    extract_flow_features,
    detect_flow_threat
)


BASE_DIR = Path(__file__).resolve().parent.parent

PCAP_FILES = {
    "BENIGN": (
        BASE_DIR
        / "datasets"
        / "raw"
        / "benign"
        / "benign.pcap"
    ),

    "SYN_FLOOD": (
        BASE_DIR
        / "datasets"
        / "raw"
        / "attacks"
        / "syn_flood"
        / "syn_flood.pcap"
    ),

    "UDP_FLOOD": (
        BASE_DIR
        / "datasets"
        / "raw"
        / "attacks"
        / "udp_flood"
        / "udp_flood.pcap"
    ),

    "SLOWLORIS": (
        BASE_DIR
        / "datasets"
        / "raw"
        / "attacks"
        / "slowloris"
        / "slowloris.pcap"
    )
}


def find_syn_flood_sources(flows):
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

    return {
        pair
        for pair, count in syn_sources.items()
        if count >= 100
    }


def find_udp_flood_targets(flows):
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

    return {
        target
        for target, count in udp_targets.items()
        if count >= 100
    }


for label, pcap_path in PCAP_FILES.items():

    packets = load_pcap(pcap_path)
    flows = extract_flow_features(packets)

    syn_flood_sources = find_syn_flood_sources(flows)
    udp_flood_targets = find_udp_flood_targets(flows)

    counts = {
        "BENIGN": 0,
        "SYN_FLOOD": 0,
        "UDP_FLOOD": 0,
        "SLOWLORIS": 0
    }

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
            threat = "SYN_FLOOD"

        elif udp_target in udp_flood_targets:
            threat = "UDP_FLOOD"

        else:
            threat, confidence = detect_flow_threat(flow)

        counts[threat] += 1

    print("\n" + "=" * 50)
    print("Dataset:", label)
    print("Packets:", len(packets))
    print("Flows:", len(flows))
    print("Detected:")

    for threat, count in counts.items():
        print(f"  {threat}: {count}")