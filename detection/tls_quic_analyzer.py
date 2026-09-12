from scapy.all import rdpcap, IP, TCP, UDP
from scapy.layers.tls.all import TLS, TLSClientHello
from scapy.layers.quic import QUIC


def identify_protocol(packet):
    """Identify TLS or QUIC traffic in a packet."""

    if packet.haslayer(TLS):
        return "TLS"

    if packet.haslayer(QUIC):
        return "QUIC"

    return None


def analyze_pcap(pcap_file):
    """Read a PCAP and count TLS and QUIC packets."""

    packets = rdpcap(pcap_file)

    results = {
        "total_packets": len(packets),
        "tls_packets": 0,
        "quic_packets": 0
    }

    for packet in packets:
        protocol = identify_protocol(packet)

        if protocol == "TLS":
            results["tls_packets"] += 1

        elif protocol == "QUIC":
            results["quic_packets"] += 1

    return results

def extract_metadata(packet):
    """Extract basic network metadata from a TLS/QUIC packet."""

    metadata = {
        "source_ip": None,
        "destination_ip": None,
        "source_port": None,
        "destination_port": None,
        "protocol": identify_protocol(packet)
    }

    if packet.haslayer(IP):
        metadata["source_ip"] = packet[IP].src
        metadata["destination_ip"] = packet[IP].dst

    if packet.haslayer(TCP):
        metadata["source_port"] = packet[TCP].sport
        metadata["destination_port"] = packet[TCP].dport

    elif packet.haslayer(UDP):
        metadata["source_port"] = packet[UDP].sport
        metadata["destination_port"] = packet[UDP].dport

    return metadata

def extract_tls_metadata(packet):
    """Extract basic TLS metadata from a packet."""

    if not packet.haslayer(TLS):
        return None

    tls_layer = packet[TLS]

    metadata = {
            "tls_version": getattr(tls_layer, "version", None),
        "tls_message_type": None,
        "has_handshake": False,
        "cipher_suites": [],
        "supported_groups": [],
        "alpn": []
    }

    if tls_layer.msg:
        client_hello = tls_layer.msg[0]

        if isinstance(client_hello, TLSClientHello):
            metadata["tls_message_type"] = "ClientHello"
            metadata["has_handshake"] = True
            metadata["cipher_suites"] = getattr(
                client_hello, "ciphers", []
            )

        for extension in getattr(client_hello, "ext", []):
            if hasattr(extension, "groups"):
                metadata["supported_groups"] = extension.groups

            if hasattr(extension, "protocols"):
                metadata["alpn"] = extension.protocols

    return metadata

def extract_quic_metadata(packet):
    """Extract basic QUIC metadata from a packet."""

    if not packet.haslayer(QUIC):
        return None

    quic_layer = packet[QUIC]

    metadata = {
        "quic_version": getattr(quic_layer, "version", None),
        "packet_length": len(packet),
    }

    return metadata

def extract_all_metadata(packet):
    """Extract network and TLS/QUIC metadata from a packet."""

    metadata = extract_metadata(packet)

    if metadata["protocol"] == "TLS":
        metadata["tls_metadata"] = extract_tls_metadata(packet)
        metadata["tls_sni"] = extract_tls_sni(packet)
        metadata["quic_metadata"] = None

    elif metadata["protocol"] == "QUIC":
        metadata["tls_metadata"] = None
        metadata["tls_sni"] = None
        metadata["quic_metadata"] = extract_quic_metadata(packet)

    else:
        metadata["tls_metadata"] = None
        metadata["tls_sni"] = None
        metadata["quic_metadata"] = None

    return metadata

def extract_tls_sni(packet):
    """Extract the TLS Server Name (SNI) when available."""

    if not packet.haslayer(TLSClientHello):
        return None

    client_hello = packet[TLSClientHello]

    for extension in getattr(client_hello, "ext", []):
        if hasattr(extension, "servernames"):
            server_names = extension.servernames

            if server_names:
                server_name = server_names[0]

                if hasattr(server_name, "servername"):
                    return server_name.servername.decode(
                        errors="ignore"
                    )

    return None 