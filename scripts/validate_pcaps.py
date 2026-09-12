from pathlib import Path
import json
import subprocess

PCAPS = {
    "BENIGN": Path("datasets/raw/benign/benign.pcap"),
    "SYN_FLOOD": Path("datasets/raw/attacks/syn_flood/syn_flood.pcap"),
    "UDP_FLOOD": Path("datasets/raw/attacks/udp_flood/udp_flood.pcap"),
    "SLOWLORIS": Path("datasets/raw/attacks/slowloris/slowloris.pcap"),
}

def analyze_pcap(label, path):
    result = {
        "label": label,
        "file": str(path),
        "exists": path.exists(),
        "size_bytes": path.stat().st_size if path.exists() else 0,
    }
    if not path.exists():
        result["status"] = "MISSING"
        return result

    try:
        output = subprocess.run(
            ["capinfos", "-c", "-z", "-t", str(path)],
            capture_output=True,
            text=True,
        )
        result["capinfos"] = output.stdout
        result["status"] = "VALID" if output.returncode == 0 else "INVALID"
    except FileNotFoundError:
        result["status"] = "PCAP_EXISTS_CAPINFOS_NOT_INSTALLED"
    return result

def main():
    report = [analyze_pcap(label, path) for label, path in PCAPS.items()]
    output_file = Path("reports/validation_report.json")
    output_file.write_text(json.dumps(report, indent=4))
    print("=== PCAP VALIDATION ===")
    for item in report:
        print(f"{item['label']:12} | {item['status']:35} | {item['size_bytes']} bytes")
    print(f"\nReport written to: {output_file}")

if __name__ == "__main__":
    main()
