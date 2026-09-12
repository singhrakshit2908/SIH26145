#!/bin/bash
set -e
OUTPUT="datasets/raw/benign/benign.pcap"
echo "[+] Starting benign capture: $OUTPUT"
sudo tcpdump -i any -w "$OUTPUT" &
TCPDUMP_PID=$!
sleep 2
echo "[+] Generate normal traffic against the isolated lab server."
# Add your lab-specific benign traffic generator here.
sleep 30
sudo kill "$TCPDUMP_PID" 2>/dev/null || true
echo "[+] Capture complete: $OUTPUT"
ls -lh "$OUTPUT"
