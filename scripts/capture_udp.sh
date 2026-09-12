#!/bin/bash
set -e

OUTPUT="datasets/raw/attacks/udp_flood/udp_flood.pcap"
TARGET="127.0.0.1"
PORT="8080"
COUNT="1000"

echo "[+] Starting controlled UDP-traffic capture"
echo "[+] Target: ${TARGET}:${PORT}"
echo "[+] Packets: ${COUNT}"

sudo tcpdump -i lo -w "$OUTPUT" "udp" &
TCPDUMP_PID=$!

sleep 2

echo "[+] Generating bounded UDP traffic..."
sudo hping3 --udp -p "$PORT" -c "$COUNT" -i u10000 "$TARGET"

echo "[+] UDP generation finished."
echo "[+] Gracefully stopping tcpdump..."

sudo kill -2 "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true

echo "[+] Capture complete:"
ls -lh "$OUTPUT"
