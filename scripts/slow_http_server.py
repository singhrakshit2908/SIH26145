import socket
import threading
import time

HOST = "127.0.0.1"
PORT = 8080

def handle_client(conn, addr):
    print(f"[+] Connection accepted from {addr}")

    conn.settimeout(30)

    data = b""

    try:
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(1024)

            if not chunk:
                break

            data += chunk

            # Deliberately wait for a complete HTTP header.
            time.sleep(0.1)

        if b"\r\n\r\n" in data:
            print(f"[+] Complete request received from {addr}")
            response = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Length: 2\r\n"
                b"Connection: close\r\n"
                b"\r\n"
                b"OK"
            )
            conn.sendall(response)

        else:
            print(f"[-] Incomplete request closed: {addr}")

    except socket.timeout:
        print(f"[-] Connection timed out: {addr}")

    except (ConnectionResetError, BrokenPipeError):
        print(f"[-] Connection closed by client: {addr}")

    finally:
        conn.close()


server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

server.bind((HOST, PORT))
server.listen(20)

print("=" * 50)
print("SentinelFlow Slow HTTP Lab Server")
print("=" * 50)
print(f"Listening ONLY on {HOST}:{PORT}")
print("Press Ctrl+C to stop.")
print()

try:
    while True:
        conn, addr = server.accept()

        thread = threading.Thread(
            target=handle_client,
            args=(conn, addr),
            daemon=True
        )

        thread.start()

except KeyboardInterrupt:
    print("\n[+] Server stopped.")

finally:
    server.close()
