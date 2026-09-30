"""
honeypot_ftp.py — Fake FTP server (low-interaction honeypot).

Speaks just enough of the FTP protocol (banner, USER, PASS) to convince
a client or scanner it's a real FTP server, logs every login attempt,
then always responds with "530 Login incorrect". No real filesystem is
ever exposed.

Run standalone:  python honeypot_ftp.py --port 2121
"""

import argparse
import socket
import threading
import sys

from db import init_db, log_event
from classifier import classify

BANNER = b"220 (vsFTPd 3.0.3)\r\n"


def handle_connection(client_sock, addr):
    client_ip, client_port = addr
    username = None
    try:
        client_sock.sendall(BANNER)
        client_sock.settimeout(15)

        while True:
            data = client_sock.recv(1024)
            if not data:
                break
            line = data.decode(errors="ignore").strip()
            if not line:
                continue

            if line.upper().startswith("USER "):
                username = line[5:].strip()
                client_sock.sendall(b"331 Please specify the password.\r\n")

            elif line.upper().startswith("PASS "):
                password = line[5:].strip()
                log_event(service="ftp", source_ip=client_ip, source_port=client_port,
                          username=username, password=password)
                attack_type = classify(service="ftp", source_ip=client_ip,
                                        username=username, password=password,
                                        source_port=client_port)
                _update_last_classification(client_ip, attack_type)
                print(f"[FTP] {client_ip}:{client_port} tried {username}:{password} -> {attack_type}")
                client_sock.sendall(b"530 Login incorrect.\r\n")

            elif line.upper().startswith("QUIT"):
                client_sock.sendall(b"221 Goodbye.\r\n")
                break

            elif line.upper().startswith(("HEAD ", "GET ", "POST ")) or "HTTP/" in line.upper():
                # Ignore internal cloud health check probes on FTP port
                client_sock.sendall(b"530 Please login with USER and PASS.\r\n")
                break

            else:
                # Any other command before a successful login is recon (e.g. SYST, PWD probing).
                if client_ip not in ["127.0.0.1", "::1"]:
                    log_event(service="ftp", source_ip=client_ip, source_port=client_port,
                              raw_payload=line, attack_type="recon")
                client_sock.sendall(b"530 Please login with USER and PASS.\r\n")

    except socket.timeout:
        pass
    except Exception as e:
        if client_ip not in ["127.0.0.1", "::1"]:
            log_event(service="ftp", source_ip=client_ip, source_port=client_port,
                       raw_payload=f"error: {e}", attack_type="recon")
    finally:
        client_sock.close()


def _update_last_classification(source_ip, attack_type):
    import sqlite3
    from db import DB_PATH
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        UPDATE events SET attack_type = ?
        WHERE id = (SELECT id FROM events WHERE source_ip = ? ORDER BY id DESC LIMIT 1)
        """,
        (attack_type, source_ip),
    )
    conn.commit()
    conn.close()


def run(port=2121, bind="0.0.0.0"):
    init_db()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bind, port))
    sock.listen(100)
    print(f"[FTP honeypot] listening on {bind}:{port}")

    while True:
        client_sock, addr = sock.accept()
        threading.Thread(target=handle_connection, args=(client_sock, addr), daemon=True).start()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=2121)
    parser.add_argument("--bind", default="0.0.0.0")
    args = parser.parse_args()
    try:
        run(args.port, args.bind)
    except KeyboardInterrupt:
        sys.exit(0)
