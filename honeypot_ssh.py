"""
honeypot_ssh.py — Fake SSH server (low-interaction honeypot).

Listens on a port, completes just enough of the SSH handshake to make
`ssh user@host -p <port>` prompt for a password, logs every username/
password attempt, then always rejects the login. No real shell is ever
given to a connecting client.

Run standalone:  python honeypot_ssh.py --port 2222
"""

import argparse
import socket
import threading
import sys

import paramiko

from db import init_db, log_event
from classifier import classify

# Any RSA host key works here — it's only used to establish the encrypted
# channel, not for any real authentication.
HOST_KEY = paramiko.RSAKey.generate(2048)


class FakeSSHServer(paramiko.ServerInterface):
    def __init__(self, client_ip, client_port):
        self.client_ip = client_ip
        self.client_port = client_port
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        # Log first, then classify (classifier looks at this event's history).
        log_event(
            service="ssh",
            source_ip=self.client_ip,
            source_port=self.client_port,
            username=username,
            password=password,
        )
        attack_type = classify(
            service="ssh",
            source_ip=self.client_ip,
            username=username,
            password=password,
            source_port=self.client_port,
        )
        # Update the row we just wrote with the real classification.
        _update_last_classification(self.client_ip, attack_type)

        print(f"[SSH] {self.client_ip}:{self.client_port} tried {username}:{password} -> {attack_type}")

        # Always deny. A honeypot never actually authenticates anyone.
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        log_event(
            service="ssh",
            source_ip=self.client_ip,
            source_port=self.client_port,
            username=username,
            raw_payload=f"pubkey-auth fingerprint={key.get_fingerprint().hex()}",
        )
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password,publickey"


def _update_last_classification(source_ip, attack_type):
    """Small helper: overwrite attack_type on the most recent row for this IP."""
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


def handle_connection(client_sock, addr):
    client_ip, client_port = addr
    transport = None
    try:
        transport = paramiko.Transport(client_sock)
        transport.add_server_key(HOST_KEY)
        server = FakeSSHServer(client_ip, client_port)
        transport.start_server(server=server)

        # Give the client a little time to attempt auth, then close.
        chan = transport.accept(20)
        if chan is not None:
            chan.close()
    except Exception as e:
        # Malformed/non-SSH connections still count as recon activity.
        log_event(service="ssh", source_ip=client_ip, source_port=client_port,
                   raw_payload=f"handshake-error: {e}", attack_type="recon")
    finally:
        if transport:
            transport.close()


def run(port=2222, bind="0.0.0.0"):
    init_db()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bind, port))
    sock.listen(100)
    print(f"[SSH honeypot] listening on {bind}:{port}")

    while True:
        client_sock, addr = sock.accept()
        threading.Thread(target=handle_connection, args=(client_sock, addr), daemon=True).start()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=2222)
    parser.add_argument("--bind", default="0.0.0.0")
    args = parser.parse_args()
    try:
        run(args.port, args.bind)
    except KeyboardInterrupt:
        sys.exit(0)
