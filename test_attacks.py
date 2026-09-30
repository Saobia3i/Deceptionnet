"""
test_attacks.py — Fires a batch of realistic attacks at your running
honeypot so the dashboard has data to show in your demo, without waiting
for a real attacker to show up.

Run this AFTER run_all.py is already running in another terminal:
    python test_attacks.py
"""

import socket
import time
import requests

TARGET = "localhost"
WEB_URL = f"http://{TARGET}:8080"


def brute_force_ftp(n=6):
    print(f"[*] Simulating {n} FTP brute-force attempts...")
    creds = [("admin", "admin"), ("admin", "123456"), ("root", "toor"),
             ("admin", "password"), ("root", "root123"), ("admin", "letmein")]
    for user, pw in creds[:n]:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((TARGET, 2121))
        s.recv(1024)
        s.sendall(f"USER {user}\r\n".encode())
        s.recv(1024)
        s.sendall(f"PASS {pw}\r\n".encode())
        s.recv(1024)
        s.close()
        time.sleep(0.3)


def sqli_web_login():
    print("[*] Simulating SQL injection attempt on web login...")
    requests.post(f"{WEB_URL}/login", data={
        "username": "admin' OR '1'='1", "password": "anything"
    })


def xss_web_search():
    print("[*] Simulating XSS attempt on web search box...")
    requests.get(f"{WEB_URL}/search", params={"q": "<script>alert(1)</script>"})


def port_scan_probe():
    print("[*] Simulating a quick port scan against honeypot ports...")
    for port in [21, 22, 2121, 2222, 8080, 8081]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((TARGET, port))
            s.close()
        except Exception:
            pass
        time.sleep(0.2)


def honeytoken_trigger():
    print("[*] Simulating Honeytoken trigger (fake API key access)...")
    requests.get(f"{WEB_URL}/api/v1/internal", params={"key": "dnet_honey_99PqRsTuVwXyZ1234567890AbCdEfGhIj"})



if __name__ == "__main__":
    brute_force_ftp()
    sqli_web_login()
    xss_web_search()
    port_scan_probe()
    honeytoken_trigger()
    print("\nDone. Check the dashboard at http://localhost:5000")

