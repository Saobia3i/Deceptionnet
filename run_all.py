"""
run_all.py — Starts every DeceptionNet service in one process:
  - SSH honeypot   (default port 2222)
  - FTP honeypot   (default port 2121)
  - Web honeypot   (default port 8080)
  - Dashboard      (default port 5000)

Usage:  python run_all.py
Then open http://localhost:5000 for the dashboard.
"""

import threading
import time

from db import init_db
import honeypot_ssh
import honeypot_ftp
import honeypot_web
import dashboard_api


def main():
    init_db()

    threading.Thread(target=honeypot_ssh.run, kwargs={"port": 2222}, daemon=True).start()
    threading.Thread(target=honeypot_ftp.run, kwargs={"port": 2121}, daemon=True).start()
    threading.Thread(
        target=lambda: honeypot_web.app.run(host="0.0.0.0", port=8080, threaded=True, use_reloader=False),
        daemon=True,
    ).start()

    time.sleep(1)
    print("\n=== DeceptionNet is running ===")
    print("  SSH honeypot : ssh test@localhost -p 2222")
    print("  FTP honeypot : ftp localhost 2121")
    print("  Web honeypot : http://localhost:8080")
    print("  Dashboard    : http://localhost:5000")
    print("================================\n")

    # Dashboard runs in the main thread so Ctrl+C stops everything cleanly.
    dashboard_api.app.run(host="0.0.0.0", port=5000, threaded=True, use_reloader=False)


if __name__ == "__main__":
    main()
