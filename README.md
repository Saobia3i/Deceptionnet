# DeceptionNet — A Honeypot-Based Intrusion Detection & Attacker Behavior Analysis System

DeceptionNet deploys fake, intentionally exposed network services (SSH, FTP, Web Admin Login with Honeytokens) that log every attacker interaction, classify payloads (Honeytoken Triggers, Honeytoken Sessions, Brute Force, SQL Injection, XSS, Port Scan, Recon), and present real-time analytics on a live web dashboard.

---

## 1. Core Architecture & Deception Mechanics

* **Fake SSH Server** (`port 2222`): Speaks standard SSH handshake via Paramiko, handles non-SSH probes gracefully, and logs credentials.
* **Fake FTP Server** (`port 2121`): Fakes standard FTP `USER`/`PASS` responses via raw sockets, always denying access.
* **Web Admin & Honeytoken Baits** (`port 8080`): Fake admin panel with a search box and 4 multi-location Honeytokens (`dnet_honey_...` keys embedded in HTML comments, `robots.txt`, JS config, and `.env` leaks).
* **360° Request Middleware**: Scans URLs, query parameters, `Authorization: Bearer` headers, `X-API-Key` headers, cookies, and POST bodies. Returns convincing fake JSON debug payloads (`"access_granted": true`) to trap attackers.
* **Active Session Tagging**: Automatically flags all subsequent activity from a honeytoken-triggered IP as `honeytoken_session`.
* **Live Dashboard & PDF Export** (`port 5000`): Real-time Chart.js analytics, grouped alert deduplication, transparent glassmorphism UI, and one-click PDF incident report generation.

---

## 2. Quick Setup

```bash
pip install -r requirements.txt --break-system-packages
```

---

## 3. Run Everything

```bash
python run_all.py
```

Open **[http://localhost:5000](http://localhost:5000)** in your browser for the live dashboard.

---

## 4. Generate Demo Attack Traffic

In a second terminal, run:

```bash
python test_attacks.py
```

This simulates FTP brute force, SQL injection, XSS, port scanning, and a Honeytoken trigger back-to-back in 5 seconds.

---

## 5. Live Demo Commands (Step-by-Step for Presentation)

1. **Honeytoken Deception Test (Authorization Header):**
   ```powershell
   curl.exe -H "Authorization: Bearer dnet_honey_88AaBbCcDdEeFfGgHhIiJjKkLlMmNnOo" http://localhost:8080/
   ```
   *Dashboard immediately displays a purple `honeytoken_triggered` badge & critical alert.*

2. **SQL Injection (Web):**
   ```powershell
   curl.exe -X POST http://localhost:8080/login -d "username=admin' OR '1'='1&password=x"
   ```

3. **XSS Payload (Search Box):**
   ```powershell
   curl.exe "http://localhost:8080/search?q=<script>alert(1)</script>"
   ```

4. **FTP Brute Force:**
   ```powershell
   py -c "import socket; [socket.create_connection(('localhost', 2121)).sendall(f'USER admin\r\nPASS pass{i}\r\n'.encode()) for i in range(6)]"
   ```

5. **PDF Export:** Click **Export PDF Report** on the dashboard or open `http://localhost:5000/api/report.pdf`.

---

## 6. How Classification Works (`classifier.py`)

Deterministic, 100% explainable rule-based logic:

1. **Honeytoken Triggered** — Matches `dnet_honey_` keys or `honeytoken` keywords across request URLs, headers, or body.
2. **SQLi** — Payload matches `' OR '1'='1`, `UNION SELECT`, or SQL comments `--`.
3. **XSS** — Payload contains `<script>`, `onerror=`, `javascript:`, etc.
4. **Honeytoken Session** — Subsequent traffic from an IP address with an active Honeytoken trigger.
5. **Brute Force** — 5+ login attempts from the same IP within 60 seconds.
6. **Port Scan** — 4+ distinct ports touched by the same IP within 30 seconds.
7. **Recon** — Default fallback for single connections or banner probes.

---

## 7. Project Structure

```
deceptionnet/
├── db.py                 # Shared SQLite database layer + session tagging helpers
├── classifier.py          # Deterministic rule-based classification engine
├── honeypot_ssh.py        # Fake SSH server (paramiko) with robust probe handling
├── honeypot_ftp.py        # Fake FTP server (raw sockets)
├── honeypot_web.py        # Web honeypot + 4 multi-location Honeytoken baits
├── dashboard_api.py        # Dashboard API + PDF report generator
├── dashboard/
│   ├── index.html         # Live dashboard (Chart.js, translucent Glassmorphism UI)
│   └── backgroundImage.jpg# Cyber shield dashboard background image
├── run_all.py             # Single-command launcher for all 4 services
├── test_attacks.py        # Automated multi-attack simulation test suite
├── RUN_SYSTEM.md          # Comprehensive demonstration & testing guide
├── PROJECT_EXPLAINED.md   # Architectural & conceptual project explanation
└── requirements.txt
```

