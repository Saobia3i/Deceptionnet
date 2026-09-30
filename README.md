# DeceptionNet — A Honeypot-Based Intrusion Detection & Attacker Behavior Analysis System

DeceptionNet deploys fake, intentionally exposed network services (SSH, FTP, Web Admin Login with Honeytokens) that log every attacker interaction, classify payloads (Honeytoken Triggers, Honeytoken Sessions, Brute Force, SQL Injection, XSS, Port Scan, Recon), and present real-time analytics on a live web dashboard.

---

## 1. Core Architecture & Deception Mechanics

* **Fake SSH Server** (`port 2222`): Speaks standard SSH handshake via Paramiko, handles non-SSH/Nmap probes gracefully, filters internal loopback health checks, and logs credentials.
* **Fake FTP Server** (`port 2121`): Fakes standard FTP `USER`/`PASS` responses via raw sockets, handles immediate TCP disconnect probes, always denying access.
* **Web Admin & Honeytoken Baits** (`port 8080` / Unified `port 5000` on Cloud): Fake admin panel with a search box and 4 multi-location Honeytokens (`dnet_honey_...` keys embedded in HTML comments, `robots.txt`, JS config, and `.env` leaks).
* **360° Request & Scanner Middleware**: Scans URLs, query parameters, `Authorization: Bearer` headers, `X-API-Key` headers, cookies, and POST bodies. Detects Nmap directory enumeration (`http-enum`) and unknown path probes as `recon`.
* **Smart Proxy IP Resolution**: Resolves true attacker IPs through reverse proxies, Cloudflare, and tunnels using `CF-Connecting-IP`, `X-Real-IP`, and `X-Forwarded-For` headers.
* **Internal Loopback Health Filter**: Filters out `127.0.0.1` container health checks on cloud platforms (e.g. Render) to ensure clean event logs.
* **Active Session Tagging**: Automatically flags all subsequent activity from a honeytoken-triggered IP as `honeytoken_session`.
* **Live Dashboard & PDF Export** (`port 5000`): Real-time Chart.js analytics, grouped alert deduplication, transparent glassmorphism UI with background image support, and one-click PDF incident report generation.

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

### Local Machine Testing:
1. **Honeytoken Deception Test (Authorization Header):**
   ```powershell
   curl.exe -H "Authorization: Bearer dnet_honey_88AaBbCcDdEeFfGgHhIiJjKkLlMmNnOo" http://localhost:5000/
   ```
   *Dashboard immediately displays a purple `honeytoken_triggered` badge & critical alert.*

2. **SQL Injection (Web Login):**
   ```powershell
   curl.exe -X POST http://localhost:5000/login -d "username=admin' OR '1'='1&password=x"
   ```

3. **XSS Payload (Search Box):**
   ```powershell
   curl.exe "http://localhost:5000/search?q=<script>alert(1)</script>"
   ```

4. **FTP Brute Force:**
   ```powershell
   py -c "import socket; [socket.create_connection(('localhost', 2121)).sendall(f'USER admin\r\nPASS pass{i}\r\n'.encode()) for i in range(6)]"
   ```

### Deployed Cloud App Testing (e.g., Render / PaaS):
1. **Nmap Service & Version Scan:**
   ```bash
   nmap -sV -p 80,443 deceptionnet-e307.onrender.com
   ```

2. **Nmap Web Directory Enumeration & Honeytoken Discovery Scan:**
   ```bash
   nmap --script=http-enum deceptionnet-e307.onrender.com
   ```
   *Dashboard live log immediately captures Nmap directory probes as `recon` and honeytoken access.*

3. **PDF Export:** Click **Export PDF Report** on the dashboard or open `http://localhost:5000/api/report.pdf`.

---

## 6. How Classification Works (`classifier.py`)

Deterministic, 100% explainable rule-based logic:

1. **Honeytoken Triggered** — Matches `dnet_honey_` keys or `honeytoken` keywords across request URLs, headers, or body.
2. **SQLi** — Payload matches `' OR '1'='1`, `UNION SELECT`, or SQL comments `--`.
3. **XSS** — Payload contains `<script>`, `onerror=`, `javascript:`, etc.
4. **Honeytoken Session** — Subsequent traffic from an IP address with an active Honeytoken trigger.
5. **Brute Force** — 5+ login attempts from the same IP within 60 seconds.
6. **Port Scan** — 4+ distinct ports touched by the same IP within 30 seconds.
7. **Recon** — Default fallback for Nmap path probes, single connections, or banner probes.

---

## 7. Project Structure

```
deceptionnet/
├── db.py                 # Shared SQLite database layer + session tagging helpers
├── classifier.py          # Deterministic rule-based classification engine
├── honeypot_ssh.py        # Fake SSH server (paramiko) with loopback filter
├── honeypot_ftp.py        # Fake FTP server (raw sockets) with TCP probe handling
├── honeypot_web.py        # Web honeypot + 4 multi-location Honeytoken baits + proxy IP parser
├── dashboard_api.py        # Unified Dashboard API, Web Baits, Nmap Recon Middleware & PDF report generator
├── dashboard/
│   ├── index.html         # Live dashboard (Chart.js, translucent Glassmorphism UI)
│   └── backgroundImage.jpg# Cyber shield dashboard background image
├── run_all.py             # Single-command launcher for all services
├── test_attacks.py        # Automated multi-attack simulation test suite
├── RUN_SYSTEM.md          # Comprehensive demonstration & testing guide
├── PROJECT_EXPLAINED.md   # Architectural & conceptual project explanation
├── context.md             # Complete technical context for AI coding assistants
└── requirements.txt
```
