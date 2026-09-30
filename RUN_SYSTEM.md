# DeceptionNet — How to Run & Demonstrate (Run Guide)

This guide provides step-by-step instructions to run **DeceptionNet**, demonstrate attack detection, Nmap scanner handling, single-port Cloud deployment, and advanced **Honeytoken Deception** to your course instructor.

---

## 🚀 1. How to Start the System

Open a terminal in the project directory (`deceptionnet`) and run:

```powershell
py run_all.py
```

### What this does:
Starts all honeypot services and the unified dashboard in parallel:
* **Dashboard, Web Admin Bait & API**: [http://localhost:5000](http://localhost:5000)
* **Web Honeypot Standalone Port**: [http://localhost:8080](http://localhost:8080)
* **SSH Honeypot**: `localhost:2222`
* **FTP Honeypot**: `localhost:2121`

---

## 🍯 2. Multi-Location Honeytoken Bait Architecture

DeceptionNet embeds realistic, Stripe/AWS-style honeytokens across 4 distinct bait locations to track exactly where an attacker discovered the credential:

| Bait Location | Endpoint / Resource | Realistic Honeytoken Key | Per-Location Tag |
|---|---|---|---|
| **HTML Comment** | `/` (Login Page source) | `dnet_honey_51Nx8fQ2eZvKYlo9A3bC7dEfGhIjKlMnOp` | `html_comment_login` |
| **Robots.txt** | `/robots.txt` (Disallow path) | `dnet_honey_99PqRsTuVwXyZ1234567890AbCdEfGhIj` | `robots_txt_disallow` |
| **JS Config Source** | `/config.js` (Frontend config) | `dnet_honey_88AaBbCcDdEeFfGgHhIiJjKkLlMmNnOo` | `config_js_source` |
| **Environment Leak** | `/.env` (Fake config file) | `dnet_honey_77ZzYyXxWwVvUuTtSsRrQqPpOoNnMmLl` | `env_file_leak` |

### **Global Request Middleware & Session Tagging:**
* **360° Inspection**: Scans URLs, query parameters, `Authorization: Bearer` headers, `X-API-Key` headers, cookies, and POST bodies.
* **Smart Proxy IP Parsing**: Extracts real client IP headers (`CF-Connecting-IP`, `X-Real-IP`, `X-Forwarded-For`) to resolve attacker IPs behind Cloudflare proxies, ngrok tunnels, or load balancers.
* **Internal Loopback Health Filter**: Filters out `127.0.0.1` SSH and FTP container health probes sent by PaaS host checkers (e.g. Render).
* **Convincing Decoy JSON Response**: When a honeytoken is triggered, the honeypot returns a fake 200 OK JSON debug session payload (`"access_granted": true`) to keep the attacker engaged.
* **Active Session Tagging**: Once an IP triggers a honeytoken, all subsequent requests from that IP within 1 hour are automatically tagged as **`honeytoken_session`**.

---

## 🧪 3. Live Demo Commands for Presentation

Open a **second terminal** window while `py run_all.py` is running and execute these commands step-by-step in front of your instructor:

### **A. Automatic Full Attack & Honeytoken Suite (Quickest Demo)**
Fires a mix of FTP brute-force, SQL injection, XSS, port scans, and honeytoken triggers in 5 seconds.
```powershell
py test_attacks.py
```

---

### **B. Honeytoken Deception Test (Bearer Header / API Key)**
Simulates an attacker using a leaked API key inside an Authorization header:
```powershell
curl.exe -H "Authorization: Bearer dnet_honey_88AaBbCcDdEeFfGgHhIiJjKkLlMmNnOo" http://localhost:5000/
```
> 📌 **What to show:** The system returns a convincing fake JSON response (`"access_granted": true`), and the dashboard immediately displays a purple **`honeytoken_triggered`** badge along with a **CRITICAL DECEPTION ALERT** banner!

---

### **C. Inspecting Bait Locations (Reconnaissance)**
Show how an attacker discovers honeytokens via common web reconnaissance:
```powershell
# 1. Inspect robots.txt disallow path
curl.exe http://localhost:5000/robots.txt

# 2. Inspect frontend JS configuration file
curl.exe http://localhost:5000/config.js

# 3. Inspect leaked .env file
curl.exe http://localhost:5000/.env
```

---

### **D. SQL Injection Attack (Web Honeypot)**
Submits a classic `' OR '1'='1` payload to the fake admin login form:
```powershell
curl.exe -X POST http://localhost:5000/login -d "username=admin' OR '1'='1&password=anything"
```

---

### **E. XSS (Cross-Site Scripting) Attack (Web Search)**
Submits a `<script>` tag into the search box (URL encoded for PowerShell compatibility):
```powershell
curl.exe "http://localhost:5000/search?q=%3Cscript%3Ealert(1)%3C/script%3E"
```

---

### **F. FTP Brute-Force Attack**
Simulates rapid consecutive password attempts on port 2121:
```powershell
py -c "import socket; [socket.create_connection(('localhost', 2121)).sendall(f'USER admin\r\nPASS pass{i}\r\n'.encode()) for i in range(6)]"
```

---

### **G. Cloud Deployed Nmap Testing (e.g. Render / Public URL)**
If testing a deployed instance (e.g. `deceptionnet-e307.onrender.com`):
```bash
# 1. Service Version Scan (Port 80/443 HTTPS):
nmap -sV -p 80,443 deceptionnet-e307.onrender.com

# 2. Web Directory Enumeration & Honeytoken Discovery Scan:
nmap --script=http-enum deceptionnet-e307.onrender.com
```

---

### **H. Export Incident PDF Report**
Generates and downloads a summary report for incident response auditing:
```powershell
Start-Process "http://localhost:5000/api/report.pdf"
```

---

## 💾 4. Why `deceptionnet.db` Shows Garbage in Text Editors & How to View It

`deceptionnet.db` is a **SQLite Binary Database File**. SQLite stores data in binary B-Tree format for high speed. Opening it in a plain text editor displays header byte symbols (`SQLite format 3...`).

### **How to Properly View Database Contents:**
* **Web Dashboard**: Open **[http://localhost:5000](http://localhost:5000)** in your browser.
* **Terminal Query (All Events)**:
  ```powershell
  py -c "import sqlite3; conn = sqlite3.connect('deceptionnet.db'); print('\n'.join([str(row) for row in conn.execute('SELECT id, timestamp, service, source_ip, attack_type, raw_payload FROM events ORDER BY id DESC LIMIT 10')]))"
  ```
* **Terminal Query (Honeytoken Triggers Only)**:
  ```powershell
  py -c "import sqlite3; conn = sqlite3.connect('deceptionnet.db'); print('\n'.join(str(r) for r in conn.execute('SELECT id, timestamp, service, source_ip, attack_type, raw_payload FROM events WHERE attack_type=? ORDER BY id DESC', ('honeytoken_triggered',))))"
  ```
* **VS Code Extension**: Install **SQLite Viewer** -> Right-click `deceptionnet.db` -> **Open Database**.

---

## 🎓 5. Instructor Presentation Script & Viva Q&A

### **30-Second Elevator Pitch**
> *"Sir, DeceptionNet is a Honeypot-based Intrusion Detection & Threat Deception System. It deploys fake SSH, FTP, and Web services embedded with realistic, multi-location Honeytokens (Stripe/AWS-style API keys in HTML comments, robots.txt, JS config, and .env files). Because legitimate users never touch fake services or honeytokens, 100% of activity is suspicious. We resolve true attacker IPs through proxy headers, handle Nmap directory probes as recon, trigger real-time alerts, tag attacker sessions, return convincing decoy payloads, and render live analytics on a web dashboard."*

### **Key Viva Questions & Answers**

1. **Why use Honeytokens alongside traditional rules?**
   * *Answer:* Traditional rules flag known attack signatures (SQLi/XSS). Honeytokens catch stealthy attackers who steal leaked credentials before they can compromise real systems — providing zero false-positive alerts.

2. **How does DeceptionNet handle Cloud Deployments (single-port PaaS like Render)?**
   * *Answer:* On single-port Cloud PaaS (e.g. Render), custom raw ports (2121, 2222) are not exposed by the PaaS ingress router. We unified all Web Admin Baits, Honeytokens, and API routes onto port 5000 (HTTP/HTTPS) while maintaining raw socket honeypots for direct IP / Docker deployments.

3. **How do you resolve the attacker's real IP when deployed behind Cloudflare or Reverse Proxies?**
   * *Answer:* We inspect `CF-Connecting-IP`, `X-Real-IP`, and `X-Forwarded-For` request headers before falling back to `request.remote_addr`.

4. **How do you filter noise from cloud health checkers?**
   * *Answer:* Automated loopback health probes (`127.0.0.1`) are filtered out at the transport layer so container health checks do not flood the live event log.

5. **How do you prevent alert fatigue if an attacker sends 500 requests?**
   * *Answer:* The dashboard uses grouped alert deduplication — aggregating high-frequency traffic into a single consolidated incident alert per IP.
