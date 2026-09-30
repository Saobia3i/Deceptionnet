# DeceptionNet — A Honeypot-Based Intrusion Detection & Attacker Behavior Analysis System

Fake SSH, FTP, and web-login services that log every attacker interaction,
classify it (brute force / SQL injection / XSS / port scan / recon), and
show it live on a dashboard. Nothing here ever grants real access —
every service always denies login.

## 1. Setup

```bash
pip install -r requirements.txt --break-system-packages
```

(Drop `--break-system-packages` if you're using a virtual environment instead.)

## 2. Run everything

```bash
python run_all.py
```

This starts, in one process:

| Service          | Port | Purpose                                  |
|------------------|------|-------------------------------------------|
| SSH honeypot     | 2222 | Fake SSH login, logs username/password    |
| FTP honeypot     | 2121 | Fake FTP login, logs username/password    |
| Web honeypot     | 8080 | Fake admin login + search box (SQLi/XSS)  |
| Dashboard        | 5000 | Live view of everything above             |

Open **http://localhost:5000** in your browser for the dashboard.

## 3. Generate demo traffic

In a second terminal, while `run_all.py` is still running:

```bash
python test_attacks.py
```

This fires a realistic batch of attacks (FTP brute force, SQLi, XSS, a port
scan) so your dashboard fills up with data instantly — useful for
screenshots or a dry run before your live demo.

## 4. Live demo script (for your instructor)

Instead of (or in addition to) `test_attacks.py`, do this live:

1. **Brute force (SSH):**
   ```bash
   for pw in admin 123456 password root123 letmein toor; do
     sshpass -p "$pw" ssh -o StrictHostKeyChecking=no -p 2222 admin@localhost
   done
   ```
   (Install `sshpass` first: `apt install sshpass`. Each attempt fails —
   that's expected — but watch the dashboard flag it as `brute_force`
   after the 5th attempt in under a minute.)

2. **SQL injection (Web):**
   ```bash
   curl -X POST http://localhost:8080/login \
        -d "username=admin' OR '1'='1&password=x"
   ```
   Dashboard flags this instantly as `sqli`.

3. **XSS (Web):**
   ```bash
   curl "http://localhost:8080/search?q=<script>alert(1)</script>"
   ```
   Dashboard flags this as `xss`.

4. **Port scan:**
   ```bash
   nmap -p 21,22,2121,2222,8080 localhost
   ```
   Multiple ports touched quickly from the same IP → flagged `port_scan`.
   (This is also a nice callback to your Nmap lab — you're now on the
   *defending* side of a scan you already know how to run.)

5. Click **Export PDF Report** on the dashboard to generate a written
   summary for your submission.

## 5. How classification works (classifier.py)

All rule-based, no ML — every flag is explainable:

- **SQLi** — payload matches patterns like `' OR '1'='1`, `UNION SELECT`, `--`
- **XSS** — payload contains `<script>`, `onerror=`, `javascript:`, etc.
- **Brute force** — 5+ attempts from the same IP within 60 seconds
- **Port scan** — 4+ distinct ports touched by the same IP within 30 seconds
- **Recon** — anything else (a single probe, a banner grab, etc.)

## 6. Project structure

```
deceptionnet/
├── db.py              # SQLite logging + query helpers
├── classifier.py       # Rule-based attack classification
├── honeypot_ssh.py      # Fake SSH server (paramiko)
├── honeypot_ftp.py      # Fake FTP server (raw sockets)
├── honeypot_web.py      # Fake admin login + search box (Flask)
├── dashboard_api.py      # Dashboard backend + PDF export
├── dashboard/index.html  # Dashboard frontend (Chart.js, auto-refreshes)
├── run_all.py           # Launches everything together
├── test_attacks.py       # Generates demo attack traffic
└── requirements.txt
```

## 7. Extending it further (optional, for extra marks)

- **Wireshark**: run a capture (`sudo tcpdump -i lo -w capture.pcap`) while
  `test_attacks.py` runs, then open the `.pcap` in Wireshark and include
  screenshots of the raw packets in your report — evidence beyond just the
  dashboard.
- **Scapy**: replace parts of `test_attacks.py` with hand-crafted Scapy
  packets (e.g., a real SYN scan) instead of plain `socket.connect()`, to
  show lower-level packet crafting skills.
- **Geolocation**: in `db.py` / the honeypot files, look up `source_ip`
  against a free API like `ip-api.com` and store the country — the schema
  already has a `country` column ready for it.
