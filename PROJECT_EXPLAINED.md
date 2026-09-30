# DeceptionNet — Project Explanation & Testing Guide

**Why, What, and How this project works — with exact test commands and what each result proves, for demonstrating to your instructor.**

---

## 1. WHY — The Problem This Solves

Most security tools (firewalls, antivirus, vulnerability scanners) work by **blocking or detecting known attack signatures on real systems**. But there's a gap: security teams often don't know *who* is attacking them, *how* they're attacking, or *what they're trying* until it's too late — because real systems only tell you an attack happened, not much about the attacker's behavior leading up to it.

**Honeypots solve a different problem**: instead of protecting a real system, you deploy a **fake system that looks real** but has nothing of value on it. Since no legitimate user has any reason to connect to it, **every single interaction with a honeypot is, by definition, suspicious** — there's no "normal traffic" to filter out, unlike a real server. This makes honeypots extremely good at:

- Capturing real attacker behavior (what credentials do they try? what payloads?) with zero false positives from legitimate use
- Acting as an early-warning system — if someone's probing your honeypot, they may be probing your real systems too
- Research and analysis — studying attack patterns safely, since the attacker never touches anything real

**DeceptionNet exists to demonstrate this concept hands-on**: build fake services, watch real attack techniques hit them, and prove that even simple rule-based logic can correctly identify what kind of attack just happened — in real time, with a live dashboard.

---

## 2. WHAT — What We Actually Built

**DeceptionNet is a honeypot-based intrusion detection and attacker behavior analysis system.** It has three fake "bait" services and one dashboard that watches all of them.

### Core Features

| Feature | Description |
|---|---|
| **Fake SSH server** | Accepts SSH connection attempts on port 2222, prompts for username/password like a real server, logs everything, always rejects login |
| **Fake FTP server** | Accepts FTP login attempts on port 2121, speaks real FTP protocol (`USER`/`PASS`/`QUIT`), handles TCP probe disconnects, logs everything, always rejects login |
| **Fake admin web login & Honeytoken Bait** | A realistic admin login page (port 8080 or port 5000) with a search box and embedded Honeytokens (fake API key `dnet_honey_...`) designed to lure threat actors into using fake credentials |
| **Nmap & Directory Scanner Recon Middleware** | Catches automated web directory enumeration (`http-enum`), unmapped path probes, and scanner recon attempts, logging them immediately as `recon` |
| **Smart Proxy IP Resolution** | Resolves true attacker client IPs through reverse proxies, Cloudflare, and ngrok using `CF-Connecting-IP`, `X-Real-IP`, and `X-Forwarded-For` headers |
| **Automatic attack classification** | Every logged event is automatically tagged as: **Honeytoken Triggered**, **Honeytoken Session**, **Brute Force**, **SQL Injection**, **XSS**, **Port Scan**, or **Recon** — using explainable, rule-based logic (no black-box ML) |
| **Live dashboard** | Real-time table of every attack attempt, charts (attacks over time, attack type breakdown, top attacker IPs), and an alert banner when activity spikes |
| **PDF report export** | One-click export of a full attack summary for submission |

---

## 3. HOW — How It Actually Works (Step by Step)

### Step 1: The bait

Each fake service opens a real network port and speaks the real protocol just enough to be convincing:
- The SSH honeypot uses `paramiko` to do a real SSH handshake (encryption setup, banner exchange) — so `ssh user@host -p 2222` genuinely prompts for a password, just like a real SSH server would.
- The FTP honeypot manually replies to `USER`/`PASS` commands with the exact response codes a real FTP server uses (`331`, `530`), and catches immediate TCP probe disconnects.
- The web honeypot is a normal-looking Flask web page with a login form, a search box, and 4 embedded Honeytoken baits (`dnet_honey_...` keys) — nothing about it visually suggests it's fake.

### Step 2: Logging

The moment someone submits a username/password, types something into the search box, accesses a honeytoken, or runs an Nmap path scan, that event gets written to a local database (`deceptionnet.db`) with: timestamp, which service, the attacker's IP/port, what they typed, and what type of attack it looks like.

### Step 3: Classification (the "brain")

A separate module (`classifier.py`) looks at each event and decides what kind of attack it is, using simple, explainable rules — **not machine learning**, so every decision can be justified in one sentence:

| Attack Type | Rule |
|---|---|
| **Honeytoken Triggered** | Attacker accesses fake debug API endpoints (`/api/v1/internal`) or submits the leaked honeytoken `dnet_honey_...` |
| **SQL Injection** | The submitted text contains SQL attack patterns like `' OR '1'='1`, `UNION SELECT`, or a SQL comment `--` |
| **XSS** | The submitted text contains HTML/JS injection tags like `<script>`, `onerror=`, `javascript:`, etc. |
| **Honeytoken Session** | Subsequent traffic from an IP address with an active Honeytoken trigger within 1 hour |
| **Brute Force** | 5 or more login attempts on the same service from the same IP address within 60 seconds |
| **Port Scan** | The same IP address connected to 4 or more distinct ports within 30 seconds |
| **Recon** | Nmap scanner probes, directory enumeration (`http-enum`), unmapped path probes, single connections, or SSH/FTP banner disconnects |

---

## 4. Single-Port Cloud Deployment vs Local Architecture

When deployed on Cloud PaaS providers like **Render.com**:
1. **PaaS Ingress Single-Port Boundary:** Render exposes only standard Web HTTP/HTTPS ports (80/443) to the public internet via Cloudflare ingress proxy.
2. **Unified Route Handling:** We unified all Web Admin Baits (`/login`), Search Box (`/search`), Honeytokens (`/robots.txt`, `/config.js`, `/.env`), and Dashboard API (`/api/events`) onto single-port `dashboard_api.py` (Port 5000).
3. **Internal Loopback Health Filtering:** Host health checkers pinging SSH (2222) and FTP (2121) internally via `127.0.0.1` are filtered out so container health checks do not pollute live logs.

---

## 5. Reverse Proxy & Attacker IP Resolution

When an attacker connects through Cloudflare, ngrok, or a load balancer:
- The raw TCP connection comes from the proxy's IP address.
- `_client_ip()` checks:
  1. `CF-Connecting-IP` (Cloudflare Edge IP header)
  2. `X-Real-IP` (Reverse proxy header)
  3. `X-Forwarded-For` (First IP in comma-separated list)
  4. `request.remote_addr` (Fallback)

This guarantees the live event log always shows the attacker's true IP address.
