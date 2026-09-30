# DeceptionNet — Project Explanation & Testing Guide

**Why, What, and How this project works — with exact test commands and
what each result proves, for demonstrating to your instructor.**

---

## 1. WHY — The Problem This Solves

Most security tools (firewalls, antivirus, vulnerability scanners) work by
**blocking or detecting known attack signatures on real systems**. But
there's a gap: security teams often don't know *who* is attacking them,
*how* they're attacking, or *what they're trying* until it's too late —
because real systems only tell you an attack happened, not much about the
attacker's behavior leading up to it.

**Honeypots solve a different problem**: instead of protecting a real
system, you deploy a **fake system that looks real** but has nothing of
value on it. Since no legitimate user has any reason to connect to it,
**every single interaction with a honeypot is, by definition, suspicious**
— there's no "normal traffic" to filter out, unlike a real server. This
makes honeypots extremely good at:

- Capturing real attacker behavior (what credentials do they try? what
  payloads?) with zero false positives from legitimate use
- Acting as an early-warning system — if someone's probing your honeypot,
  they may be probing your real systems too
- Research and analysis — studying attack patterns safely, since the
  attacker never touches anything real

**DeceptionNet exists to demonstrate this concept hands-on**: build fake
services, watch real attack techniques hit them, and prove that even
simple rule-based logic can correctly identify what kind of attack just
happened — in real time, with a live dashboard.

---

## 2. WHAT — What We Actually Built

**DeceptionNet is a honeypot-based intrusion detection and attacker
behavior analysis system.** It has three fake "bait" services and one
dashboard that watches all of them.

### Core Features

| Feature | Description |
|---|---|
| **Fake SSH server** | Accepts SSH connection attempts on port 2222, prompts for username/password like a real server, logs everything, always rejects login |
| **Fake FTP server** | Accepts FTP login attempts on port 2121, speaks real FTP protocol (`USER`/`PASS`/`QUIT`), logs everything, always rejects login |
| **Fake admin web login & Honeytoken Bait** | A realistic admin login page (port 8080) with a search box and embedded Honeytokens (fake API key `dnet_honey_51Nx8fQ2eZvKYlo9A3bC7dEfGhIjKlMnOp`) designed to lure threat actors into using fake credentials |
| **Automatic attack classification** | Every logged event is automatically tagged as: **Honeytoken Triggered**, **Brute Force**, **SQL Injection**, **XSS**, **Port Scan**, or **Recon** — using explainable, rule-based logic (no black-box ML) |
| **Live dashboard** | Real-time table of every attack attempt, charts (attacks over time, attack type breakdown, top attacker IPs), and an alert banner when activity spikes |
| **PDF report export** | One-click export of a full attack summary for submission |

### What makes this different from the other lab projects (vuln scanner,
firewall simulator, etc.)?

A **vulnerability scanner** finds weaknesses in a *real* system.
A **firewall simulator** blocks *incoming* traffic to a *real* system.

**DeceptionNet does neither** — it has no real system to protect. It's
pure **deception**: it convinces an attacker they've found something real,
then studies them while they try to break in. This is why, no matter what
an attacker sends it, the honeypot must **never actually grant access** —
that's not a bug, that's the entire design.

---

## 3. HOW — How It Actually Works (step by step)

### Step 1: The bait

Each fake service opens a real network port and speaks the real protocol
just enough to be convincing:
- The SSH honeypot uses `paramiko` to do a real SSH handshake (encryption
  setup, banner exchange) — so `ssh user@host -p 2222` genuinely prompts
  for a password, just like a real SSH server would.
- The FTP honeypot manually replies to `USER`/`PASS` commands with the
  exact response codes a real FTP server uses (`331`, `530`).
- The web honeypot is a normal-looking Flask web page with a login form,
  a search box, and embedded Honeytoken comments (`dnet_honey_51Nx8fQ2eZvKYlo9A3bC7dEfGhIjKlMnOp`) — nothing about it visually suggests it's fake.

### Step 2: Logging

The moment someone submits a username/password, or types something into
the search box, or even just connects and disconnects, that event gets
written to a local database (`deceptionnet.db`) with: timestamp, which
service, the attacker's IP/port, what they typed, and what type of attack
it looks like.

### Step 3: Classification (the "brain")

A separate module (`classifier.py`) looks at each event and decides what
kind of attack it is, using simple, explainable rules — **not machine
learning**, so every decision can be justified in one sentence:

| Attack Type | Rule |
|---|---|
| **Honeytoken Triggered** | Attacker accesses fake debug API endpoints (`/api/v1/internal`) or submits the leaked honeytoken `dnet_honey_51Nx8fQ2eZvKYlo9A3bC7dEfGhIjKlMnOp` |
| **SQL Injection** | The submitted text contains SQL attack patterns like `' OR '1'='1`, `UNION SELECT`, or a SQL comment `--` |
| **XSS (Cross-Site Scripting)** | The submitted text contains `<script>`, `onerror=`, `javascript:`, etc. |
| **Brute Force** | The same IP address tried logging in **5 or more times within 60 seconds** |
| **Port Scan** | The same IP address touched **4 or more different ports within 30 seconds** |
| **Recon** | Anything else — a single connection, a probe, a banner grab (default/fallback category) |

The check order matters: Honeytokens & content-based checks (SQLi/XSS) run first because
they're unambiguous when present; behavioral checks (brute force/port
scan) run after, since they depend on counting recent history for that IP.


### Step 4: The dashboard

`dashboard_api.py` reads the same database and serves it as a webpage.
The webpage automatically re-fetches the data every 3 seconds, so as new
attacks come in, the table and charts update live without refreshing the
page.

---

## 4. HOW TO TEST — Exact Commands, Expected Output, and What It Proves

This is the part to actually run in front of your instructor. Do this in
**two terminals**: Terminal A runs the system, Terminal B sends attacks.

### Setup (once)

**Terminal A:**
```bash
cd deceptionnet
pip install -r requirements.txt --break-system-packages
python run_all.py
```
Wait until you see `=== DeceptionNet is running ===`. Then open
**http://localhost:5000** in your browser — this is the dashboard, keep it
visible during the whole demo.

---

### Test 1 — Brute Force Detection

**What you do (Terminal B):**
```bash
for pw in admin 123456 password root123 letmein toor; do
  sshpass -p "$pw" ssh -o StrictHostKeyChecking=no -p 2222 admin@localhost
done
```
*(If `sshpass` isn't installed: `sudo apt install sshpass`, or just run
`python test_attacks.py` instead — it does this automatically via FTP.)*

**Input, in plain terms:** 6 rapid login attempts with different
passwords, all from the same machine, within a few seconds.

**Expected output on the dashboard:**
- The Live Event Log fills with 6 new rows, service = `ssh`
- After the 5th attempt, the `attack_type` column changes to
  **`brute_force`** (shown in red)
- The "Brute Force" stat card at the top increments
- The Attack Type Breakdown chart gets a new red slice

**What this proves:** *"5+ login attempts from one IP within 60 seconds
were automatically flagged as a brute-force attack — this is exactly how
real intrusion detection systems catch password-guessing attacks, without
needing to know the passwords in advance."*

---

### Test 2 — SQL Injection Detection

**What you do (Terminal B):**
```bash
curl -X POST http://localhost:8080/login \
     -d "username=admin' OR '1'='1&password=anything"
```

**Input, in plain terms:** submitting `admin' OR '1'='1` as the username —
a classic SQL injection payload that (on a real, poorly-coded system)
tricks the login query into always returning true, bypassing
authentication entirely.

**Expected output on the dashboard:**
- New row appears, service = `web`, username shows the payload
- `attack_type` = **`sqli`** immediately (no waiting — this is a
  content-based check, not behavioral)
- The "SQL Injection" stat card increments

**What this proves:** *"The system recognized a real SQL injection
signature the instant it arrived, before the attacker even got a second
attempt — proving the fake login form is convincingly attackable, and the
detection is signature-based and instant."*

---

### Test 3 — XSS (Cross-Site Scripting) Detection

**What you do (Terminal B):**
```bash
curl "http://localhost:8080/search?q=<script>alert(1)</script>"
```

**Input, in plain terms:** submitting a `<script>` tag into the search
box — if the website were vulnerable and reflected this back into the
page without sanitizing it, this script would actually execute in a
victim's browser.

**Expected output on the dashboard:**
- New row appears, service = `web`, payload shows the script tag
- `attack_type` = **`xss`**
- The "XSS Attempts" stat card increments

**What this proves:** *"The search box is a realistic injection target —
exactly the kind of input field real attackers probe first — and the
payload was correctly identified as a script-injection attempt."*

---

### Test 4 — Port Scan Detection

**What you do (Terminal B):**
```bash
nmap -p 21,22,2121,2222,8080,5000 localhost
```
*(No `nmap`? Use `python test_attacks.py`, which includes a simplified
port-probe simulation.)*

**Input, in plain terms:** quickly checking which of several ports are
open — the very first thing almost every real attacker or automated
scanner does before deciding what to attack.

**Expected output on the dashboard:**
- Multiple new rows, one per port touched
- Once 4+ distinct ports are hit within 30 seconds, those events get
  tagged **`port_scan`**
- The "Port Scans" stat card increments

**What this proves:** *"Reconnaissance behavior — checking multiple ports
in a short window — was distinguished from a single random connection,
because real attacks almost always start with scanning, and defenders
need to catch that stage, not just the final breach attempt."*

---

### Test 5 — Recon / Fallback Behavior

**What you do (Terminal B):**
```bash
curl http://localhost:8080/
```
Just load the page once, do nothing else.

**Input, in plain terms:** a single, harmless connection — no credentials
submitted, no payload, no repetition.

**Expected output on the dashboard:**
- One row, `attack_type` = **`recon`** (the default/fallback category)

**What this proves:** *"The system doesn't over-flag everything as an
attack — a single, non-malicious-looking connection correctly falls back
to the lowest-severity category, showing the classification logic
discriminates rather than just labeling everything 'attack'."*

---

### Test 6 — Export Evidence

**What you do:** click **"Export PDF Report"** on the dashboard, or visit
`http://localhost:5000/api/report.pdf`.

**Expected output:** a downloaded PDF listing total events, the attack
type breakdown, top attacker IPs, and the most recent 50 raw events.

**What this proves:** *"The system doesn't just detect attacks live — it
produces a persistent, reviewable record, the way a real SOC (Security
Operations Center) would need for incident review after the fact."*

---

## 5. One-Command Version (if you're short on time in the demo)

```bash
python test_attacks.py
```
This runs Tests 1–4 automatically back-to-back, so the dashboard fills
with a realistic mix of all four attack types in about 5 seconds. Good for
a fast overview; the manual commands above are better if your instructor
wants to see *you* trigger each one and explain it live.

---

## 6. Anticipated Questions From Your Instructor

**"How is this different from just logging everything?"**
Because of the classification layer — it doesn't just record that
something happened, it explains *what kind* of attack it was, using
specific, defensible rules you can point to in the code.

**"Why rule-based instead of AI/ML?"**
Explainability. In a security context, you need to be able to say
*exactly* why something was flagged — a rule like "5 login attempts in 60
seconds" is auditable; a black-box model's decision often isn't. This is
also a realistic design choice — many real intrusion detection systems
(like Snort) are signature/rule-based for exactly this reason.

**"Could an attacker tell this is a honeypot?"**
Possibly, with enough probing (e.g., timing analysis, or noticing it never
actually grants access no matter what's tried) — but that's true of most
low-interaction honeypots. This project is a low-interaction honeypot by
design (safer, simpler, faster to build) rather than a high-interaction
one (which would simulate a full fake OS/filesystem — much more complex
and outside this lab's scope).

**"What happens if two attackers hit it at the same time?"**
Each service runs attacker connections in separate threads, and all
database writes go through a lock in `db.py` to prevent them from
corrupting each other — so concurrent attackers are handled safely.
