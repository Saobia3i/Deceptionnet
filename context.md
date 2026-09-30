# context.md — DeceptionNet Project Context (for AI coding agents)

> Read this fully before making any changes. This file exists so an AI agent
> (Claude Code, Cursor, Copilot, etc.) understands the project's purpose,
> constraints, and boundaries without re-deriving them from scratch.

---

## 1. What this project is

**DeceptionNet** is a university cybersecurity lab open-end project: a
**honeypot-based intrusion detection and attacker behavior analysis system**.

It deploys fake, intentionally exposed network services (SSH, FTP, a web
admin login) that look real to an attacker or scanner. Every connection,
login attempt, and payload sent to these fake services is logged, classified
by attack type, and shown live on a dashboard.

**The entire point of a honeypot is that it never actually works as a real
service.** No fake service in this project should ever grant real access,
return real data, or execute anything an attacker sends it.

## 2. Why this project exists — lab context

This is being built for a **university Cyber Security Lab open-end project
assignment**. The student can pick any topic from an instructor-provided list
(vulnerability scanner, password vault, firewall simulator, steganography
tool, PGP email system, honeypot, etc.) and must build something with a UI.

**This means the scope is intentionally a student lab project, not a
production security product.** Keep that framing in every decision:

- It runs on `localhost` / a local network, for a live classroom demo.
- It does not need to survive real-world adversarial conditions, scale to
  production traffic, or be hardened against sophisticated evasion.
- The evaluator is a course instructor, not a security auditor — clarity,
  a working live demo, and explainable logic matter more than
  enterprise-grade robustness.
- The student already completed earlier labs in this course: AES modes of
  operation, 2FA (bcrypt + TOTP), Nmap scanning, network protocol analysis,
  and PGP/Thunderbird secure email. Those are NOT part of this project —
  don't pull them in unless the student explicitly asks to combine them.

## 3. Hard boundaries — do not exceed lab scope

An AI agent working on this repo should **stay within these boundaries**
unless the student (the repo owner) explicitly asks otherwise in a given
session:

- **Do not** turn any honeypot service into a real, functioning service.
  `check_auth_password` in `honeypot_ssh.py`, the `PASS` handler in
  `honeypot_ftp.py`, and `/login` in `honeypot_web.py` must always reject
  / deny. Never add a "backdoor" credential that actually succeeds.
- **Do not** add real exploitation capability (e.g., don't turn the search
  box into an actually-vulnerable SQL query against a real database, don't
  add remote code execution, don't add a real file system to the fake FTP
  server). The whole design intentionally keeps these services fake and
  inert — that's what makes it safe to demo.
- **Do not** add functionality for scanning, attacking, or logging
  real third-party targets. This project only fakes services locally and
  only logs connections *to* those fake services — it is not an offensive
  tool aimed outward.
- **Do not** silently expand scope into unrelated lab topics (e.g. don't
  bolt on a password cracker, a vulnerability scanner, or an ML model)
  unless asked. If something seems like a good addition, propose it and
  wait for confirmation rather than just building it.
- **Do not** add authentication, user accounts, or real data persistence
  beyond the local SQLite log — there is no "production deployment" phase
  for this project.
- Keep the rule-based classifier in `classifier.py` **rule-based and
  explainable**. Don't swap it for an ML model — the student needs to be
  able to explain, line by line, why each event was classified the way it
  was, in a live viva/demo.

If a request from the student clearly asks to go beyond these boundaries
(e.g., "add a real vulnerable SQL query" or "make this scan a real
network"), the agent should flag that this changes the project's safety
posture and confirm intent before proceeding, rather than just doing it.

## 4. Tech stack

| Layer | Choice | Why |
|---|---|---|
| Language | Python 3.8+ | Everything below is Python |
| SSH honeypot | `paramiko` | Standard library for implementing SSH server-side handshakes without a real SSH daemon |
| FTP honeypot | Raw `socket` (no library) | FTP's text protocol is simple enough to hand-roll; avoids pulling in a real FTP server library that might expose real file access |
| Web honeypot | `Flask` | Fake admin login page + a reflected search box, both bait for credential and injection attacks |
| Dashboard backend | `Flask` (separate app) | Serves the frontend + a small JSON API (`/api/events`, `/api/stats`) + PDF export |
| Dashboard frontend | Single `index.html`, vanilla JS + `Chart.js` (via CDN) | No build step needed — keeps setup to `pip install` only |
| Storage | SQLite (`deceptionnet.db`) | Zero-config, file-based, fine for local demo traffic volume |
| PDF export | `reportlab` | Generates `deceptionnet_report.pdf` for lab submission |
| Test traffic generator | `requests` + raw sockets | `test_attacks.py` fires realistic attack patterns for demo/dev without waiting for a real attacker |

No frontend framework, no build tooling, no database server, no
containerization — this is intentional. Keep it this way; adding Docker,
React, Postgres, etc. would be scope creep for a lab project meant to run
with `pip install -r requirements.txt && python run_all.py`.

## 5. Architecture

```
deceptionnet/
├── db.py                 # SQLite schema + all read/write helpers
├── classifier.py          # Rule-based attack classification (no ML)
├── honeypot_ssh.py         # Fake SSH server (paramiko), port 2222
├── honeypot_ftp.py         # Fake FTP server (raw sockets), port 2121
├── honeypot_web.py         # Fake admin login + search box (Flask), port 8080
├── dashboard_api.py         # Dashboard backend + JSON API + PDF export, port 5000
├── dashboard/index.html      # Dashboard frontend (polls the API every 3s)
├── run_all.py                # Launches all 4 services in one process (threads)
├── test_attacks.py            # Fires demo attack traffic at a running instance
├── requirements.txt
└── README.md                 # Human-facing setup + live demo script
```

**Data flow:** attacker/test-script → honeypot service (`honeypot_*.py`) →
`db.log_event()` writes a row → `classifier.classify()` determines
`attack_type` → the row is updated with that type → dashboard frontend polls
`dashboard_api.py`'s `/api/events` and `/api/stats` every 3 seconds and
re-renders the table + charts.

**Event ordering quirk (intentional, don't "fix" without understanding
why):** each honeypot logs the raw event first (with whatever default
`attack_type` `log_event` was given), then calls `classify()` — which looks
at *history* for that IP (via `recent_attempts_by_ip` /
`distinct_ports_by_ip` in `db.py`) — then does a small `UPDATE` to overwrite
that row's `attack_type` with the real classification. This is deliberate:
the classifier's brute-force/port-scan checks need to count the event that
just happened as part of the window, so the row must exist before
classification runs.

## 6. Database schema (`db.py`)

Single table, `events`:

| Column | Type | Notes |
|---|---|---|
| `id` | INTEGER PK | autoincrement |
| `timestamp` | TEXT | ISO 8601, UTC |
| `service` | TEXT | `ssh` \| `ftp` \| `web` |
| `source_ip` | TEXT | attacker's IP |
| `source_port` | INTEGER | attacker's source port, nullable |
| `username` | TEXT | nullable |
| `password` | TEXT | nullable |
| `raw_payload` | TEXT | free text — search query, error string, etc. |
| `attack_type` | TEXT | `honeytoken_triggered` \| `sqli` \| `xss` \| `brute_force` \| `port_scan` \| `recon` |
| `country` | TEXT | nullable, reserved for future geolocation (not yet implemented) |

## 7. Classification logic (`classifier.py`)

Rule-based, checked in this priority order — Honeytokens first (highest-fidelity deception bait), then content signatures, then behavioral patterns, then default to `recon`:

1. **Honeytoken Triggered** — regex match on `dnet_honey_` or `honeytoken` pattern when an attacker accesses bait API endpoints or uses leaked fake credentials
2. **SQLi** — regex match on `' OR '1'='1`, `UNION SELECT`, SQL comment
   `-- `, `; DROP TABLE`, `' OR 1=1` in username/password/payload
3. **XSS** — regex match on `<script`, `onerror=`, `onload=`, `javascript:`
4. **Brute force** — 5+ events from the same IP on the same service within
   60 seconds (`BRUTE_FORCE_THRESHOLD` / `BRUTE_FORCE_WINDOW` in
   `classifier.py`)
5. **Port scan** — 4+ distinct source ports from the same IP within 30
   seconds (`PORT_SCAN_THRESHOLD` / `PORT_SCAN_WINDOW`) — note this is a
   simplified proxy for scan detection, not a real SYN-scan detector
6. **Recon** — fallback for anything else (single probes, banner grabs)

If asked to improve detection accuracy, prefer tightening/adding to these
explicit rules over introducing statistical or ML-based detection — the
explainability is a project requirement, not just a style choice.

## 8. How to run

```bash
cd deceptionnet
pip install -r requirements.txt --break-system-packages   # omit flag on Windows
python run_all.py
```

This starts, in one process (threads), all four services:

| Service | Port | URL/connection |
|---|---|---|
| SSH honeypot | 2222 | `ssh anyuser@localhost -p 2222` |
| FTP honeypot | 2121 | `ftp localhost 2121` |
| Web honeypot | 8080 | `http://localhost:8080` |
| Dashboard | 5000 | `http://localhost:5000` |

Individual services can also be run standalone (each file has a
`if __name__ == "__main__"` block with `argparse` for `--port`), e.g.
`python honeypot_ssh.py --port 2222` — useful for isolated debugging.

Generate demo traffic: `python test_attacks.py` (run in a second terminal
while `run_all.py` is running) — simulates FTP brute force, a SQLi login
attempt, an XSS search query, and a quick port probe.

## 9. Environment / platform notes

- Pure Python, no OS-specific code except default socket behavior.
- `paramiko` on Windows sometimes needs `pip install pypiwin32` as a
  transitive dependency in older environments — flag this if SSH honeypot
  setup fails on Windows and `paramiko` itself installed fine.
- Ports 2222/2121/8080/5000 are unprivileged (>1024) specifically so this
  runs without `sudo`/admin rights on any OS.
- `deceptionnet.db` is created on first run in the working directory; it's
  safe to delete between demo runs to reset all logged data.

## 10. What "done" looks like for this project

The lab deliverable is: a **live demo** where the instructor watches an
attack happen (brute force / SQLi / XSS / port scan) and sees it appear,
correctly classified, on the dashboard in real time — plus a PDF report
export and a short written explanation of the detection logic. Optimize
work on this repo toward that outcome: a reliable local demo and a clear
story, not additional unrelated features.

Already-approved extension ideas (only if the student asks for them):
- **Wireshark**: capture a `.pcap` of demo traffic for the report as extra
  evidence, alongside the dashboard.
- **Scapy**: replace some of `test_attacks.py`'s plain-socket probes with
  hand-crafted Scapy packets (e.g. a real SYN scan) to show lower-level
  packet-crafting skill.
- **Geolocation**: populate the already-reserved `country` column via a
  free IP geolocation API (e.g. `ip-api.com`) and show it on the dashboard.

Anything beyond this list should be treated as a new decision to check with
the student on, not an assumed next step.
