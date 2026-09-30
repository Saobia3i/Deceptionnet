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

---

## 2. Why this project exists — lab context

This is being built for a **university Cyber Security Lab open-end project
assignment**. The student can pick any topic from an instructor-provided list
(vulnerability scanner, password vault, firewall simulator, steganography
tool, PGP email system, honeypot, etc.) and must build something with a UI.

**This means the scope is intentionally a student lab project, not a
production security product.** Keep that framing in every decision:

- It runs on `localhost` / a local network or free PaaS (Render), for a live classroom demo.
- It does not need to survive real-world adversarial conditions, scale to
  production traffic, or be hardened against sophisticated evasion.
- The evaluator is a course instructor, not a security auditor — clarity,
  a working live demo, and explainable logic matter more than
  enterprise-grade robustness.
- The student already completed earlier labs in this course: AES modes of
  operation, 2FA (bcrypt + TOTP), Nmap scanning, network protocol analysis,
  and PGP/Thunderbird secure email. Those are NOT part of this project —
  don't pull them in unless the student explicitly asks to combine them.

---

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

---

## 4. Tech stack

| Layer | Choice | Why |
|---|---|---|
| Language | Python 3.8+ | Everything below is Python |
| SSH honeypot | `paramiko` | Standard library for implementing SSH server-side handshakes with loopback health filtering |
| FTP honeypot | Raw `socket` | FTP protocol emulation + TCP disconnect probe handling |
| Web honeypot & Baits | `Flask` | Fake admin login page + search box + 4 multi-location Honeytoken baits (`dnet_honey_...`) |
| Dashboard backend | `Flask` (unified in `dashboard_api.py`) | Serves static UI + JSON API (`/api/events`, `/api/stats`) + Nmap Web Recon Middleware + PDF export |
| Proxy IP Resolver | Header parser | Resolves real IPs via `CF-Connecting-IP`, `X-Real-IP`, and `X-Forwarded-For` |
| Dashboard frontend | Single `index.html`, vanilla JS + `Chart.js` | Translucent glassmorphic dark design with `backgroundImage.jpg` background |
| Storage | SQLite (`deceptionnet.db`) | Zero-config, file-based database with active session tagging |
| PDF export | `reportlab` | Generates `deceptionnet_report.pdf` for lab submission |
| Test suite | `requests` + raw sockets | `test_attacks.py` fires realistic attack patterns in 5 seconds |

---

## 5. Architecture Summary

1. `run_all.py` spawns SSH (2222), FTP (2121), Web (8080), and Unified Dashboard (5000) concurrently.
2. `dashboard_api.py` middleware catches Nmap web directory probes (`http-enum`), honeytokens, and SQLi/XSS attacks.
3. `classifier.py` runs deterministic classification on every event.
4. `db.py` tags subsequent requests from a honeytoken IP as `honeytoken_session`.
5. `dashboard/index.html` fetches `/api/events` and `/api/stats` every 3 seconds to render live Chart.js graphs and alert banners.
