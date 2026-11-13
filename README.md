# 🔐 SecView — Security Intelligence SaaS

> **Open SaaS for Security Experts** · Free public APIs · No API key required

[![Version](https://img.shields.io/badge/version-4.0-gold)](https://github.com/abid8670/secview)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/flask-2.0+-teal.svg)](https://flask.palletsprojects.com/)

SecView is a complete open-source security platform that consolidates **10 professional security tools**
into one clean interface. Every tool runs on **free public APIs that require no API key** — no signup,
no credit card, no hidden cost. Just answers.

It ships with **two interfaces**: a rich terminal tool and a full web UI with a landing page,
side navigation, and readable result cards (never raw JSON).

---

## ✨ Features — 10 Tools

| # | Tool | What it does | Example |
|---|------|--------------|---------|
| 1 | **CVE Lookup** | Full CVE detail — description, CVSS score/severity, affected vendors & products, references | `CVE-2021-44228` (Log4j) |
| 2 | **CISA KEV Feed** | Live known-exploited vulnerabilities from CISA with status and reason | 6,500+ exploited CVEs |
| 3 | **Vulnerability Search** | Find CVEs by vendor + product name | `vendor=apache product=httpd` |
| 4 | **CPE Search** | CVEs for a specific CPE (Common Platform Enumeration) URI | `cpe:2.3:*:apache:httpd` |
| 5 | **Shodan Host Scan** | Free network host scan — open ports, services, org, ASN, country | `8.8.8.8` → ports 443, 53 |
| 6 | **URLScan** | Scan any domain — all URLs, IPs, server headers, titles found | `github.com` |
| 7 | **IPinfo Lookup** | IP geolocation — country, city, ISP, ASN, timezone, coordinates | any IP address |
| 8 | **DShield ISC** | SANS Internet Storm Center threat feed for an IP | any IP address |
| 9 | **Email Reputation** | Email sender reputation & spam-risk check | `info@company.com` |
| 10 | **Export Data** | Download any result as JSON or CSV for offline analysis | `report.json` |

---

## 🖥️ Interfaces

### Web UI (Flask)

```
Landing page  →  http://localhost:<port>/        (product overview, features, CTA)
Tool console  →  http://localhost:<port>/app     (10 tools, side navigation, readable cards)
```

- Modern dark UI — navy / teal / gold theme
- One-line usage hint above every tool
- Loading states and error handling
- Readable result cards: CVE cards, KEV tables, host cards, IP grids — **no raw JSON dumps**

### Terminal UI

```
python security_apis_tool.py
```

A menu-driven CLI with colored output covering the same 10 tools.

---

## 🚀 Quick Start

### 1. Clone & install

```bash
git clone https://github.com/abid8670/secview.git
cd secview
pip install -r requirements.txt
```

### 2. Run the terminal tool

```bash
python security_apis_tool.py
```

### 3. Run the web app

```bash
cd web_app
python app.py
```

The console prints the URL with a random free port:

```
╔══════════════════════════════════════════════╗
║   SECVIEW v4.0 — Security Intelligence SaaS   ║
╚══════════════════════════════════════════════╝

→ Open: http://localhost:59132/
→ Press Ctrl+C to stop
```

Open the printed URL — the landing page loads first; click **🚀 Open the Tool** to enter the console.

---

## 🧩 How It Works

```
secview/
├── security_apis_tool.py      # Core library — 10 tools, free API clients, exporter
├── test_web.py                # Endpoint test script
├── requirements.txt           # flask
└── web_app/
    ├── app.py                 # Flask app — routes / and /app
    └── templates/
        ├── landing.html       # Landing page (home)
        └── app.html           # Tool console (sidebar UI)
```

Every request goes through one core library (`SecurityAPI`) that wraps each free public API
with timeouts, retries, and clean error handling — then the terminal and web interfaces
render the same structured data.

### Free APIs used (no key required)

| API | Used by |
|-----|---------|
| [CIRCL CVE](https://cve.circl.lu/api/) | CVE Lookup, Vuln Search, CPE Search |
| [CIRCL KEV](https://cve.circl.lu/api/kev) | CISA KEV Feed |
| [Shodan Host](https://api.shodan.io/shodan/host/{ip}) | Shodan Host Scan |
| [urlscan.io](https://urlscan.io/api/v1/) | URLScan |
| [IPinfo](https://ipinfo.io) | IPinfo Lookup |
| [DShield ISC](https://www.dshield.org/api/) | DShield ISC |
| [EmailRep](https://api.emailrep.io/) | Email Reputation |

---

## 🧪 Testing

```bash
python test_web.py
```

Runs a full pass against every endpoint and reports OK / FAIL per tool.

---

## ⚠️ Disclaimer

SecView is built for **defensive security, research, and education**. Only scan and query
systems you own or have explicit permission to test. The author is not responsible for
misuse of this tool.

---

## 📄 License

MIT — free to use, modify, and distribute. See [LICENSE](LICENSE).

---

## 🙏 Credits

Built on top of the amazing free-API collection [jaegeral/security-apis](https://github.com/jaegeral/security-apis).
