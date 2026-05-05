# VulnScanner

A full-stack security testing platform that combines **network vulnerability scanning** with an AI-powered **DAST (Dynamic Application Security Testing)** engine. Built with Python, FastAPI, React, and Claude AI.

---

## Features

### 🔍 Network Scanner
- High-performance TCP port scanner using 100 concurrent threads
- Service fingerprinting via banner grabbing
- Automatic CVE lookup against the NIST NVD database
- Real-time port discovery streamed live to the dashboard
- **AI Analysis** — click to get Claude's risk summary, exploit scenario, and fix recommendation for any finding

### ⚡ DAST Scanner
- Actively probes web applications for OWASP Top 10 vulnerabilities
- Checks for SQL Injection, XSS, CORS misconfigurations, open redirects, and exposed sensitive paths
- Checks for missing security headers (CSP, HSTS, X-Frame-Options, etc.)
- **AI Triage** — Claude automatically explains each finding, rates exploitability, and suggests targeted payloads
- **AI Pentest Report** — generates a full executive + technical report on demand

### 🖥️ Dashboard
- Unified React dashboard with tab-based interface for both scan modes
- Real-time terminal output streamed over WebSockets
- Severity-coded findings (CRITICAL / HIGH / MEDIUM / LOW)
- Summary stats bar with CVE and finding counts

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3, FastAPI, WebSockets |
| Scanner | Raw TCP sockets, threading, NVD REST API |
| DAST Engine | Python stdlib (`urllib`, `socket`, `re`) |
| AI | Anthropic Claude API (`claude-sonnet-4`) |
| Frontend | React.js, inline CSS |
| Container | Docker, Docker Compose |

---

## Project Structure

```
vulnscanner/
├── backend/
│   ├── main.py           # FastAPI app, WebSocket routes, AI endpoint
│   ├── scanner.py        # TCP port scanner (100-thread pool)
│   ├── fingerprint.py    # Banner grabbing + service identification
│   ├── cve_lookup.py     # NVD API integration
│   ├── dast_scanner.py   # DAST engine (SQLi, XSS, CORS, headers...)
│   ├── ai_analysis.py    # Claude API integration
│   └── requirements.txt
├── frontend/
│   └── src/
│       ├── App.jsx
│       └── components/
│           ├── ScanForm.jsx
│           ├── DASTForm.jsx
│           ├── PortCard.jsx
│           ├── DASTFindingCard.jsx
│           ├── SummaryBar.jsx
│           ├── Terminal.jsx
│           └── AIReport.jsx
├── Dockerfile
├── docker-compose.yml
├── .env.example
└── .gitignore
```

---

## Getting Started

### Prerequisites
- Docker + Docker Compose
- Anthropic API key → [console.anthropic.com](https://console.anthropic.com)

### Setup

**1. Clone the repo**
```bash
git clone https://github.com/FingerCoder69/vulnscanner.git
cd vulnscanner
```

**2. Add your API key**
```bash
cp .env.example .env
# Edit .env and add your key:
# ANTHROPIC_API_KEY=sk-ant-...
```

**3. Run**
```bash
docker-compose up --build
```

**4. Open**
- Frontend: [http://localhost:5173](http://localhost:5173)
- Backend: [http://localhost:8000](http://localhost:8000)
- Health check: [http://localhost:8000/health](http://localhost:8000/health)

---

## Usage

### Network Scanner
1. Enter a target hostname or IP (e.g. `scanme.nmap.org`)
2. Set port range (default: 1–1024)
3. Click **Run Scan**
4. Once results load, click **✦ AI Analyse** on any port to get Claude's assessment

### DAST Scanner
1. Switch to the **DAST + AI** tab
2. Enter a target URL (e.g. `https://httpbin.org`)
3. Enable **AI Triage** and/or **Generate pentest report**
4. Click **Run DAST**

> ⚠️ Only scan targets you own or have explicit written permission to test.

### Legal Test Targets
| Target | Purpose |
|---|---|
| `scanme.nmap.org` | Network scan (officially permitted by Nmap) |
| `https://httpbin.org` | DAST headers and CORS checks |
| `http://zero.webappsecurity.com` | DAST general web checks |

---

## AI Integration

VulnScanner uses the **Anthropic Claude API** for three AI features:

| Feature | Where | What it does |
|---|---|---|
| Port AI Analysis | Network Scanner → PortCard | Risk summary, exploit scenario, fix, attacker commands |
| Finding Triage | DAST → each finding | Explains vulnerability, rates exploitability, next payloads |
| Pentest Report | DAST → summary | Executive summary, risk rating, immediate actions |

All AI calls are proxied through the backend — your API key is never exposed to the browser.

---

## Environment Variables

| Variable | Description |
|---|---|
| `ANTHROPIC_API_KEY` | Your Anthropic API key |

Copy `.env.example` to `.env` and fill in your key. Never commit `.env` to version control.

---

## ⚠️ Disclaimer

VulnScanner is built for **authorized security testing and educational purposes only**. Scanning systems without explicit permission is illegal. The authors take no responsibility for misuse.
