# VulnScanner

A full-stack network vulnerability scanner with a real-time dark-themed dashboard.

**Pipeline:** Port scan → Service fingerprinting → CVE enrichment → Live UI

---

## Stack

| Layer | Tech |
|---|---|
| Frontend | React 18 + Vite, served via Nginx |
| Backend | Python 3.11 + FastAPI + WebSockets |
| Deployment | Docker + docker-compose |

---

## Quick start

### Prerequisites
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed and running

### Run (one command)

```bash
git clone https://github.com/YOUR_USERNAME/vulnscanner.git
cd vulnscanner
docker-compose up --build
```

Then open **http://localhost** in your browser.

To stop:
```bash
docker-compose down
```

---

## Development (no Docker)

### Backend

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Frontend runs on **http://localhost:5173**, backend on **http://localhost:8000**.

> The `.env` file already points the WebSocket at `localhost:8000` for local dev.

---

## How it works

### Backend pipeline (`/ws/scan` WebSocket)

The frontend opens a WebSocket connection and sends a JSON scan request. The backend streams events back in real time:

| Event | Payload | Meaning |
|---|---|---|
| `start` | scan_id, target, port_range | Scan initiated |
| `log` | message | Progress log line |
| `port_found` | port | Open port discovered |
| `done` | full results object | Pipeline complete |
| `error` | message | Something went wrong |

**Stage 1 — Port scanner (`scanner.py`)**
Raw TCP `connect_ex()` scan across the port range, parallelised with a 100-thread pool using `threading.Queue`. A callback fires on every open port discovery so the UI can update live.

**Stage 2 — Fingerprinting (`fingerprint.py`)**
Banner grabbing via raw sockets. Probes known protocols (HTTP, SSH, FTP, SMTP) with appropriate payloads to extract version strings.

**Stage 3 — CVE lookup (`cve_lookup.py`)**
Queries the [NIST NVD REST API v2.0](https://nvd.nist.gov/developers/vulnerabilities) with keywords mapped from detected service names. Results sorted by CVSS severity. A 0.7s inter-request delay respects NVD's unauthenticated rate limit.

### Frontend

Built in React with a terminal-style dark UI. The `App.jsx` manages the WebSocket lifecycle. As events arrive:
- `port_found` events update a live ticker showing discovered ports in real time
- `log` events stream into a macOS-style terminal pane
- `done` renders the full findings: summary stats bar + per-port CVE cards

---
<img width="1846" height="1029" alt="Screenshot 2026-04-08 205130" src="https://github.com/user-attachments/assets/88af7400-0e3f-4615-bf56-aaff6dfd8f47" />

<img width="1836" height="1026" alt="Screenshot 2026-04-08 205155" src="https://github.com/user-attachments/assets/24db45a6-7210-475e-b8fe-5eb9af730f32" />

## Project structure

```
vulnscanner/
├── docker-compose.yml
├── .gitignore
├── README.md
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── main.py          ← FastAPI app + WebSocket endpoint
│   ├── scanner.py       ← TCP port scanner
│   ├── fingerprint.py   ← Banner grabbing + service ID
│   └── cve_lookup.py    ← NIST NVD API integration
└── frontend/
    ├── Dockerfile        ← Multi-stage: Vite build → Nginx
    ├── nginx.conf        ← Serves React + proxies /ws/ to backend
    ├── package.json
    ├── vite.config.js
    ├── index.html
    └── src/
        ├── main.jsx
        ├── index.css
        ├── App.jsx                   ← WebSocket logic + layout
        └── components/
            ├── ScanForm.jsx          ← Target input + port range
            ├── Terminal.jsx          ← Live log stream
            ├── PortCard.jsx          ← Per-port CVE findings
            └── SummaryBar.jsx        ← Scan stats dashboard
```

---

## Ethical use

Only scan hosts you own or have explicit written permission to test.

`scanme.nmap.org` is provided by the Nmap project for legal scan testing.

---

## License

MIT
