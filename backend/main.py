import asyncio
import json
import uuid
from datetime import datetime
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from concurrent.futures import ThreadPoolExecutor

from scanner import PortScanner
from fingerprint import fingerprint_ports
from cve_lookup import enrich_with_cves
from dast_scanner import run_dast
from ai_analysis import analyze_finding, generate_report

app = FastAPI(title="VulnScanner API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

executor = ThreadPoolExecutor(max_workers=4)
scan_results: dict = {}


# ── Models ────────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    target: str
    port_start: int = 1
    port_end: int = 1024
    skip_cve: bool = False


class DASTRequest(BaseModel):
    target: str
    ai_triage: bool = True
    generate_report: bool = False


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "time": datetime.now().isoformat()}


@app.get("/results/{scan_id}")
def get_results(scan_id: str):
    if scan_id not in scan_results:
        return {"error": "Scan not found"}
    return scan_results[scan_id]


# ── Network Scanner WebSocket ─────────────────────────────────────────────────

@app.websocket("/ws/scan")
async def websocket_scan(websocket: WebSocket):
    await websocket.accept()

    async def send(event: str, data: dict):
        try:
            await websocket.send_text(json.dumps({"event": event, **data}))
        except Exception:
            pass

    try:
        raw = await websocket.receive_text()
        req = ScanRequest(**json.loads(raw))
        scan_id = str(uuid.uuid4())[:8]

        await send("start", {
            "scan_id": scan_id,
            "target": req.target,
            "port_range": f"{req.port_start}-{req.port_end}",
            "timestamp": datetime.now().isoformat(),
        })

        loop = asyncio.get_event_loop()
        open_ports = []

        def on_open(port):
            open_ports.append(port)
            asyncio.run_coroutine_threadsafe(
                send("port_found", {"port": port}),
                loop,
            )

        scanner = PortScanner(
            target=req.target,
            port_range=(req.port_start, req.port_end),
            on_open=on_open,
        )

        await send("log", {"message": f"[*] Resolving {req.target}..."})
        await send("log", {"message": f"[*] Scanning ports {req.port_start}-{req.port_end} with 100 threads..."})

        try:
            found = await loop.run_in_executor(executor, scanner.run)
        except ValueError as e:
            await send("error", {"message": str(e)})
            return

        await send("log", {"message": f"[+] Scan complete. {len(found)} open port(s) found."})

        if not found:
            await send("done", {"scan_id": scan_id, "results": []})
            return

        await send("log", {"message": "[*] Fingerprinting services..."})
        results = await loop.run_in_executor(executor, fingerprint_ports, scanner.ip, found)

        for entry in results:
            await send("log", {
                "message": f"  [{entry['port']}/TCP]  {entry['service']}  →  {entry['banner'][:60]}"
            })

        if not req.skip_cve:
            await send("log", {"message": "[*] Querying NVD for CVEs (may take ~30s)..."})
            results = await loop.run_in_executor(executor, enrich_with_cves, results)
            total_cves = sum(len(r["cves"]) for r in results)
            await send("log", {"message": f"[+] CVE lookup complete. {total_cves} CVE(s) found."})
        else:
            await send("log", {"message": "[*] CVE lookup skipped."})

        scan_results[scan_id] = {
            "scan_id": scan_id,
            "target": req.target,
            "ip": scanner.ip,
            "port_range": f"{req.port_start}-{req.port_end}",
            "timestamp": datetime.now().isoformat(),
            "results": results,
        }

        await send("done", scan_results[scan_id])

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await send("error", {"message": f"Unexpected error: {str(e)}"})
        except Exception:
            pass


# ── DAST Scanner WebSocket ────────────────────────────────────────────────────

@app.websocket("/ws/dast")
async def websocket_dast(websocket: WebSocket):
    await websocket.accept()

    async def send(event: str, data: dict):
        try:
            await websocket.send_text(json.dumps({"event": event, **data}))
        except Exception:
            pass

    try:
        raw = await websocket.receive_text()
        req = DASTRequest(**json.loads(raw))
        scan_id = str(uuid.uuid4())[:8]

        await send("start", {
            "scan_id": scan_id,
            "target": req.target,
            "timestamp": datetime.now().isoformat(),
        })

        loop = asyncio.get_event_loop()

        # Progress callback — fires from thread into the WS
        def on_progress(stage: str, message: str):
            asyncio.run_coroutine_threadsafe(
                send(stage, {"message": message}),
                loop,
            )

        # Run DAST scan in thread
        await send("log", {"message": f"[*] Starting DAST scan on {req.target}"})
        result = await loop.run_in_executor(
            executor, lambda: run_dast(req.target, on_progress=on_progress)
        )

        if "error" in result:
            await send("error", {"message": result["error"]})
            return

        # AI triage each finding
        if req.ai_triage and result["findings"]:
            await send("log", {"message": f"[*] Running AI triage on {len(result['findings'])} finding(s)..."})
            for i, finding in enumerate(result["findings"]):
                await send("log", {"message": f"  [AI] Analysing: {finding['check']}..."})
                ai = await loop.run_in_executor(executor, analyze_finding, finding)
                result["findings"][i]["ai"] = ai
                await send("finding_ai", {
                    "index": i,
                    "check": finding["check"],
                    "ai": ai,
                })
            await send("log", {"message": "[+] AI triage complete."})

        # Optional full report
        if req.generate_report:
            await send("log", {"message": "[*] Generating AI pentest report..."})
            report = await loop.run_in_executor(executor, generate_report, result)
            result["ai_report"] = report
            await send("log", {"message": "[+] Report generated."})

        scan_results[scan_id] = {**result, "scan_id": scan_id}
        await send("done", scan_results[scan_id])

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await send("error", {"message": f"Unexpected error: {str(e)}"})
        except Exception:
            pass


# ── AI Port Analysis endpoint ─────────────────────────────────────────────────

class PortAIRequest(BaseModel):
    entry: dict

@app.post("/ai/analyse-port")
async def analyse_port(req: PortAIRequest):
    from ai_analysis import analyze_port
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(executor, analyze_port, req.entry)
    return result
