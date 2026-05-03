import urllib.request
import urllib.parse
import urllib.error
import re
import ssl
import socket
from datetime import datetime

# SSL context that doesn't verify certs (for scanning)
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

TIMEOUT = 8

# ── Payloads ────────────────────────────────────────────────────────────────

SQLI_PAYLOADS = [
    ("' OR '1'='1", "Classic OR-based SQLi"),
    ("' OR 1=1--", "Comment-based SQLi"),
    ("'; DROP TABLE users--", "Stacked query SQLi"),
    ("1' AND SLEEP(3)--", "Time-based blind SQLi"),
    ("' UNION SELECT NULL,NULL--", "UNION-based SQLi"),
]

XSS_PAYLOADS = [
    ('<script>alert("XSS")</script>', "Basic script injection"),
    ('"><img src=x onerror=alert(1)>', "Image onerror XSS"),
    ("javascript:alert(1)", "JavaScript protocol XSS"),
    ('<svg onload=alert(1)>', "SVG onload XSS"),
]

OPEN_REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
]

SENSITIVE_PATHS = [
    "/.env", "/.git/config", "/config.php", "/wp-config.php",
    "/admin", "/admin/", "/phpinfo.php", "/server-status",
    "/api/v1/users", "/api/users", "/.DS_Store",
    "/backup.zip", "/backup.sql", "/db.sql",
]

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

SQLI_ERROR_PATTERNS = [
    r"sql syntax", r"mysql_fetch", r"ORA-\d{5}", r"pg_query",
    r"sqlite3", r"syntax error", r"unclosed quotation",
    r"microsoft jet database", r"odbc drivers error",
]

# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_request(url: str, params: dict = None, method: str = "GET") -> tuple:
    """Returns (status_code, headers_dict, body_text). Never raises."""
    try:
        if params and method == "GET":
            url = url + ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "VulnScanner-DAST/1.0",
                "Accept": "*/*",
            },
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=SSL_CTX) as resp:
            body = resp.read(8192).decode("utf-8", errors="ignore")
            return resp.status, dict(resp.headers), body
    except urllib.error.HTTPError as e:
        try:
            body = e.read(4096).decode("utf-8", errors="ignore")
        except Exception:
            body = ""
        return e.code, dict(e.headers), body
    except Exception:
        return None, {}, ""


def _extract_forms_and_params(body: str, base_url: str) -> list:
    """Very lightweight form/param extractor — no external deps."""
    params = []
    # grab query params from links
    for href in re.findall(r'href=["\']([^"\']+)["\']', body):
        if "?" in href:
            qs = href.split("?", 1)[1]
            for k, _ in urllib.parse.parse_qsl(qs):
                params.append(k)
    # grab input names from forms
    for name in re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', body, re.IGNORECASE):
        params.append(name)
    return list(set(params)) or ["q", "id", "search", "page", "url", "redirect"]


# ── Individual checks ─────────────────────────────────────────────────────────

def check_security_headers(url: str) -> dict | None:
    status, headers, _ = _make_request(url)
    if status is None:
        return None
    missing = [h for h in SECURITY_HEADERS if h.lower() not in {k.lower() for k in headers}]
    present = [h for h in SECURITY_HEADERS if h.lower() in {k.lower() for k in headers}]
    if not missing:
        return None
    severity = "HIGH" if len(missing) >= 3 else "MEDIUM" if len(missing) >= 1 else "LOW"
    return {
        "check": "Missing Security Headers",
        "severity": severity,
        "score": 7.5 if severity == "HIGH" else 5.0,
        "detail": f"Missing: {', '.join(missing)}",
        "evidence": f"Present: {', '.join(present) or 'None'}",
        "url": url,
        "category": "Security Misconfiguration",
    }


def check_sqli(url: str, params: list) -> list:
    findings = []
    for param in params[:3]:  # limit to first 3 params
        for payload, desc in SQLI_PAYLOADS[:3]:
            status, _, body = _make_request(url, {param: payload})
            if status is None:
                continue
            for pattern in SQLI_ERROR_PATTERNS:
                if re.search(pattern, body, re.IGNORECASE):
                    findings.append({
                        "check": "SQL Injection",
                        "severity": "CRITICAL",
                        "score": 9.8,
                        "detail": f"Parameter `{param}` reflects SQLi error with payload: {payload}",
                        "evidence": f"Error pattern matched: `{pattern}` — {desc}",
                        "url": url,
                        "category": "Injection",
                        "param": param,
                        "payload": payload,
                    })
                    break
    return findings


def check_xss(url: str, params: list) -> list:
    findings = []
    for param in params[:3]:
        for payload, desc in XSS_PAYLOADS[:2]:
            status, _, body = _make_request(url, {param: payload})
            if status is None:
                continue
            if payload in body or urllib.parse.quote(payload) in body:
                findings.append({
                    "check": "Cross-Site Scripting (XSS)",
                    "severity": "HIGH",
                    "score": 8.2,
                    "detail": f"Parameter `{param}` reflects unescaped payload in response",
                    "evidence": f"Payload echoed: {payload[:60]}",
                    "url": url,
                    "category": "XSS",
                    "param": param,
                    "payload": payload,
                })
                break
    return findings


def check_open_redirect(url: str, params: list) -> list:
    findings = []
    redirect_params = [p for p in params if any(k in p.lower() for k in ["url", "redirect", "next", "return", "goto", "dest"])]
    if not redirect_params:
        redirect_params = ["url", "redirect", "next"]

    for param in redirect_params[:2]:
        for payload in OPEN_REDIRECT_PAYLOADS[:2]:
            status, headers, _ = _make_request(url, {param: payload})
            location = headers.get("Location", "") or headers.get("location", "")
            if "evil.com" in location:
                findings.append({
                    "check": "Open Redirect",
                    "severity": "MEDIUM",
                    "score": 6.1,
                    "detail": f"Parameter `{param}` causes redirect to attacker-controlled URL",
                    "evidence": f"Location header: {location}",
                    "url": url,
                    "category": "Broken Access Control",
                    "param": param,
                    "payload": payload,
                })
                break
    return findings


def check_sensitive_paths(base_url: str) -> list:
    findings = []
    base = base_url.rstrip("/")
    for path in SENSITIVE_PATHS:
        status, headers, body = _make_request(base + path)
        if status in (200, 403):
            sev = "CRITICAL" if any(x in path for x in [".env", "config", ".git"]) else "HIGH"
            findings.append({
                "check": "Sensitive Path Exposed",
                "severity": sev,
                "score": 9.1 if sev == "CRITICAL" else 7.5,
                "detail": f"Path `{path}` returned HTTP {status}",
                "evidence": f"Response size: {len(body)} bytes" + (f" | Snippet: {body[:80]}" if status == 200 and body else ""),
                "url": base + path,
                "category": "Security Misconfiguration",
            })
    return findings


def check_cors(url: str) -> dict | None:
    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "VulnScanner-DAST/1.0",
                "Origin": "https://evil.com",
            },
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=SSL_CTX) as resp:
            headers = dict(resp.headers)
            acao = headers.get("Access-Control-Allow-Origin", "") or headers.get("access-control-allow-origin", "")
            acac = headers.get("Access-Control-Allow-Credentials", "") or headers.get("access-control-allow-credentials", "")
            if acao == "*" or "evil.com" in acao:
                severity = "HIGH" if acac.lower() == "true" else "MEDIUM"
                return {
                    "check": "CORS Misconfiguration",
                    "severity": severity,
                    "score": 8.0 if severity == "HIGH" else 6.5,
                    "detail": "Server reflects attacker origin in Access-Control-Allow-Origin",
                    "evidence": f"ACAO: {acao} | ACAC: {acac}",
                    "url": url,
                    "category": "Security Misconfiguration",
                }
    except Exception:
        pass
    return None


# ── Main orchestrator ─────────────────────────────────────────────────────────

def run_dast(target_url: str, on_progress=None) -> dict:
    """Run full DAST pipeline. on_progress(stage, message) called at each step."""

    def log(stage: str, msg: str):
        if on_progress:
            on_progress(stage, msg)

    findings = []
    start = datetime.now()

    # Normalize URL
    if not target_url.startswith("http"):
        target_url = "https://" + target_url

    log("log", f"[*] Target: {target_url}")
    log("log", "[*] Stage 1/5 — Fetching base page...")

    status, headers, body = _make_request(target_url)
    if status is None:
        return {"error": f"Could not reach {target_url}"}

    log("log", f"[+] Base page: HTTP {status} ({len(body)} bytes)")

    # Extract params
    params = _extract_forms_and_params(body, target_url)
    log("log", f"[*] Discovered parameters: {', '.join(params[:6]) or 'none (using defaults)'}")

    # Stage 2: Security headers
    log("log", "[*] Stage 2/5 — Checking security headers...")
    h = check_security_headers(target_url)
    if h:
        findings.append(h)
        log("finding", f"[!] {h['severity']} — {h['check']}: {h['detail'][:80]}")
    else:
        log("log", "[+] Security headers: OK")

    # Stage 3: SQLi
    log("log", "[*] Stage 3/5 — Testing SQL injection...")
    sqli = check_sqli(target_url, params)
    findings.extend(sqli)
    if sqli:
        for f in sqli:
            log("finding", f"[!] {f['severity']} — {f['check']} on param `{f['param']}`")
    else:
        log("log", "[+] No SQLi indicators found")

    # Stage 4: XSS
    log("log", "[*] Stage 4/5 — Testing XSS...")
    xss = check_xss(target_url, params)
    findings.extend(xss)
    if xss:
        for f in xss:
            log("finding", f"[!] {f['severity']} — {f['check']} on param `{f['param']}`")
    else:
        log("log", "[+] No XSS reflection found")

    # Stage 5: Misc checks
    log("log", "[*] Stage 5/5 — Running miscellaneous checks (CORS, paths, redirect)...")

    cors = check_cors(target_url)
    if cors:
        findings.append(cors)
        log("finding", f"[!] {cors['severity']} — {cors['check']}")

    redirect = check_open_redirect(target_url, params)
    findings.extend(redirect)

    paths = check_sensitive_paths(target_url)
    findings.extend(paths)
    for f in paths:
        log("finding", f"[!] {f['severity']} — {f['check']}: {f['url']}")

    log("log", f"[+] Scan complete. {len(findings)} finding(s) in {(datetime.now()-start).seconds}s")

    # Sort by severity
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda x: sev_order.get(x["severity"], 4))

    return {
        "target": target_url,
        "timestamp": datetime.now().isoformat(),
        "findings": findings,
        "stats": {
            "total": len(findings),
            "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
            "high": sum(1 for f in findings if f["severity"] == "HIGH"),
            "medium": sum(1 for f in findings if f["severity"] == "MEDIUM"),
            "low": sum(1 for f in findings if f["severity"] == "LOW"),
        },
        "params_tested": params[:6],
    }
