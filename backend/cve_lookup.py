import urllib.request
import urllib.parse
import json
import time

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

SERVICE_SEARCH_TERMS = {
    "FTP": "ftp", "SSH": "openssh", "Telnet": "telnet", "SMTP": "smtp",
    "HTTP": "apache http", "HTTPS": "apache http",
    "HTTP-Alt": "apache http", "HTTPS-Alt": "apache http",
    "SMB": "windows smb", "RDP": "remote desktop",
    "MySQL": "mysql", "PostgreSQL": "postgresql",
    "MongoDB": "mongodb", "Redis": "redis",
    "MSSQL": "sql server", "VNC": "vnc", "DNS": "bind dns",
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}


def _extract_score(metrics: dict) -> tuple:
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if key in metrics:
            data = metrics[key][0].get("cvssData", {})
            return data.get("baseScore", 0.0), data.get("baseSeverity", "UNKNOWN").upper()
    return 0.0, "UNKNOWN"


def fetch_cves(service: str, max_results: int = 5) -> list:
    keyword = SERVICE_SEARCH_TERMS.get(service)
    if not keyword:
        return []
    params = urllib.parse.urlencode({"keywordSearch": keyword, "resultsPerPage": max_results})
    url = f"{NVD_API_URL}?{params}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "VulnScanner/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
        cves = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "N/A")
            descriptions = cve.get("descriptions", [])
            description = next((d["value"] for d in descriptions if d.get("lang") == "en"), "No description available")
            score, severity = _extract_score(cve.get("metrics", {}))
            cves.append({
                "id": cve_id,
                "description": description[:300],
                "severity": severity,
                "score": score,
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            })
        cves.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 4))
        return cves
    except Exception:
        return []


def enrich_with_cves(fingerprints: list) -> list:
    for entry in fingerprints:
        entry["cves"] = fetch_cves(entry["service"])
        time.sleep(0.7)
    return fingerprints
