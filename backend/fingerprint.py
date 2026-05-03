import socket

PORT_SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle DB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}

BANNER_PROBES = {
    "HTTP": b"HEAD / HTTP/1.0\r\n\r\n",
    "default": b"\r\n",
}

TIMEOUT = 2


def grab_banner(ip: str, port: int) -> str:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        sock.connect((ip, port))
        service = PORT_SERVICE_MAP.get(port, "unknown")
        probe = BANNER_PROBES.get(service, BANNER_PROBES["default"])
        if probe:
            sock.send(probe)
        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        sock.close()
        return banner[:200] if banner else ""
    except Exception:
        return ""


def fingerprint_ports(ip: str, open_ports: list) -> list:
    results = []
    for port in open_ports:
        service = PORT_SERVICE_MAP.get(port, "Unknown")
        banner = grab_banner(ip, port)
        results.append({
            "port": port,
            "service": service,
            "banner": banner if banner else "No banner retrieved",
            "protocol": "TCP",
            "cves": [],
        })
    return results
