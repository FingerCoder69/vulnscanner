import socket
import threading
from queue import Queue
from datetime import datetime

MAX_THREADS = 100
TIMEOUT = 1


class PortScanner:
    def __init__(self, target: str, port_range: tuple = (1, 1024), on_open=None):
        self.target = target
        self.start_port, self.end_port = port_range
        self.open_ports = []
        self.lock = threading.Lock()
        self.queue = Queue()
        self.ip = None
        self.on_open = on_open  # callback fired each time a port is found open

    def resolve_target(self) -> str:
        try:
            return socket.gethostbyname(self.target)
        except socket.gaierror:
            raise ValueError(f"Could not resolve host: {self.target}")

    def scan_port(self, ip: str, port: int) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TIMEOUT)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except socket.error:
            return False

    def worker(self, ip: str):
        while not self.queue.empty():
            port = self.queue.get()
            if self.scan_port(ip, port):
                with self.lock:
                    self.open_ports.append(port)
                    if self.on_open:
                        self.on_open(port)
            self.queue.task_done()

    def run(self) -> list:
        self.ip = self.resolve_target()
        for port in range(self.start_port, self.end_port + 1):
            self.queue.put(port)
        threads = []
        for _ in range(min(MAX_THREADS, self.end_port - self.start_port + 1)):
            t = threading.Thread(target=self.worker, args=(self.ip,))
            t.daemon = True
            t.start()
            threads.append(t)
        self.queue.join()
        self.open_ports.sort()
        return self.open_ports
