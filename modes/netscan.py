from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import socket
import threading
from datetime import datetime

from variables.ether.icmp     import ping
from variables.ether.ports    import ports
from variables.nodeinfo.hostname import get_hostname
from variables.nodeinfo.os    import os_detect

BASE_DIR = Path(__file__).resolve().parent


class NetScan:
    def __init__(self):
        self.results:   list[dict] = []
        self.scanning   = False
        self.scan_done  = False
        self.scan_range = ""
        self._lock      = threading.Lock()
        self.log_path   = BASE_DIR / "logs" / "netscan.log"

    def _scan_host(self, ip: str):
        if not ping(ip):
            return

        entry = {
            "ip":       ip,
            "hostname": get_hostname(ip),
            "ports":    ports.port_check(ip),
            "os":       os_detect(ip),
            "ts":       datetime.now().strftime("%H:%M:%S"),
        }
        with self._lock:
            self.results.append(entry)

    def _resolve_base(self, subnet: str) -> str:
        if subnet:
            base = subnet
        else:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                base = s.getsockname()[0]
                s.close()
            except Exception:
                base = "192.168.1.0"
        return base.rsplit(".", 1)[0] + "."

    def start_scan(self, subnet: str = ""):
        if self.scanning:
            return

        self.results.clear()
        self.scan_done = False
        self.scanning  = True

        def _worker():
            base            = self._resolve_base(subnet)
            self.scan_range = base + "0/24"

            threads = [
                threading.Thread(target=self._scan_host, args=(f"{base}{i}",), daemon=True)
                for i in range(1, 255)
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=30)

            self.scanning  = False
            self.scan_done = True

        threading.Thread(target=_worker, daemon=True).start()


net_scan_panel = NetScan()
scan_mode      = net_scan_panel.start_scan