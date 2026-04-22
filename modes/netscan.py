from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import time
import threading
import socket
from datetime import datetime

from variables.ether.icmp import ping
from variables.ether.ports import ports
from variables.nodeinfo.hostname import get_hostname
from variables.nodeinfo.os import os_detect



class NetScanPanel:
    def __init__(self):
        self.results: list[dict] = []
        self.scanning   = False
        self.scan_done  = False
        self.scan_range = ""
        self._lock      = threading.Lock()




    def _scan_host(self, ip: str):
       
        if not ping(ip):             
            return
       
       
        hostname   = get_hostname(ip)
        open_ports = ports.port_check(ip)
        os_guess   = os_detect(ip)
        entry = {"ip": ip, "hostname": hostname, "ports": open_ports,
                 "os": os_guess, "ts": datetime.now().strftime("%H:%M:%S")}
        
        
        with self._lock:
            self.results.append(entry)




    def start_scan(self, subnet: str = ""):
        
        if self.scanning:
            return
        
        
        
        self.results.clear()
        self.scan_done = False
        self.scanning  = True

        
        
        
        
        
        def _worker():
            
            base = subnet
            
            
            
            if not base:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.connect(("8.8.8.8", 80))
                    local_ip = s.getsockname()[0]
                    s.close()
                    base = local_ip.rsplit(".", 1)[0] + "."
                except Exception:
                    base = "192.168.1."

            
            
            if not base.endswith("."):
                base = base.rsplit(".", 1)[0] + "."

            
            self.scan_range = base + "0/24"
            threads = []

            
            
            for i in range(1, 255):
                t = threading.Thread(target=self._scan_host,
                                     args=(f"{base}{i}",), daemon=True)
                t.start()
                threads.append(t)

            
            for t in threads:
                t.join(timeout=30)

            
            
            self.scanning  = False
            self.scan_done = True

        threading.Thread(target=_worker, daemon=True).start()


#isntances
net_scan_panel = NetScanPanel()