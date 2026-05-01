import socket
import sys , re, time
from pathlib import Path
import subprocess

class Hostnames:

    def get_hostname(self, ip: str) -> str:
        if sys.platform == "linux":
            try:
                return socket.gethostbyaddr(ip)[0]
            except Exception:
                return " "
            
        elif sys.platform == "win32":
            try:
                p= subprocess.run(["nbtstat", "-A", ip], capture_output = True, text=True, timeout=3)

                for line in p.stdout.splitlines():
                    m = re.search(r"^\s*([^\s<]+)\s+<00>\s+UNIQUE", line, re.IGNORECASE)
                    if m:
                        return m.group(1)
            except Exception:
                return " "
            
            try:
                p = subprocess.run(["ping", "-a", "-n", "1", ip],
                                capture_output=True, text=True, timeout=3)
                # "Pinging host.domain [192.168.1.10] with 32 bytes of data:"
                m = re.search(r"Pinging\s+([^\s\[]+)\s+\[", p.stdout)
                if m and m.group(1) and m.group(1) != ip:
                    return m.group(1)
            except Exception:
                pass
            return "Unknown"
        else:
            return "Unknown"



hostname     = Hostnames()
get_hostname = hostname.get_hostname