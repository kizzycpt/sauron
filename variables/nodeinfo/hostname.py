import platform
import sys
import socket
import subprocess
import re

class Hostnames():
    
    @staticmethod
    def hostname_for(ip):
            try:
                platform.node()
            except Exception:
                return None

    @staticmethod
    def resolve_hostname(ip: str) -> str:
        try:
            name = socket.gethostbyaddr(ip)[0]
            if name and name != ip:
                return name
        except Exception:
            pass

        # Windows-only helpers
        if sys.platform.startswith("win"):
            try:
                p = subprocess.run(["nbtstat", "-A", ip], capture_output=True, text=True, timeout=3)
                for line in p.stdout.splitlines():
                    m = re.search(r"^\s*([^\s<]+)\s+<00>\s+UNIQUE", line, re.IGNORECASE)
                    if m:
                        return m.group(1)
            except Exception:
                pass

            try:
                p = subprocess.run(["ping", "-a", "-n", "1", ip], capture_output=True, text=True, timeout=3)
                m = re.search(r"Pinging\s+([^\s\[]+)\s+\[", p.stdout)
                if m and m.group(1) and m.group(1) != ip:
                    return m.group(1)
            except Exception:
                pass
        
        #Linux-only helpers
        elif sys.platform.startswith("linux"):
            try:
                p = subprocess.run(["avahi-resolve", "-a", ip], capture_output=True, text=True, timeout=3)
                if p.stdout:
                    name = p.stdout.split()[1].rstrip(".")
                    if name and name != ip:
                        return name
            except Exception:
                pass
            try:
                p = subprocess.run(["nmblookup", "-A", ip], capture_output=True, text=True, timeout=3)
                for line in p.stdout.splitlines():
                    if "<00>" in line and "<GROUP>" not in line:
                        name = line.split()[0].strip()
                        if name and name != ip:
                            return name
            except Exception:
                pass            
            return "Unknown"

#instances

hostname = Hostnames()

resolve_hostname = hostname.resolve_hostname