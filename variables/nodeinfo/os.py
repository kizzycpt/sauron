import nmap
import os
import subprocess
from variables.ether.gateway import NetInfo


#local ip
ip = NetInfo.get("local_ip")

class OperatingSystem:


    def _os_detect(self, ip: str) -> str:

        try:
            r = subprocess.run(
                ["nmap", "-O", "--osscan-guess", ip],
                capture_output=True, text=True, timeout=10,
            )

            for line in r.stdout.splitlines():
                if "OS guess" in line or "OS details" in line:
                    return line.split(":", 1)[-1].strip()

        except Exception:
            pass
        return "-"

osystem = OperatingSystem()

os_detect = osystem._os_detect