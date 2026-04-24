import sys
import subprocess


class ICMP:

    def ping(self, ip: str) -> bool:
        try:
            flag = "-n" if sys.platform == "win32" else "-c"
            r = subprocess.run(
                ["ping", flag, "1", "-W", "1", ip],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2,
            )
            return r.returncode == 0
        except Exception:
            return False


icmp = ICMP()
ping = icmp.ping