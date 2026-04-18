import nmap
import os
import subprocess
import argparse
from variables.ether.gateway import NetInfo
#arguments
parser = argparse.ArgumentParser()
parser.add_argument("--os-scan", action="store_true")

args = parser.parse_args

#local ip
ip = NetInfo.get("local_ip")

class OperatingSystem:


    def __init__(self, args):
        self.args = args

    def guess_for(self, ip):
        if not getattr(self.args, "os_scan", False):
            return (None, 0)

        try:
            scanner = nmap.PortScanner()
            scanner.scan(hosts=ip, arguments="-O -Pn -T4")

            if ip in scanner.all_hosts():
                matches = scanner[ip].get("osmatch", [])
                if matches:
                    name = matches[0].get("name")
                    accuracy = int(matches[0].get("accuracy", 0))
                    return (name, accuracy)
        except Exception:
            pass

        return (None, 0)


    @staticmethod
    def os_hint_from_services(ip: str) -> str:
        try:
            nm = nmap.PortScanner()
            nm.scan(hosts=ip, arguments="-sV -Pn -T4 --version-light --host-timeout 10s")
            if ip not in nm.all_hosts():
                return "-"

            tcp = nm[ip].get("tcp", {})
            hints = []
            for port, info in tcp.items():
                product = info.get("product")
                name    = info.get("name")
                ver     = info.get("version")
                if product:
                    hints.append(f"{name}:{product} {ver}".strip())

            return "; ".join(hints[:2]) if hints else "-"
        except Exception:
            return "-"

    @staticmethod
    def os_scan(target_ip: str) -> str:
        scanner = nmap.PortScanner()
        out = f"\n--- OS Scan for {target_ip} ---\n"
        try:
            scanner.scan(
                hosts=target_ip,
                arguments="-O --osscan-guess -Pn -T4 --max-retries 2 --host-timeout 10s"
            )
            if target_ip in scanner.all_hosts():
                matches = scanner[target_ip].get("osmatch", [])
                if matches:
                    best = matches[0]
                    out += f"OS: {best.get('name','?')} (Accuracy: {best.get('accuracy','0')}%)\n"
                else:
                    out += "[!] OS detection failed.\n"
            else:
                out += "[!] Host is down or not responding.\n"
        except Exception as e:
            out += f"[!] OS scan error: {e}\n"
        return out



operating_system = OperatingSystem(args)
os_guess = operating_system.guess_for(ip)
os_hint = operating_system.os_hint_from_services(ip)
os_scan = operating_system.os_scan(ip)

