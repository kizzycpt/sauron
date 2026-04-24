import json
import sys
import time
import traceback
import csv
from datetime import datetime
from pathlib import Path
from rich.console import Console

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from variables.ether.gateway    import Network, NetInfo
from variables.ether.L2         import l2_arp, arp_scan
from variables.utils.signals    import install_sigint_handler
from variables.ether.icmp       import ping
from variables.ether.ports      import ports, common_ports
from variables.ether.mac        import gateway_mac
from variables.nodeinfo.hostname import get_hostname
from variables.nodeinfo.os      import os_detect

console  = Console()
BASE_DIR = Path(__file__).resolve().parent


class IntrusionDetectionSystem:

    def __init__(self, out=None, subnet=None, ports=None, hostname=None, os_scan=None):
        self.scanning        = False
        self.scan_complete   = False
        self.scan_range      = " "
        self.out             = out or (BASE_DIR.parent / "logs" / "IDS" / "runs")
        self.subnet          = subnet or NetInfo.get("subnet")
        self.ports           = ports or common_ports
        self.hostname        = hostname or get_hostname
        self.os_scan         = os_scan if os_scan is not None else False
        self.stop            = install_sigint_handler(console)
        self.stop_requested  = False
        self.BASE_DIR        = BASE_DIR.parent
        self.log_path        = self.BASE_DIR / "logs" / "IDS" / "ids.log"
        self.run_dir_root    = self.BASE_DIR / "logs" / "IDS" / "runs"
        self.BASELINE_FILE   = self.BASE_DIR / "logs" / "IDS" / "data" / "baseline.json"
        self.baseline: dict  = {
            "Last Run At": None,
            "Gateway IP":  None,
            "Gateway MAC": None,
            "IP:MAC":      {},
            "Devices":     {},
        }
        self.current_devices:  dict = {}
        self.alerts:           list = []
        self.offline_this_run: list = []


    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def make_run_dir(root: Path) -> Path:
        date = root / datetime.now().strftime("%Y-%m-%d")
        date.mkdir(parents=True, exist_ok=True)
        return date

    def load_baseline(self) -> dict:
        if self.BASELINE_FILE.exists():
            try:
                return json.loads(self.BASELINE_FILE.read_text(encoding="utf-8"))
            except Exception:
                pass
        return dict(self.baseline)

    def save_baseline(self, baseline: dict):
        self.BASELINE_FILE.parent.mkdir(parents=True, exist_ok=True)
        self.BASELINE_FILE.write_text(
            json.dumps(baseline, indent=2, default=str), encoding="utf-8")


    # ── Per-host scan ─────────────────────────────────────────────────────────

    def per_host_info(self, hosts, base_devices, is_first_run, now_iso):
        current_devices: dict = {}
        alerts:  list[str]   = []

        for ip, mac in hosts.items():
            if self.stop_requested:
                break

            host_name  = get_hostname(ip)
            open_ports = ports.port_check(ip, self.ports)
            os_str     = " "

            if self.os_scan:
                result = os_detect(ip)
                if result and len(result) == 2:
                    name, acc = result
                    os_str    = f"{name} ({acc}%)" if name else "-"
                else:
                    os_str = "-"

            prev          = base_devices.get(mac, {})
            prev_ports    = set(prev.get("open_ports", []))
            current_ports = set(open_ports)
            opened        = sorted(current_ports - prev_ports)
            closed        = sorted(prev_ports - current_ports)

            if opened:
                alerts.append(f"{now_iso}: [!] PORT OPENED [!] {mac} opened {opened}.")
            if closed:
                alerts.append(f"{now_iso}: [+] PORT CLOSED [+] {mac} closed {closed}")
            if mac not in base_devices and not is_first_run:
                alerts.append(f"{now_iso}: [+] NEW DEVICE [+] {mac} first seen")

            current_devices[mac] = {
                "IP":         [ip],
                "Hostname":   host_name,
                "Open Ports": sorted(open_ports),
                "Possible OS": os_str,
                "Last Seen":  now_iso,
            }

        self.current_devices = current_devices
        self.alerts          = alerts

    def offline_detection(self, base_devices, now_iso):
        for mac in base_devices:
            if mac not in self.current_devices:
                self.offline_this_run.append(mac)
                self.alerts.append(f"{now_iso}: [X] DEVICE OFFLINE [X] {mac} not seen this run")

    def update_baselines(self, baseline, gw_ip, gw_mac, hosts, now_iso):
        baseline.update({
            "Last Run At": now_iso,
            "Gateway IP":  gw_ip,
            "Gateway Mac": gw_mac,
            "IP:MAC":      {ip: mac for ip, mac in hosts.items()},
            "Devices":     self.current_devices,
        })
        self.save_baseline(baseline)

        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(f"======Scan Completed @ {now_iso}======\n\n")
            for a in self.alerts:
                f.write(f"  [!] ALERT[!]: {a}\n")

        return baseline


    # ── Single run ────────────────────────────────────────────────────────────

    def run_once(self) -> dict:
        self.offline_this_run = []
        now_iso  = datetime.now().isoformat(timespec="seconds")

        root     = Path(self.out)
        root.mkdir(parents=True, exist_ok=True)
        run_dir     = self.make_run_dir(root)
        devices_csv = run_dir / "devices.csv"
        report_md   = run_dir / "report.md"

        baseline     = self.load_baseline()
        base_devices = baseline.get("Devices", {})
        is_first_run = not self.BASELINE_FILE.exists()

        hosts    = arp_scan(self.subnet, quiet=False)
        gw_ip    = NetInfo.get("gateway")
        gw_mac   = gateway_mac

        self.per_host_info(hosts, base_devices, is_first_run, now_iso)
        self.offline_detection(base_devices, now_iso)
        self.update_baselines(baseline, gw_ip, gw_mac, hosts, now_iso)

        # Write devices.csv
        try:
            with open(devices_csv, "a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                if devices_csv.stat().st_size == 0:
                    writer.writerow(["MAC", "IP", "Hostname", "Open Ports", "Possible OS", "Last Seen"])
                for mac, info in self.current_devices.items():
                    writer.writerow([
                        mac,
                        ", ".join(info.get("IP", [])),
                        info.get("Hostname", ""),
                        ", ".join(str(p) for p in info.get("Open Ports", [])),
                        info.get("Possible OS", ""),
                        info.get("Last Seen", ""),
                    ])
        except Exception:
            pass

        # Write report.md
        try:
            with open(report_md, "a", encoding="utf-8") as f:
                f.write(f"# IDS Run Report - {now_iso}\n\n")
                f.write(f"**Timestamp:** {now_iso}  \n**Subnet:** {self.subnet}  \n")
                f.write(f"**Gateway IP:** {gw_ip}  \n**Gateway MAC:** {gw_mac}  \n\n---\n\n")
                f.write(f"## Summary\n\n| Metric | Value |\n|--------|-------|\n")
                f.write(f"| Devices Found | {len(self.current_devices)} |\n")
                f.write(f"| Devices Offline | {len(self.offline_this_run)} |\n")
                f.write(f"| Alerts Triggered | {len(self.alerts)} |\n\n---\n\n")
                f.write(f"## Devices\n\n| MAC | IP | Hostname | Open Ports | OS |\n")
                f.write(f"|-----|----|----------|------------|----|\n")
                for mac, info in self.current_devices.items():
                    ip       = ", ".join(info.get("IP", []))
                    hostname = info.get("Hostname", "-")
                    op       = ", ".join(str(p) for p in info.get("Open Ports", []))
                    os_str   = info.get("Possible OS", "-")
                    f.write(f"| {mac} | {ip} | {hostname} | {op} | {os_str} |\n")
                f.write(f"\n---\n\n## Alerts\n\n")
                if self.alerts:
                    for alert in self.alerts:
                        f.write(f"- {alert}\n")
                else:
                    f.write("_No alerts this run._\n")
                if self.offline_this_run:
                    f.write(f"\n---\n\n## Offline Devices\n\n")
                    for mac in self.offline_this_run:
                        f.write(f"- {mac}\n")
        except Exception as e:
            console.print(f"[red][!] Failed to write report.md: {e}")

        return baseline


    # ── Continuous loop ───────────────────────────────────────────────────────

    def run_loop(self, every_hours: float = 0.0001):
        self.scanning      = True
        self.scan_complete = False
        interval           = every_hours * 3600.0

        try:
            while True:
                try:
                    self.run_once()
                except Exception as e:
                    console.print(f"[red][!] Scan error: {e}")
                    with open(self.log_path, "a", encoding="utf-8") as f:
                        f.write(f"[{datetime.now().isoformat(sep=' ', timespec='seconds')}]"
                                f"[!]IDS Monitoring Failed[!]: {e}\n")
                        traceback.print_exc(file=f)

                if self.stop or self.stop_requested:
                    break

                end_time = time.time() + interval
                while time.time() < end_time:
                    if self.stop or self.stop_requested:
                        break
                    time.sleep(1)

                if self.stop or self.stop_requested:
                    break
        except KeyboardInterrupt:
            pass

        self.scanning      = False
        self.scan_complete = True


ids_panel = IntrusionDetectionSystem()
ids_loop  = ids_panel.run_loop