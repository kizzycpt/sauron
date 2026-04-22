import json
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path
from rich.console import Console


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


from variables.ether.gateway import Network, NetInfo
from variables.ether.L2 import l2_arp, arp_scan
from variables.utils.signals import install_sigint_handler
from variables.ether.icmp import ping
from variables.ether.ports import ports
from variables.nodeinfo.hostname import get_hostname
from variables.nodeinfo.os import os_detect


console = Console()
LOG_FILE = Path("logs") / "ids.log"
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

DEFAULT_PORTS = ports.DEFAULT_PORTS if hasattr(ports.port_check, "DEFAULT_PORTS") else []


def make_run_dir(root: Path) -> Path:
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    d = root / ts
    d.mkdir(parents=True, exist_ok=True)
    return d


class IDS:
    """Intrusion Detection System — network baseline monitor."""

    BASELINE_FILE = Path("logs") / "ids_baseline.json"

    def __init__(
        self,
        out: str = "ids_runs",
        subnet: str | None = None,
        ports: list[int] | None = None,
        os_scan: bool = False,
    ):
        self.out      = out
        self.subnet   = subnet or NetInfo.get("subnet")
        self.ports    = ports or DEFAULT_PORTS
        self.os_scan  = os_scan
        self._stop    = install_sigint_handler(console)

        self._empty_baseline: dict = {
            "last_run_at":  None,
            "gateway_ip":   None,
            "gateway_mac":  None,
            "ip_to_mac":    {},
            "devices":      {},
        }

    # ── Baseline helpers ──────────────────────────────────────────────────

    def _load_baseline(self) -> dict:
        if self.BASELINE_FILE.exists():
            try:
                return json.loads(self.BASELINE_FILE.read_text(encoding="utf-8"))
            except Exception:
                pass
        return dict(self._empty_baseline)

    def _save_baseline(self, baseline: dict) -> None:
        self.BASELINE_FILE.parent.mkdir(parents=True, exist_ok=True)
        self.BASELINE_FILE.write_text(
            json.dumps(baseline, indent=2, default=str), encoding="utf-8"
        )

    # ── Single IDS run ────────────────────────────────────────────────────

    def run_once(self) -> dict:
        """Run one IDS scan cycle. Returns the updated baseline."""
        now     = datetime.now()
        now_iso = now.isoformat(timespec="seconds")

        root    = Path(self.out)
        root.mkdir(parents=True, exist_ok=True)
        run_dir     = make_run_dir(root)
        devices_csv = run_dir / "devices.csv"
        report_md   = run_dir / "report.md"

        baseline      = self._load_baseline()
        base_devs     = baseline.get("devices", {})
        is_first_run  = not self.BASELINE_FILE.exists()

        # ── ARP scan ─────────────────────────────────────────────────────
        console.print(f"[cyan]Scanning {self.subnet} …[/cyan]")
        hosts  = arp_scan(self.subnet, quiet=False)
        gw_ip  = NetInfo.get("gateway")
        gw_mac = hosts.get(gw_ip)

        net_info = NetInfo.get_all() if hasattr(NetInfo, "get_all") else {}
        net_tbl  = tables.build_network_results_table(net_info, gw_mac=gw_mac)
        tables.print_and_log_table(console, net_tbl, LOG_FILE)

        
        
        # ── Per-host enrichment ───────────────────────────────────────────
        current_devices: dict = {}
        alerts: list[str]     = []
        offline_this_run: list[str] = []

        opened_by_mac: dict = {}
        closed_by_mac: dict = {}

        for ip, mac in hosts.items():
            from variables.nodeinfo.hostname import hostname as _hn
            from variables.ether.ports import open_ports_for
            from variables.nodeinfo.os import os_guess

            host_name  = _hn.resolve_hostname(ip) or "Unknown"
            open_ports = open_ports_for(ip, self.ports)
            os_str     = "-"
            if self.os_scan:
                name, acc = os_guess(ip)
                os_str = f"{name} ({acc}%)" if name else "-"

            prev       = base_devs.get(mac, {})
            prev_ports = set(prev.get("open_ports", []))
            cur_ports  = set(open_ports)

            opened = sorted(cur_ports - prev_ports)
            closed = sorted(prev_ports - cur_ports)
            if opened:
                opened_by_mac[mac] = opened
                alerts.append(f"{now_iso} MEDIUM PORT_OPENED {mac} opened {opened}")
            if closed:
                closed_by_mac[mac] = closed

            if mac not in base_devs and not is_first_run:
                alerts.append(f"{now_iso} HIGH NEW_DEVICE {mac} ({ip}) first seen")

            current_devices[mac] = {
                "ips":        [ip],
                "hostname":   host_name,
                "open_ports": sorted(open_ports),
                "os_guess":   os_str,
                "last_seen":  now_iso,
            }

        # ── Offline detection ─────────────────────────────────────────────
        for mac in base_devs:
            if mac not in current_devices:
                offline_this_run.append(mac)
                alerts.append(f"{now_iso} LOW OFFLINE {mac} not seen this run")

        # ── Build & write tables ──────────────────────────────────────────
        arp_tbl      = tables.build_arp_ports_table(
            hosts          = hosts,
            ports          = self.ports,
            do_os_scan     = self.os_scan,
            resolve_hostname = _hn.resolve_hostname,
            open_ports_for = open_ports_for,
            os_guess_for_table = os_guess,
        )
        alerts_tbl   = tables.build_alerts_table(alerts)
        offline_tbl  = tables.build_offline_table(offline_this_run, base_devs)
        changes_tbl  = tables.build_changes_table(opened_by_mac, closed_by_mac)
        inventory_tbl = tables.build_inventory_table(current_devices, base_devs, now_iso)

        run_log = run_dir / "console_tables.txt"
        for tbl in [arp_tbl, alerts_tbl, offline_tbl, changes_tbl, inventory_tbl]:
            tables.print_and_log_table(console, tbl, run_log)

        # ── CSV + Markdown ────────────────────────────────────────────────
        tables.write_devices_csv(devices_csv, current_devices, base_devs, now_iso)
        tables.write_markdown_report(
            report_md, now_iso, self.subnet, gw_ip, gw_mac,
            net_info, current_devices, alerts, offline_this_run,
        )
        tables.append_alerts_log(run_dir / "alerts.log", alerts)

        # ── Update baseline ───────────────────────────────────────────────
        baseline.update({
            "last_run_at": now_iso,
            "gateway_ip":  gw_ip,
            "gateway_mac": gw_mac,
            "ip_to_mac":   {ip: mac for ip, mac in hosts.items()},
            "devices":     current_devices,
        })
        self._save_baseline(baseline)

        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"Scan completed @ {now_iso}\n")
            if alerts:
                for a in alerts:
                    f.write(f"  ALERT: {a}\n")

        return baseline

    # ── Loop mode ─────────────────────────────────────────────────────────

    def run_loop(self, every_hours: float = 0.25) -> None:
        """Run IDS repeatedly every `every_hours` hours until stopped."""
        interval = every_hours * 3600.0
        console.print(
            f"[cyan]IDS loop started — scanning every {every_hours}h. "
            "Press Ctrl+C to stop gracefully.[/cyan]"
        )
        try:
            while True:
                try:
                    self.run_once()
                except Exception as e:
                    console.print(f"[red]IDS run failed:[/red] {e}")
                    with open(LOG_FILE, "a", encoding="utf-8") as f:
                        f.write(
                            f"[{datetime.now().isoformat(sep=' ', timespec='seconds')}] "
                            f"IDS run failed: {e}\n"
                        )
                        traceback.print_exc(file=f)

                if self._stop:
                    break

                end_time = time.time() + interval
                console.print(
                    f"[cyan]Next scan in {every_hours}h — Ctrl+C to stop.[/cyan]"
                )
                while time.time() < end_time:
                    if self._stop:
                        break
                    time.sleep(1)

                if self._stop:
                    break

        except KeyboardInterrupt:
            pass

        console.print("[yellow]IDS stopped.[/yellow]")



#instances

intrusion_detection = IDS()

ids_loop = intrusion_detection.run_loop


if __name__ == "__main__":
    ids_loop()