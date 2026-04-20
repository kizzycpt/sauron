# (linux) Make sure to run sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/python3.
import time
from datetime import datetime
from pathlib import Path
import sys

from rich.console import Console

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from variables.ui.tables import tables
from variables.ether.L2 import arp_scan
from variables.ether.gateway import NetInfo
from variables.ether.mac import gateway_mac
from variables.ether.ports import open_ports_for, default_ports
from variables.nodeinfo.hostname import hostname
from variables.nodeinfo.os import os_guess
from variables.utils.signals import install_sigint_handler

LOG_FILE = Path("logs") / "netscan.log"
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)


class NetScan:
    """Network scanner — wraps stream_arp_ports_live into a reusable object."""

    def __init__(
        self,
        subnet: str | None = None,
        ports: list[int] | None = None,
        os_scan: bool = False,
        console: Console | None = None,
    ):
        self.subnet   = subnet or NetInfo.get("subnet")
        self.ports    = ports or default_ports
        self.os_scan  = os_scan
        self.console  = console or Console()

        # State readable by the dashboard panel
        self.scanning   = False
        self.scan_done  = False
        self.hosts: dict[str, str] = {}   # {ip: mac}
        self.arp_table  = None            # RichTable from last completed scan
        self.error      = ""



    def run(self, stop_requested=None) -> tuple:
        """Execute a full scan (blocking — run in a thread).
        stop_requested: callable → bool, used to break the live loop.
        Returns (arp_table, hosts)."""
        self.scanning  = True
        self.scan_done = False
        self.error     = ""
        self.hosts     = {}
        self.arp_table = None

        _stop = stop_requested or (lambda: False)




        try:
            LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(f"Scanning {self.subnet} @ {datetime.now()}\n")

            arp_table, hosts = tables.stream_arp_ports_live(
                console          = self.console,
                subnet           = self.subnet,
                ports            = self.ports,
                do_os_scan       = self.os_scan,
                arp_scan         = arp_scan,
                resolve_hostname = hostname.resolve_hostname,
                open_ports_for   = open_ports_for,
                os_guess_for_table = os_guess,
                stop_requested   = _stop,
            )

            gw_mac  = gateway_mac
            net_tbl = tables.build_network_results_table(
                NetInfo  = NetInfo.get_all() if hasattr(NetInfo, "get_all") else {},
                gw_mac   = gw_mac,
            )
            self.console.line()
            tables.print_and_log_table(self.console, arp_table, LOG_FILE)
            self.console.print(net_tbl)

            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(f"Scan completed @ {datetime.now()}\n")

            self.arp_table = arp_table
            self.hosts     = hosts
            return arp_table, hosts

        except Exception as e:
            self.error = str(e)
            self.console.print(f"[red]Scan failed:[/red] {e}")
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(f"Scan failed @ {datetime.now()}: {e}\n")
            return None, {}

        finally:
            self.scanning  = False
            self.scan_done = True


def main():
    scanner = NetScan()
    scanner.run()


if __name__ == "__main__":
    main()