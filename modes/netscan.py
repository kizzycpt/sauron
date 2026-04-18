# Make sure to run sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/python3. 

from variables.ether.ports import port
from variables.ether.mac import mac, my_mac, gateway_mac
from variables.ether.gateway import Network, NetInfo
from variables.ui.tables import tables, live_table
from variables.nodeinfo.os import operating_system, os_scan



import time
from datetime import datetime
import socket
from rich.console import Console
from datetime import datetime




def scan_mode(subnet: str | None = None, os_scan: bool = True, ports: list[int] | None = None):
    live_ports = ports or DEFAULT_PORTS
    scan_subnet = subnet or NetInfo.get("subnet")

    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"Scanning {scan_subnet} @ {datetime.now()}\n")

            arp_table, hosts = live_table(
                console=console,
                subnet=scan_subnet,
                ports=live_ports,
                do_os_scan=os_scan,
            )

            gw_mac = gateway_mac
            net_tbl = tables.build_network_results_table(
                subnet=scan_subnet,
                gateway_mac=gw_mac,
                hosts=hosts,
            )

            console.line()
            tables.print_and_log_table(console, arp_table, LOG_FILE)
            console.print(net_tbl)

            f.write(f"Scan Terminated @ {datetime.now()}\n")

        return arp_table, hosts

    except Exception as e:
        console.print(f"[red]Scan failed:[/red] {e}")
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"Scan failed @ {datetime.now()}: {e}\n")
        return None, {}

def main():
    scan_mode()

if __name__ == "__main__":
    main()