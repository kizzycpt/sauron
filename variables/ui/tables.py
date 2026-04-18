from variables.ether.gateway import Network, NetInfo
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from variables.ether.L2 import arp_scan as scan_arp
from variables.nodeinfo.os import OperatingSystem, os_guess, os_hint, os_scan
from variables.ether.ports import port, open_ports
from variables.ether.mac import MAC, gateway_mac,my_mac
from variables.nodeinfo.hostname import hostname
from variables.utils.signals import install_sigint_handler

import socket
import platform
import sys

from rich.console import Console
from rich.table import Table as RichTable
from rich.live import Live


console = Console()
gw_mac = gateway_mac
subnet = NetInfo.get("subnet")
ports = port.ports or port.DEFAULT_PORTS
resolve_hostname = hostname.resolve_hostname()
open_ports_for = port.open_ports_for()
os_guess_for_table = os_guess
STOP_REQUESTED = install_sigint_handler(console)


class Tables:
    @staticmethod
    def build_network_results_table(NetInfo: dict, gw_mac: str | None = None) -> RichTable:
        tbl = RichTable(
            title="\n[!] Network Connection Summary [!]",
            title_style="blue",
            style="blue",
            show_lines=True,
        )

        tbl.add_column("Item", style="green", no_wrap=True)
        tbl.add_column("Value", style="green")

        tbl.add_row("Hostname", socket.gethostname())
        tbl.add_row("Local IP", NetInfo.get("local_ip", "N/A"))
        tbl.add_row("Default Gateway", NetInfo.get("gateway", "N/A"))
        tbl.add_row("Subnet", NetInfo.get("subnet", "N/A"))
        tbl.add_row("Public IP", NetInfo.get("public_ip", "N/A"))
        tbl.add_row("Timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        if gw_mac:
            tbl.add_row("Gateway MAC", gw_mac)

        return tbl

    @staticmethod
    def build_alerts_table(alerts: list[str]) -> RichTable:
        tbl = RichTable(
            title="\n[!] Alerts This Run [!]",
            title_style="blue",
            style="blue",
            show_lines=True,
        )

        tbl.add_column("Time", style="green", no_wrap=True)
        tbl.add_column("Severity", style="green")
        tbl.add_column("Type", style="green")
        tbl.add_column("Message", style="green")

        if not alerts:
            tbl.add_row("-", "-", "-", "None")
            return tbl

        for line in alerts:
            try:
                t, sev, typ, msg = line.split(" ", 3)
            except ValueError:
                t, sev, typ, msg = ("", "", "", line)
            tbl.add_row(t, sev, typ, msg)

        return tbl

    @staticmethod
    def build_offline_table(offline_macs: list[str], base_devs: dict) -> RichTable:
        tbl = RichTable(
            title="\n[!] Offline Devices (this run) [!]",
            title_style="blue",
            style="blue",
            show_lines=True,
        )

        tbl.add_column("MAC", style="green")
        tbl.add_column("Last Seen", style="green")
        tbl.add_column("Missed Runs", style="green")

        if not offline_macs:
            tbl.add_row("-", "-", "-")
            return tbl

        for mac in offline_macs:
            dev = base_devs.get(mac, {})
            tbl.add_row(
                mac,
                dev.get("last_seen", "N/A"),
                str(int(dev.get("missed_runs", 0))),
            )

        return tbl

    @staticmethod
    def build_changes_table(opened_by_mac: dict, closed_by_mac: dict) -> RichTable:
        tbl = RichTable(
            title="\n[!] Changes Since Last Run [!]",
            title_style="blue",
            style="blue",
            show_lines=True,
        )

        tbl.add_column("MAC", style="green")
        tbl.add_column("Opened", style="green")
        tbl.add_column("Closed", style="green")

        macs = sorted(set(opened_by_mac) | set(closed_by_mac))
        if not macs:
            tbl.add_row("-", "-", "-")
            return tbl

        for mac in macs:
            opened = ", ".join(str(p) for p in opened_by_mac.get(mac, [])) or "-"
            closed = ", ".join(str(p) for p in closed_by_mac.get(mac, [])) or "-"
            tbl.add_row(mac, opened, closed)

        return tbl

    @staticmethod
    def build_inventory_table(current_devices: dict, base_devs: dict, now_iso: str) -> RichTable:
        tbl = RichTable(
            title="\n[!] Inventory [!]",
            title_style="blue",
            style="blue",
            show_lines=True,
        )

        tbl.add_column("MAC", style="green")
        tbl.add_column("IPs", style="green")
        tbl.add_column("Hostname", style="green")
        tbl.add_column("Open Ports", style="green")
        tbl.add_column("OS Guess", style="green")
        tbl.add_column("First Seen", style="green")
        tbl.add_column("Last Seen", style="green")
        tbl.add_column("Missed Runs", style="green")

        if not current_devices:
            tbl.add_row("-", "-", "-", "-", "-", "-", "-", "-")
            return tbl

        for mac, cur in sorted(current_devices.items()):
            prev = base_devs.get(mac, {})
            first_seen = prev.get("first_seen", now_iso)
            missed = int(prev.get("missed_runs", 0))

            tbl.add_row(
                mac,
                ", ".join(cur.get("ips", [])) or "-",
                cur.get("hostname") or "-",
                ", ".join(str(p) for p in cur.get("open_ports", [])) or "-",
                cur.get("os_guess") or "-",
                first_seen,
                cur.get("last_seen", now_iso),
                str(missed),
            )

        return tbl

    @staticmethod
    def print_and_log_table(console: Console, rich_table: RichTable, log_path: Path, width: int = 120):
        console.print(rich_table)

        with open(log_path, "a", encoding="utf-8") as f:
            file_console = Console(file=f, no_color=True, width=width, soft_wrap=False)
            file_console.print(rich_table)
            f.write("\n")

    
    
    
    @staticmethod
    def build_arp_ports_table(
        hosts: dict[str, str],
        ports: list[int],
        do_os_scan: bool = False,
        resolve_hostname=None,
        open_ports_for=None,
        os_guess_for_table=None,
    ) -> RichTable:
        
        
        tbl = RichTable(
            title="\n[!] ARP Scan Results [!]",
            title_style="blue",
            style="blue",
            show_lines=True,
        )

        tbl.add_column("Host Name", style="green")
        tbl.add_column("IP Address", style="green", no_wrap=True)
        tbl.add_column("MAC Address", style="green", no_wrap=True)
        tbl.add_column("OS", style="green")
        tbl.add_column("Open Ports", style="green")
        tbl.add_column("Closed Ports", style="green")

        
        def fmt_ports(nums: list[int], color: str) -> str:
            if not nums:
                return "-"
            return "(" + ", ".join(f"[{color}]{p}[/{color}]" for p in nums) + ")"

        for ip, mac in hosts.items():
            hostname = resolve_hostname(ip) if resolve_hostname else "Unknown"
            open_list = open_ports_for(ip, ports) if open_ports_for else []
            closed_list = sorted(set(ports) - set(open_list))
            os_guess = os_guess_for_table(ip, enabled=do_os_scan) if os_guess_for_table else "-"

            tbl.add_row(
                hostname or "Unknown",
                ip,
                mac,
                os_guess or "-",
                fmt_ports(open_list, "green"),
                fmt_ports(closed_list, "red"),
            )

        return tbl

    
    
    
    @staticmethod
    def stream_arp_ports_live(
        console: Console,
        subnet: str,
        ports: list[int],
        do_os_scan: bool,
        scan_arp,
        resolve_hostname,
        open_ports_for,
        os_guess_for_table,
        stop_requested,
        refresh_interval: float = 2.0,
    ) -> tuple[RichTable, dict[str, str]]:
        def make_table() -> RichTable:
            tbl = RichTable(
                title="\n[!] ARP Scan Results [!]",
                title_style="blue",
                style="blue",
                show_lines=True,
            )
            tbl.add_column("Host Name", style="green")
            tbl.add_column("IP Address", style="green", no_wrap=True)
            tbl.add_column("MAC Address", style="green", no_wrap=True)
            tbl.add_column("OS", style="green")
            tbl.add_column("Open Ports", style="green")
            tbl.add_column("Closed Ports", style="green")
            return tbl

        def fmt_ports(nums: list[int], color: str) -> str:
            if not nums:
                return "-"
            return "(" + ", ".join(f"[{color}]{p}[/{color}]" for p in nums) + ")"

        hosts: dict[str, str] = {}
        final_table = make_table()

        with Live(final_table, console=console, refresh_per_second=8, transient=False) as live:
            while not stop_requested():
                discovered = scan_arp(console, subnet, quiet=True)
                targets = list(discovered.keys())

                rows = []
                current_hosts: dict[str, str] = {}

                with ThreadPoolExecutor(max_workers=64) as pool:
                    hostname_futures = {
                        pool.submit(resolve_hostname, ip): ip for ip in targets
                    }
                    ports_futures = {
                        pool.submit(open_ports_for, ip, ports): ip for ip in targets
                    }
                    os_futures = {
                        pool.submit(os_guess_for_table, ip, enabled=do_os_scan): ip for ip in targets
                    }

                    hostname_results = {}
                    open_ports_results = {}
                    os_results = {}

                    for fut in as_completed(hostname_futures):
                        ip = hostname_futures[fut]
                        hostname_results[ip] = fut.result() or "Unknown"

                    for fut in as_completed(ports_futures):
                        ip = ports_futures[fut]
                        open_ports_results[ip] = fut.result()

                    for fut in as_completed(os_futures):
                        ip = os_futures[fut]
                        os_results[ip] = fut.result() or "-"

                for ip in targets:
                    mac = discovered.get(ip, "-")
                    open_list = open_ports_results.get(ip, [])
                    closed_list = sorted(set(ports) - set(open_list))

                    row = (
                        hostname_results.get(ip, "Unknown"),
                        ip,
                        mac or "-",
                        os_results.get(ip, "-"),
                        fmt_ports(open_list, "green"),
                        fmt_ports(closed_list, "red"),
                    )
                    rows.append(row)
                    current_hosts[ip] = mac

                new_table = make_table()
                for row in rows:
                    new_table.add_row(*row)

                hosts = current_hosts
                final_table = new_table
                live.update(new_table)

                time.sleep(refresh_interval)

        return final_table, hosts
    def write_tables(self, run_dir, hosts, ports, args, alerts, offline_this_run, base_devs, opened_by_mac, closed_by_mac, current_devices, now_iso, build_arp_ports_table, build_alerts_table, build_offline_table, build_changes_table, build_inventory_table):
        arp_ports_tbl = build_arp_ports_table(hosts, ports, do_os_scan=args.os_scan)
        alerts_tbl = build_alerts_table(alerts)
        offline_tbl = build_offline_table(offline_this_run, base_devs)
        changes_tbl = build_changes_table(opened_by_mac, closed_by_mac)
        inventory_tbl = build_inventory_table(current_devices, base_devs, now_iso)

        run_tables_log = run_dir / "console_tables.txt"
        for table in [arp_ports_tbl, alerts_tbl, offline_tbl, changes_tbl, inventory_tbl]:
            self.print_and_log_table(self.console, table, run_tables_log)

    def write_devices_csv(self, devices_csv, current_devices, base_devs, now_iso):
        with open(devices_csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(
                ["mac", "ips", "hostname", "open_ports", "os_guess", "first_seen", "last_seen", "missed_runs"]
            )

            for mac, cur in sorted(current_devices.items()):
                prev = base_devs.get(mac, {})
                first_seen = prev.get("first_seen", now_iso)

                writer.writerow(
                    [
                        mac,
                        ",".join(cur["ips"]),
                        cur["hostname"] or "",
                        ",".join(str(port) for port in cur["open_ports"]),
                        cur["os_guess"] or "",
                        first_seen,
                        cur["last_seen"],
                        0,
                    ]
                )

    def write_markdown_report(
        self,
        report_md,
        now_iso,
        subnet,
        gw_ip,
        gw_mac,
        net_info,
        current_devices,
        alerts,
        offline_this_run,
    ):
        new_count = sum(1 for alert in alerts if "NEW_DEVICE" in alert)
        offline_count = len(offline_this_run)

        with open(report_md, "w", encoding="utf-8") as f:
            f.write(f"# SKO IDS Report — {now_iso}\n\n")
            f.write("## Network\n")
            f.write(f"- Subnet: {subnet}\n")
            f.write(f"- Gateway: {gw_ip} (MAC: {gw_mac or 'N/A'})\n")
            f.write(f"- Local IP: {net_info.get('local_ip', 'N/A')}\n")
            f.write("## Summary\n")
            f.write(f"- Devices seen: {len(current_devices)}\n")
            f.write(f"- New devices: {new_count}\n")
            f.write(f"- Offline (this run): {offline_count}\n")
            f.write(f"- Alerts this run: {len(alerts)}\n\n")
            f.write("## Alerts (this run)\n")

            if alerts:
                for line in alerts:
                    f.write(f"- {line}\n")
            else:
                f.write("- None\n")

            f.write("\n")

    def append_alerts_log(self, alerts_file, alerts):
        if not alerts:
            return

        alerts_file.parent.mkdir(parents=True, exist_ok=True)
        with open(alerts_file, "a", encoding="utf-8") as f:
            for line in alerts:
                f.write(line + "\n")









#instances:

console = Console()
tables = Tables()

live_table = tables.stream_arp_ports_live(
                console=console,
                subnet=subnet,
                ports=ports,
                do_os_scan=True,
                scan_arp=scan_arp,
                resolve_hostname=resolve_hostname,
                open_ports_for=open_ports_for,
                os_guess_for_table=os_guess_for_table,
                stop_requested=lambda: STOP_REQUESTED,
            )