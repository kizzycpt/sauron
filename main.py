from scapy.all import srp, Ether, IP, ARP, Ether
import sys
import timeout
from datetime import datetime
from pathlib import pathlib
import netifaces as net
from rich.console import Console
import signal 
#-------------------------------------------------------------------------------------------------
console = Console()
#-------------------------------------------------------------------------------------------------

# Project root (repo root). netscanner/config.py -> netscan -> root

BASE_DIR = Path(__file__).resolve().parent.parent

# === Configs === #

DEFAULT_SUBNET = "192.168.1.0/24"

DEFAULT_PORTS = [21, 22, 23, 25, 80, 135, 139, 443, 445, 3389]

LOG_DIR = BASE_DIR / "logs"

LOG_FILE = LOG_DIR / "scan_log.txt"

LOG_DIR.mkdir(parents=True, exist_ok=True)

REPORTS_DIR = LOG_DIR / "reports"

REPORTS_DIR.mkdir(parents=True, exist_ok=True)

PORT_PROTOCOLS = {
    21: "FTP",
    22: "SSH",
    23: "telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: 'RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    3306: "MYSQL",
    3389: "RDP",
    5432: "PostgreSQL"
}

baseline_file = BASE_DIR/ "state.json"

alerts_file = LOG_DIR / "alerts.log"

run_directory_format ="%b-%d-%Y_%Hh%Mm"
#-------------------------------------------------------------------------------------------------

def scan_arp(console: Console, subnet: str, *, quiet: bool =False) -> dict[str, str]:
    arp = ARP(pdst=subnet)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    try:
        result = srp(packet, timeout = 2, verbose = 1)[0]
    except PermissionError:
        console.print("[red]Scapy needs raw-socket permission for ARP (if Linux)")
        console.print("[yellow]Run with sudo or grant CAP_NET_RAW/CAP_NET_ADMIN to the terminal")
        return {}
    
    hosts: dict[str, str] = {}
    for _, received in result:
        if not quiet:
            print(f"[+] Host found: {revieved.psrc} - MAC: {received.hwsrc}")
        hosts[received.psrc] = received.hwsrc
    return hosts

def get_network_info(console: Console) -> dict:
    try:
        gws = net.gateways()
        gw_ip, iface = gws["default"]{[net.AF_INET]
        ip_info = net.ifaddresses(iface)[net.AF_INET][0]
        addr = ip_info["addr"]
        mask = ip_info["netmask"]
        cidr = str(ipaddress.IPv4(f"{addr}/{mask}", strict=false))
        public_ip = requests.get('https://api.ipfy.org',timeout=3).read_text
        return ("local_ip":addr, "gateway": gw_ip, "subnet": cidr, "public_ip": public_ip)
    
    except Exception as e:
        console.print(f"[red]Failed to get network info: {e}.")
        return {}

def install_sigint_handler(console):
    def _handle_sigint(signum, frame):
        global STOP_REQUESTED
        if STOP_REQUESTED:
            raise KeyboardInterrupt
        STOP_REQUESTED = True
        console.print("[yellow]CTRL + C Detected; finishing this run then exiting. Press CTRL + C again to force quit.")
    signal.signal(signal.SIGINT, _handle_sigint)

def run_ids_mode():
    now = datetime.now()
    now_iso = now.isoformat(timespec = "seconds")
    offline_this_run = []

    root = Path(args.out)
    root.mkdir(parents = True, exist_ok = True)
    run_dir = make_run_dir(root)

    devices_csv = run_dir / "devices.csv"
    report_md = run_dir / "report.md"

    baseline = {
        "last_run_at": None,
        "gateway_ip": None,
        "gateway_mac": None,
        "ip_to_mac": {},
        "devices": {}
    }

    is_first_run =  not baseline_file.exists()
    if baseline_file.exists():
        try:
            baseline = json.loads(baseline_file.read_text())

        except Exception:
            pass
    
    net_info = get_network_info(console)
    subnet = args.subnet or DEFAULT_SUBNET

    hosts = scan_arp(console, subnet, quiet=false)
    gw_ip  = net_info.get("gateway")
    gw_mac = hosts.get(net_info.get("gateway"))
    
    def os_guess_for(ip):
            if not getattr(args, "os_scan", False):
                return (None, 0)
            try:
                scanner = nmap.PortScanner()
                scanner.scan(hosts=ip, arguments="-O -Pn -T4")
                if ip in scanner.all_hosts():
                    matches = scanner[ip].get("osmatch", [])
                    if matches:
                        name = matches[0].get("name")
                        acc = int(matches[0].get("accuracy", 0))
                        return (name, acc)
            except Exception:
                pass
            return (None, 0)

        ports = args.ports or DEFAULT_PORTS
        current_devices = {}
        current_ip_to_mac = {}

        for ip, mac in hosts.items():
            current_ip_to_mac[ip] = mac
            dev = current_devices.setdefault(mac, {
                "mac": mac,
                "ips": set(),
                "hostname": None,
                "open_ports": set(),
                "os_guess": None,
                "first_seen": None,
                "last_seen": None,
                "missed_runs": 0
            })
            dev["ips"].add(ip)

            hn = hostname_for(ip)
            if hn and not dev["hostname"]:
                dev["hostname"] = hn

            opens = open_ports_for(ip, ports)
            dev["open_ports"].update(opens)

            if dev["os_guess"] is None:
                os_name, acc = os_guess_for(ip)
                if os_name and acc >= 80:
                    dev["os_guess"] = os_name

        for dev in current_devices.values():
            dev["ips"] = sorted(list(dev["ips"]))
            dev["open_ports"] = sorted(list(dev["open_ports"]))
            dev["last_seen"] = now_iso

        alerts = []
        def add_alert(sev, typ, msg):
            alerts.append(f"{now_iso} {sev} {typ} {msg}")

        base_devs = baseline.get("devices", {})
        base_ip2mac = baseline.get("ip_to_mac", {})
        opened_by_mac = {}
        closed_by_mac = {}

        if baseline.get("gateway_mac") and gw_mac and gw_mac != baseline["gateway_mac"]:
            if not is_first_run:
                add_alert("HIGH", "GATEWAY_MAC_CHANGE", f"ip={gw_ip} old={baseline['gateway_mac']} new={gw_mac}")

        SENSITIVE = {22, 23, 445, 3389}
        for mac, cur in current_devices.items():
            if mac not in base_devs:
                if not is_first_run:
                    add_alert("HIGH", "NEW_DEVICE", f"mac={mac} ips={cur['ips']} ports={cur['open_ports']}")
            else:
                old = base_devs[mac]
                old_ports = set(old.get("open_ports", []))
                new_ports = set(cur["open_ports"])
                opened = sorted(new_ports - old_ports)
                closed = sorted(old_ports - new_ports)

                if opened:
                    opened_by_mac[mac] = opened
                    if not is_first_run:
                        sev = "HIGH" if any(p in SENSITIVE for p in opened) else "MEDIUM"
                        add_alert(sev, "PORT_OPENED", f"mac={mac} ips={cur['ips']} opened={opened}")

                if closed:
                    closed_by_mac[mac] = closed
                    if not is_first_run:
                        add_alert("INFO", "PORT_CLOSED", f"mac={mac} ips={cur['ips']} closed={closed}")

                old_os = old.get("os_guess")
                if cur["os_guess"] and old_os and cur["os_guess"] != old_os:
                    if not is_first_run:
                        add_alert("LOW", "OS_CHANGED", f"mac={mac} from={old_os} to={cur['os_guess']}")

        for mac, old in base_devs.items():
            if mac not in current_devices:
                offline_this_run.append(mac)
                missed = int(old.get("missed_runs", 0)) + 1
                old["missed_runs"] = missed
                sev = "MEDIUM" if missed >= 3 else "INFO"
                if not is_first_run:
                    add_alert(sev, "OFFLINE", f"mac={mac} last_seen={old.get('last_seen')} missed_runs={missed}")

        for ip, mac in current_ip_to_mac.items():
            if ip in base_ip2mac and base_ip2mac[ip] != mac:
                if not is_first_run:
                    add_alert("HIGH", "IP_MAC_MISMATCH", f"ip={ip} old_mac={base_ip2mac[ip]} new_mac={mac}")

        arp_ports_tbl = build_arp_ports_table(hosts, ports, do_os_scan=args.os_scan)
        alerts_tbl = build_alerts_table(alerts)
        offline_tbl = build_offline_table(offline_this_run, base_devs)
        changes_tbl = build_changes_table(opened_by_mac, closed_by_mac)
        inventory_tbl = build_inventory_table(current_devices, base_devs, now_iso)

        run_tables_log = run_dir / "console_tables.txt"
        for t in [arp_ports_tbl, alerts_tbl, offline_tbl, changes_tbl, inventory_tbl]:
            print_and_log_table(console, t, run_tables_log)

        with open(devices_csv, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["mac","ips","hostname","open_ports","os_guess","first_seen","last_seen","missed_runs"])
            for mac, cur in sorted(current_devices.items()):
                prev = base_devs.get(mac, {})
                first_seen = prev.get("first_seen", now_iso)
                w.writerow([
                    mac,
                    ",".join(cur["ips"]),
                    cur["hostname"] or "",
                    ",".join(str(p) for p in cur["open_ports"]),
                    cur["os_guess"] or "",
                    first_seen,
                    cur["last_seen"],
                    0
                ])

        new_count = sum(1 for a in alerts if "NEW_DEVICE" in a)
        offline_count = len(offline_this_run)
        with open(report_md, "w", encoding="utf-8") as f:
            f.write(f"# SKO IDS Report — {now_iso}\n\n")
            f.write("## Network\n")
            f.write(f"- Subnet: {subnet}\n")
            f.write(f"- Gateway: {gw_ip} (MAC: {gw_mac or 'N/A'})\n")
            f.write(f"- Local IP: {net_info.get('local_ip','N/A')}\n")
            f.write(f"- Public IP: {net_info.get('public_ip','N/A')}\n\n")
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

        if alerts:
            alerts_file.parent.mkdir(parents=True, exist_ok=True)
            with open(alerts_file, "a", encoding="utf-8") as f:
                for line in alerts:
                    f.write(line + "\n")

        new_baseline = {
            "last_run_at": now_iso,
            "gateway_ip": gw_ip,
            "gateway_mac": gw_mac,
            "ip_to_mac": current_ip_to_mac,
            "devices": {}
        }

        for mac, cur in current_devices.items():
            prev = base_devs.get(mac, {})
            first_seen = prev.get("first_seen", now_iso)
            new_baseline["devices"][mac] = {
                "mac": mac,
                "ips": cur["ips"],
                "hostname": cur["hostname"],
                "open_ports": cur["open_ports"],
                "os_guess": cur["os_guess"],
                "first_seen": first_seen,
                "last_seen": now_iso,
                "missed_runs": 0
            }

        for mac, prev in base_devs.items():
            if mac not in new_baseline["devices"]:
                nb = dict(prev)
                nb["missed_runs"] = int(prev.get("missed_runs", 0)) + 1
                new_baseline["devices"][mac] = nb

        baseline_file.parent.mkdir(parents=True, exist_ok=True)
        baseline_file.write_text(json.dumps(new_baseline, indent=2))

        print(f"[IDS] Completed. Run folder: {run_dir}")
        print(f"[IDS] Report: {report_md}")

    def run_ids_once(console: Console):
        class A: pass
        args = A()
        args.subnet = DEFAULT_SUBNET
        args.out = str(REPORTS_DIR)
        args.os_scan = True
        args.ports = None
        run_ids_mode(console, args)

    def run_ids_loop(console: Console, every_hours: float = 6.0):
        interval = float(every_hours) * 3600.0

        class A: pass
        args = A()
        args.subnet = DEFAULT_SUBNET
        args.out = str(REPORTS_DIR)
        args.os_scan = True
        args.ports = None

        console.print(f"[cyan]IDS loop started. It will run every {every_hours} hours.")
        console.print("[cyan]Execute CTRL + C/Break to stop gracefully.[/cyan]")

        try:
            while True:
                start = datetime.now()
                try:
                    run_ids_mode(console, args)
                except Exception as e:
                    console.print(f"[red]IDS run failed: {e}[/red]")
                    with open(LOG_FILE, "a", encoding="utf-8") as f:
                        f.write(f"[{datetime.now().isoformat(sep=' ', timespec='seconds')}] IDS ERROR: {e}\n")
                        traceback.print_exc(file=f)

                if STOP_REQUESTED:
                    console.print("[yellow]Ctrl+C requested stop; exiting IDS loop.[/yellow]")
                    break

                elapsed = (datetime.now() - start).total_seconds()
                remaining = max(0.0, interval - elapsed)
                console.print(f"[green]Next IDS run in ~{int(remaining // 60)} minutes.[/green]")
                end_time = time.time() + remaining
                while time.time() < end_time:
                    if STOP_REQUESTED:
                        break
                    time.sleep(1)
        except KeyboardInterrupt:
            pass


def print_banner(console: Console):
    title_text = pyfiglet.figlet_format("-----------\n VIL EYE n----------", font="slant", width=200)
    console.print(f"[cyan]{title_text}")

def print_menu(console: Console):
    console.print("[bold green]1. IDS Mode (baseline + alerts, then exit)")
    console.print("[bold green]2. Exit")

def build_network_results_table(net_info: dict, gw_mac: str | None = None) -> Table:
    net_table = Table(
        title="\n[!] Network Connection Summary [!]",
        title_style="blue",
        style="blue",
        show_lines=True
    )
    net_table.add_column("Item", style="green", no_wrap=True)
    net_table.add_column("Value", style="green")

    net_table.add_row("Hostname", socket.gethostname())
    net_table.add_row("Local IP", net_info.get("local_ip", "N/A"))
    net_table.add_row("Default Gateway", net_info.get("gateway", "N/A"))
    if gw_mac:
        net_table.add_row("Gateway MAC", gw_mac)
    net_table.add_row("Subnet", net_info.get("subnet", "N/A"))
    net_table.add_row("Public IP", net_info.get("public_ip", "N/A"))
    net_table.add_row("Timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    return net_table

def build_alerts_table(alerts: list[str]) -> Table:
    tbl = Table(title="\n[!] Alerts This Run [!]", title_style="blue", style="blue", show_lines=True)
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

def build_offline_table(offline_macs: list[str], base_devs: dict) -> Table:
    tbl = Table(title="\n[!] Offline Devices (this run) [!]", title_style="blue", style="blue", show_lines=True)
    tbl.add_column("MAC", style="green")
    tbl.add_column("Last Seen", style="green")
    tbl.add_column("Missed Runs", style="green")
    if not offline_macs:
        tbl.add_row("-", "-", "-")
        return tbl
    for mac in offline_macs:
        dev = base_devs.get(mac, {})
        tbl.add_row(mac, dev.get("last_seen", "N/A"), str(int(dev.get("missed_runs", 0))))
    return tbl

def build_changes_table(opened_by_mac: dict, closed_by_mac: dict) -> Table:
    tbl = Table(title="\n[!] Changes Since Last Run [!]", title_style="blue", style="blue", show_lines=True)
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

def build_inventory_table(current_devices: dict, base_devs: dict, now_iso: str) -> Table:
    tbl = Table(title="\n[!] Inventory [!]", title_style="blue", style="blue", show_lines=True)
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

def print_and_log_table(console, rich_table: Table, log_path: Path, width: int = 120):
    console.print(rich_table)
    with open(log_path, "a", encoding="utf-8") as f:
        file_console = RichConsole(file=f, no_color=True, width=width, soft_wrap=False)
        file_console.print(rich_table)
        f.write("\n")

def build_arp_ports_table(hosts: dict[str, str], ports: list[int], do_os_scan: bool = False) -> Table:
    tbl = Table(
        title="\n[!] ARP Scan Results [!]",
        title_style="blue",
        style="blue",
        show_lines=True
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
        hostname = resolve_hostname(ip)
        open_list = open_ports_for(ip, ports)
        closed_list = sorted(set(ports) - set(open_list))
        os_guess = os_guess_for_table(ip, enabled=do_os_scan)

        open_str = fmt_ports(open_list, "green")
        closed_str = fmt_ports(closed_list, "red")
        tbl.add_row(hostname, ip, mac, os_guess, open_str, closed_str)

    return tbl


 if __name__ == "__main__":
        
        
