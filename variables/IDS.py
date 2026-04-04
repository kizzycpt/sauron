from datetime import datetime
from pathlib import Path
import socket
import json
import csv
import traceback


class IDS:
    def __init__(self):
        
        self.now = datetime.now()
        self.now_iso = self.now.isoformat(timespec="seconds")
        self.offline_this_run = []

        self.root = Path(args.out)
        self.root.mkdir(parents=True, exist_ok=True)
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
        is_first_run = not baseline_file.exists()
        if baseline_file.exists():
            try:
                baseline = json.loads(baseline_file.read_text())
            except Exception:
                pass

        net_info = get_network_info(console)
        subnet = args.subnet or DEFAULT_SUBNET

        hosts = scan_arp(console, subnet, quiet=False)
        gw_ip = net_info.get("gateway")
        gw_mac = hosts.get(net_info.get("gateway"))

        net_tbl = build_network_results_table(net_info, gw_mac=gw_mac)
        print_and_log_table(console, net_tbl, LOG_FILE)

    