import json
import sys
import time
import traceback
import logging

from datetime import datetime
from pathlib import Path
from rich.console import Console


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


from variables.ether.gateway import Network, NetInfo
from variables.ether.L2 import l2_arp, arp_scan
from variables.utils.signals import install_sigint_handler
from variables.ether.icmp import ping
from variables.ether.ports import ports, common_ports
from variables.ether.mac import gateway_mac 
from variables.nodeinfo.hostname import get_hostname
from variables.nodeinfo.os import os_detect


#Instance
console  = Console()
#find parent folder
BASE_DIR = Path(__file__).resolve().parent



class IntrusionDetectionSystem:



    def __init__(self, out=None, subnet=None, ports=None, hostname=None, os_scan=None):
        self.scanning       = False
        self.scan_complete  = False
        self.scan_range     = " "
        self.out            = out or (BASE_DIR.parent / "logs" / "IDS" / "runs")
        self.subnet         = subnet or NetInfo.get("subnet")
        self.ports          = ports or common_ports
        self.hostname       = hostname or get_hostname
        self.os_scan        = os_scan if os_scan is not None else False
        self.stop           = install_sigint_handler(console)
        self.stop_requested = False
        self.BASE_DIR       = BASE_DIR.parent
        self.log_path       = self.BASE_DIR / "logs" / "IDS" / "ids.log" 
        self.run_dir_root   = self.BASE_DIR / "logs" / "IDS" / "runs"
        self.BASELINE_FILE  = self.BASE_DIR / "logs" / "IDS" / "data" / "baseline.json"
        self.baseline: dict = {
            "Last Run At"   : None,
            "Gateway IP"    : None,
            "Gateway MAC"   : None,
            "IP:MAC"     : {},
            "Devices"       : {},
        }
        self.current_devices: dict = {} 
        self.alerts         : list = []
        self.offline_this_run: list= []



# --- Helpers --------------------------------------------------------------


    @staticmethod
    def make_run_dir(root: Path) -> Path:
        start_time  = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        date        = root / start_time

        date.mkdir(parents=True)
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
        self.BASELINE_FILE.write_text(json.dumps(baseline, indent=2, default=str), encoding="utf-8")



    # --- Per Host Information -----------------------------------------------
    def per_host_info(self, hosts, base_devices, is_first_run, now_iso):
        
        current_devices: dict       = {}
        alerts: list[str]           = []
        offline_this_run: list[str] = []

        opened_by_mac: dict         = {}
        closed_by_mac: dict         = {}
        



        #Information and Port Comparisons
        for ip, mac in hosts.items():

            if self.stop_requested:
                break

            host_name   = self.hostname
            open_ports  = ports.port_check(ip, self.ports)
            os_str      = " "


            if self.os_scan:
                result = os_detect(ip)

                if result and len(result) == 2:
                    name, acc = result
                    os_str    = f"{name} ({acc}%)" if name else "-"
                else:
                    os_str    = "-"


            prev            = base_devices.get(mac, {})
            prev_ports      = set(prev.get("open_ports", []))
            current_ports   = set(open_ports)

            opened          = sorted(current_ports - prev_ports)
            closed          = sorted(prev_ports - current_ports)




            #log alerts table
            if opened:
                opened_by_mac[mac] = opened
                alerts.append(f"{now_iso}: [!]MEDIUM PORT OPENED[!] {mac} opened {opened}.")
            
            if closed:
                alerts.append(f"{now_iso}: [+] MEDIUM PORT CLOSED [+]\n {mac} closed {closed}")
            
            if mac not in base_devices and not is_first_run:
                alerts.append(f"{now_iso}: [+] HIGH NEW DEVICE [+]\n {ip}: {mac} first seen")
            
            current_devices[mac]   = {
                "IP"            : [ip],
                "Hostname"      : host_name,
                "Open Ports"    : sorted(open_ports),
                "Possible OS"   : os_str,
                "Last Seen"     : now_iso
            }

        self.current_devices    = current_devices
        self.alerts             = alerts
        self.offline_this_run   = []




    #If certain devices offline
    def offline_detection(self, base_devices, now_iso):
        for mac in base_devices:
            if mac not in self.current_devices:
                self.offline_this_run.append(mac)
                self.alerts.append(f"{now_iso}: [X] LOW OFFLINE [X] {mac} not seen this run")
    




    #update for comparison (previos scan as a baseline)
    def update_baselines(self, baseline, gw_ip, gw_mac, hosts, now_iso):

        baseline.update({
            "Last Run At"       : now_iso,
            "Gateway IP"        : gw_ip,
            "Gateway Mac"       : gw_mac,
            "IP:MAC"            : {ip: mac for ip, mac in hosts.items()},
            "Devices"           : self.current_devices
        })

        self.save_baseline(baseline)

        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(f"======Scan Completed @ {now_iso}======\n\n")

            if self.alerts:
                for a in self.alerts:
                    f.write(f"  [!]ALERT[!]: {a}\n")
        return baseline






# --- IDS Scan 1x ---------------------------------------------------------


    def run_once(self) -> dict:
        """ Run the IDS scan once. Return the updated basline for comparison """

        now         = datetime.now()
        now_iso     = now.isoformat(timespec="seconds")

        root        = Path(self.out)
        root.mkdir(parents=True, exist_ok=True)

        run_dir     = self.make_run_dir(root)
        devices_csv = run_dir / "devices.csv"
        report_md   = run_dir / "report.md"

        baseline    = self.load_baseline()
        base_devices= baseline.get("devices", {})
        is_first_run= not self.BASELINE_FILE.exists()






    # --- ARP Check  ---------------------------------------------------------

        hosts       = arp_scan(self.subnet, quiet=False)
        gw_ip       = NetInfo.get("gateway")
        gw_mac      = gateway_mac
        net_info    = NetInfo.get_all() if hasattr(NetInfo, "get_all") else {}

        self.per_host_info(hosts, base_devices, is_first_run, now_iso)
        self.offline_detection(base_devices, now_iso)
        self.update_baselines(baseline, gw_ip, gw_mac, hosts, now_iso)

    def run_loop(self, every_hours: float = 0.25):
        
        self.scanning = True
        self.scan_complete = False

        interval    = every_hours * 3600.0
        
        console.print(f"[cyan]IDS Monitoring Mode Activated - Scanning Every {every_hours} Hr(s). ")
        console.print(f"[yellow][!]Press (Ctrl+C) to terminate monitoring.")
        
        

        try:
            while True:
                try:
                    self.run_once()
                except Exception as e:
                    console.print(f"[red][!]Error Initiating Scan[!]: {e}")

                    with open(self.log_path, "a", encoding="utf-8") as f:
                        f.write(f"[{datetime.now().isoformat(sep=' ', timespec='seconds')}])"
                        f"[!]IDS Monitoring Failed[!]: {e}\n")
                        
                        traceback.print_exc(file=f)


                if self.stop or self.stop_requested:
                    break

                end_time = time.time() + interval
                console.print(f"[cyan][+]Next Scan in {every_hours}Hr(s) - CTRL+C to stop.")


                while time.time() < end_time:
                    if self.stop or self.stop_requested:
                        break
                    time.sleep(1)


                if self.stop or self.stop_requested:
                    break
        except KeyboardInterrupt:
            pass

        console.print(f"[red][X]IDS Terminated[X]")
        self.scanning = False
        self.scan_complete = True


#instances

ids_panel = IntrusionDetectionSystem()
ids_loop = ids_panel.run_loop




    
