from variables.Ether.gateway import Network, NetInfo
from variables.Ether.L2 import ARP, ARP_SCAN
from variables.Ether.ports import PortScan

class IDS:

    #class variables
    now = datetime.now()
    now_iso = now.isoformat(timespec="seconds")
    offline_this_run = []

    root = Path(args.out)
    root.mkdir(parents=True, exist_ok=True)
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
    subnet = NetInfo.get("subnet")

    hosts = ARP_SCAN(console, subnet, quiet=False)
    gw_ip = NetInfo.get("gateway")
    gw_mac = hosts.get(NetInfo.get("gateway"))

    net_tbl = build_network_results_table(net_info, gw_mac=gw_mac)
    print_and_log_table(console, net_tbl, LOG_FILE)

    
    
    def run_ids_mode(args):
        is_first_run = not baseline_file.exists()
        if baseline_file.exists():
            try:
                baseline = json.loads(baseline_file.read_text())
            except Exception:
                pass

    

    def run_ids_once(self):
        class A: pass
        args = A()
        args.subnet = subnet
        args.out = str
        args.os_scan = 
        args.ports = PortScan
        run_ids_mode(args)

    

    def run_ids_loop(console: Console, every_hours: float = 6.0):

        interval  = float(every_hours) * 3600.0
        start = datetime.now()

        elpased = (now - start).total_seconds()
        remaining = max(0.0, interval - elpased)

        end_time = time.time() + remaining


        class A: pass
        args = A()
        args.subnet = subnet
        args out = str( )
        
        args.ports = None


        console.print(f"[cyan]IDS loop started. It will run every {every_hours} hours.")
        console.print("[cyan]Execute CTRL + C/Break to stop gracefully.[/cyan]")

        
        try:
            while True:
                start
                
                try:
                    run_ids_mode(args)
                except Exception as e: console.print(f"[red]IDS run failed: {e}")
                    with open(LOG_FILE, "a" encoding = "utf-8") as f:
                        f.write(f:[{now.isoformat(sep=' ', time
                        traceback.print_exc(file=f))}])
                

                if STOP_REQUESTED
                    break

                while time.time() < end_time:
                    if STOP_REQUESTED:
                        break
                        time.sleep(1)
        
        except KeyboardInterrupt: pass  


#Instance(s)

ids_mode = IDS()



