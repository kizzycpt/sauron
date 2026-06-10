import socket, random, ipaddress

from threading              import Thread, Lock
from concurrent.futures     import ThreadPoolExecutor
from datetime               import datetime
from pathlib                import Path
from pybloom_live           import BloomFilter

base_dir = Path(__file__).resolve().parent

class SaveIps:

    LOG_DIR = base_dir / "IP Scans"
    TS_FMT  = "%Y_%B_%d_%H_%M%p"

    def __init__(self):
        timestamp     = datetime.now().strftime(self.TS_FMT)
        self.log_path = self.LOG_DIR / f"{timestamp}.csv"

    def save(self, found: list[tuple[str, int]]) -> bool:
        if not found:
            print("[!] Nothing to save.")
            return False
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)

            with self.log_path.open("w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["IP Address", "Port", "Scanned At"])
                writer.writerows([
                    (ip, port, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                    for ip, port in found
                ])

            print(f"[+] Saved {len(found)} results → {self.log_path}")
            return True

        except PermissionError:
            print(f"[!] Permission denied: {self.log_path}")
        except OSError as e:
            print(f"[!] Save error: {e}")

        return False

class MassIPScanner:

    def __init__(self):
        
        self.scanning       = False
        self.scan_done      = False

        self.online_ips     = 0
        self.scanned_ips    = 0
        self.found          = []
        self.errors         = 0

        self.country        = None
        self.ports          = [7, 19, 20, 21, 22, 23, 25, 42, 43, 49, 53, 67, 68, 69, 70, 79, 80, 88,
                                102, 110, 113, 119, 123, 135, 137, 138, 139, 143, 161, 162, 177, 179,
                                194, 201, 264, 318, 381, 383, 389, 411, 412, 427, 443, 445, 464, 465,
                                497, 500, 512, 513, 514, 515, 520, 521, 540, 548, 554, 546, 547, 560,
                                563, 587, 591, 593, 596, 631, 636, 639, 646, 691, 860, 873, 902, 989,
                                990, 993, 995,]
        
        self.threads        = 250
        self.bloomsize      = 1_000_000_000
        self.bfilter_all    = None
        self.timeout        = 1
        self.save           = False
        self.save_results   = SaveIps()
        

        self.blocks         = []
        self.ip_pool        = []
        self.lock           = Lock()
        verbose             = False

        self.country        = False
        self.asn            = False

        #Modes              
        self.iot            = False
        self.nas            = False
        self.router         = False
        self.database       = False
        self.webserver      = False
        self.remote         = False
        self.camera         = False
        



    def _track_ip_blocks(self):
        
        try:
                # Do non-shared work outside the lock
            with self.lock:
                if not self.ip_pool:
                    if not self.blocks:
                        return None
                    block        = self.blocks.pop(0)
                    network      = ipaddress.IPv4Network(block)
                    self.ip_pool = [str(ip) for ip in network]
                
                # Only increment and pop need the lock
                self.scanned_ips += 1
                return self.ip_pool.pop(0)


                return None                   

        except Exception as e:
            return f"error: ip exception {e}"
    


    def _make_random_ip(self):
        try:
            if self.bfilter_all is None:
                self.bfilter_all = BloomFilter(capacity=self.bloomsize, error_rate=0.001)

            while True:
                ip = f'{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,254)}'

                with self.lock:
                    if ip in self.bfilter_all:
                        continue                  # already seen, try again
                    self.bfilter_all.add(ip)      # .add() not ()
                    self.scanned_ips += 1

                return ip

        except Exception as e:
            return f"Exception Error: {e}"

        except Exception as e:

            return f"Exception Error: {e}"
    
            

    def _get_ip(self):

        if self.country:
            return self._track_ip_blocks()
        
        return self._make_random_ip()



    def _validate_ip(self, ip):

        for port in self.ports:

            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(self.timeout)
                    result = s.connect_ex((ip, int(port)))
                
                    if result == 0:
                        with self.lock:
                            self.online_ips = self.online_ips + 1
                            self.found.append((ip, port))

                            return f"[+] {ip} --> {port}"
                        
            except OSError:
                with self.lock:
                    self.errors = self.errors + 1



    def _ip_threadder(self):
        while self.scanning:
            ip = self._get_ip()
            
            if ip is None:
                self.scanning  = False
                break
            self._validate_ip(ip)
    


    def run(self, ports=None, threads=None, blocks=None):

        self.scanning       = True
        self.scan_done      = False

        self.online_ips     = 0
        self.scanned_ips    = 0

        self.found          = []
        self.errors         = 0

        self.ip_pool        = []

        if ports:
            self.ports      = ports

        if threads:
            self.threads    = threads
        
        if blocks:
            self.blocks     = list(blocks)
        

        try:
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = [executor.submit(self._ip_threadder) for _ in range(self.threads)]
                for f in futures:
                    f.result()
        
        except KeyboardInterrupt:
            self.scanning   = False

        except Exception as e:
            self.scanning   = False
            return f"Fatal Error: {e}"
        
        finally:
            self.scanning   = False
            self.scan_done  = True

            if self.save and self.found:
                self.save_results.save(self.found)
    
    def start(self, ports=None, threads=None, blocks=None):
        Thread(target=self.run, kwargs={"ports": ports, "threads": threads, "blocks": blocks}, daemon=True).start()

    @property
    def status(self):

        return {
            "Scanning"          : self.scanning,
            "Scanned"           : self.scanned_ips,
            "Online"            : self.online_ips,
            "Errors "           : self.errors,
            "Found"             : self.found,
            "Scanned Blocks"    : self.blocks   
        }
    

mass_ip_scanner = MassIPScanner()

  

