#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sauron - Net Attack/Monitor Dashboard
    recreated by kizzycpt (ringmst4r)
- neofetch like system information
- IDS monitoring and counter intelligence tools
- Network scanner (press S to open panel, then press S again to start scan)
"""
import os
import sys
import time
import math
import threading
import platform
import json
import urllib.request
import urllib.error
import csv
import subprocess
import select
import argparse
from datetime import datetime, timedelta
from collections import deque
from pathlib import Path

# ─────────────────────────────────────────────
# Dependency checks with helpful install hints
# ─────────────────────────────────────────────
def _install_hint():
    print("\n📦 INSTALL INSTRUCTIONS:\n")
    if sys.platform == "linux":
        try:
            with open("/etc/os-release", "r") as f:
                os_info = f.read().lower()
            if any(d in os_info for d in ("kali", "debian", "ubuntu")):
                print("  Option 1 (Recommended - via apt):")
                print("    sudo apt install python3-psutil python3-blessed")
                print("\n  Option 2 (via pip with override):")
                print("    pip3 install psutil blessed --break-system-packages")
            else:
                print("  sudo pip3 install psutil blessed")
        except Exception:
            print("  sudo pip3 install psutil blessed")
    elif sys.platform == "win32":
        print("  pip install psutil blessed")
    else:
        print("  pip3 install psutil blessed")
    print("\n  Or install from requirements.txt:")
    print("    pip3 install -r requirements.txt --break-system-packages\n")

try:
    import psutil
except ImportError:
    print("\n❌ ERROR: Missing required module 'psutil'")
    _install_hint()
    sys.exit(1)

try:
    from blessed import Terminal
except ImportError:
    print("\n❌ ERROR: Missing required module 'blessed'")
    _install_hint()
    sys.exit(1)

# ── Optional local modules ────────────────────
try:
    from modes.netscan import scan_mode          # noqa: F401
    HAS_NETSCAN = True
except ImportError:
    HAS_NETSCAN = False

try:
    from modes.IDS import IDS                    # noqa: F401
    HAS_IDS = True
except ImportError:
    HAS_IDS = False

# ── Windows VT100 / UTF-8 ────────────────────
if sys.platform == "win32":
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# ─────────────────────────────────────────────
# Version  (SemVer: MAJOR.MINOR.PATCH)
# ─────────────────────────────────────────────
VERSION = "1.7.1"

# ─────────────────────────────────────────────
# Colour helpers
# ─────────────────────────────────────────────
def rgb(r, g, b):
    """ANSI foreground RGB escape."""
    return f"\033[38;2;{r};{g};{b}m"

def rgb_bg(r, g, b):
    """ANSI background RGB escape."""
    return f"\033[48;2;{r};{g};{b}m"

RESET = "\033[0m"

# ─────────────────────────────────────────────
# ASCII art assets
# ─────────────────────────────────────────────
DEATH_STAR_STATIC = [
    "                             .-------===-=+=-:                               ",
    "                       .-------:=-======-===+=++++=.                         ",
    "                    :----:------=-=-=-===-=++++=+++***-                      ",
    "                 :-----::::---:=---:=====--+=++=+**+**+**-                   ",
    "               --::--::.:::-::--:=---==+=--===#%#####*+++*##                 ",
    "            .-::.:::::.:::::------:--=====-=-%%#####**+++==*#*.              ",
    "           :-::.::::.::::::::::-:-::=======+=#%%%###**+=--=:+##+             ",
    "         .:--::.::::.......:..:::-:--=+-=====%%%%##%#++=-:----###:           ",
    "        :-:-::.::.: ...... ...:::--::=-==---==#%%%%%%%+--------#%%*          ",
    "       :-::::.::: ........ ..:::::-::==-=---==+#%%%%%%#--:---=-+#%%*         ",
    "      -:---:...:. .:.::... .::::::-::--=----===+*#%%%@#==----+-+#%%%#        ",
    "     ::---....:: ..:.:.... .:-:::::-::---=---===+++*%###**++=++=###%%%+      ",
    "    .-:--:-:.:-:...::.:... .:::::::-::--===--===++++++*#####***####%%%%-     ",
    "    =------...:. ..:.:.::..:::::::--:-===---===++++++++*******#####%%%%.     ",
    "   :-------...:.  .:...:.. .........::::::-----=====++++++***######%%%%+     ",
    "   ----::......-+=----====-----------====+++******######********###%%%%#     ",
    "   -::-=*#=:......::.....:..:::::::--::-----=-====+++++++++**#%%%%%%%%%%:    ",
    "   *+-:::::::::.::::::::.::::--:::--=-:---====++*+**++******##*###%%%%%%=    ",
    "  .-------:::--::::--:::.:::----:--==-:===+++=++*+********#*##*#%%%%%%%%*    ",
    "  .+-=-----:-----:-----:.:-:----:-===--===+=+=+****+**#*###*%###%%%%%%%%#    ",
    "  .+==----:--=------=---::-===--:=+===-===++++***##**####%####%%%%#%%#%%*    ",
    "   +====-----==---=====-:---====-===+=-+++++++***#***#######%#%%%%#%%%#%-    ",
    "   =+=======-=========----======-=+++==++++*++**###**##%####%%#%%%#%%%%%.    ",
    "   =*+++=====-===-===+=====++++++=+++++*++***+++*%#*#**#######%%%#%%%%%*     ",
    "   .+++++=+=--====-++=++=+=*++++++++++**+****+**###*#*#######%%%%%%%%%%=     ",
    "    =*++++++===+++=++=++=++******++**+*#+****+*#*########%%#%%%%%%%%%%#      ",
    "     **++++++==+=========++++++*+++**#**+***##***########%#%%%%%#%%#%%       ",
    "     :**+*+*+++**++++++++++*****+*+**#*#**####**########%%#%%%#%%%%%%-       ",
    "      -#******++*******+*++****#+**###*#**####*#########%#%%%%%%%#%%-        ",
    "       -#********#*#***#****######*###*###%######%%%%%%%%%%%%%%%#%%-         ",
    "        .##*#*******########*%####*##%#%#%#%%%%%%%%%%%%%%%%%%%%%%%           ",
    "          +%#########%#####%##%#%###%%#%%%%%%%%%%%%%%%%#%%%%%%%%*            ",
    "           :#%##%#%%#%%%##%%%%%#%%#%%%%%%%%%%%%%%%%%%%%%%%%%%%#.             ",
    "             :%%%%###%#########%%%%%#%%%%%%%%%%%%%%%%%%%%%%%%:               ",
    "               :#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%#.                 ",
    "                  +%@@%%%%%%@%@%%%%%%%%%%%%%@%@%%%%%%%%#=                    ",
    "                     -%%@%@@%%@@@@@@%@@@%%@@@%%%%%%%%-                       ",
    "                         :+@@@@@@@@@%%%%%%@%%@%%+:                           ",
    "                               .-===+++==-:.                                 ",
    "                                    ...                                      ",
    "                                                                             ",
]

EARTH_MAP = [
    "                                                                                                                        ",
    "                                                                                                                        ",
    "                                                                                                                        ",
    "                             # ####### #################                                    #                           ",
    "                       #    #   ### #################            ###                                                    ",
    "                      ###  ## ####       ############ #                        ##         ########        #####         ",
    "                  ## ###   #  ### ##      ###########                         #    #### ################   ###          ",
    "      ######## ###### #### # #  #  ###     #########              #######        # ## ##################################",
    " ### ###########################    ####   #####      #          ####### ###############################################",
    "      ########################       ##    ####                #### ####################################################",
    "      ### # #################      ##        #                ##### # ##########################################  ##    ",
    "                ##############     #####                   #     #  #######################################      ##     ",
    "                 ################ #######                # #   ###########################################      ##      ",
    "                  ########################                 ################################################             ",
    "                    ###################  ##                ################################################             ",
    "                   ################### #                    ##########  ####  ############################              ",
    "                   ##################                    ##### ##  ###    ### ##########################                ",
    "                   #################                     ###       # ######## ######################  #    #            ",
    "                    ###############                       #  ###       ##############################  #  #             ",
    "                     #############                        ######        #############################                   ",
    "                       ######## #                        ############################################                   ",
    "                      # ####     #                      ##################### #######################                   ",
    "                       # ###      #                    ################# ######    #################                    ",
    "                         ###  #   #                    ################## ######     ####  #####                        ",
    "                          #####   # #                  ################## #####      ###    ####                        ",
    "                             ####                      ################### ###       ##      ####   #                   ",
    "                               #    #                  ####################           #      # ##                       ",
    "                                #  #####                #####################         #      # #     ##                 ",
    "                                   ######                #### ###############          #      #    #                    ",
    "                                   ########                     ############                 ##   ##                    ",
    "                                  #########                     ###########                   #  ####                   ",
    "                                  #############                 ##########                    ##### #     ##            ",
    "                                 ################                ########                                  ## #         ",
    "                                  ###############                #########                         ## #    # #          ",
    "                                   #############                 #########                                              ",
    "                                   ############                  #########  #                         # ##  #           ",
    "                                     ##########                 #########  ##                        ########           ",
    "                                     ##########                  #######   ##                      ###########     #    ",
    "                                     ########                    #######   #                      #############         ",
    "                                     #######                     ######                           ##############        ",
    "                                     #######                      #####                            #############        ",
    "                                     ######                       ####                             ###   ######         ",
    "                                    #####                                                                  ####       # ",
    "                                    #####                                                                              #",
    "                                    ###                                                                      #        # ",
    "                                    ###                                                                             ##  ",
    "                                    ##                                                                                  ",
    "                                   ##                                                                                   ",
    "                                    ##                                                                                  ",
    "                                                                                                                        ",
    "                                                                                                                        ",
    "                                                                                                                        ",
    "                                       #                                                                                ",
    "                                      #                                #  ##########   ########################         ",
    "                                   #####                 ########################## #################################   ",
    "                  # ## #   #############              #############################################################     ",
    "        ## #########################             ##################################################################     ",
    "           ######################## #  #  ##     #################################################################      ",
    "    ##################################################################################################################  ",
    "########################################################################################################################",
]

LOGOS = {
    "Windows": [
        " ....::  ll",
        " ll  llllll",
        " ll  llllll",
        " ll  llllll",
        "",
        " ll  llllll",
        " ll  llllll",
        " ll  llllll",
        " ``  llllll",
    ],
    "Linux": [
        "    ___",
        "   (.. |",
        "   (<> |",
        "  / __  \\",
        " ( /  \\ /|",
    ],
    "Darwin": [
        "      .:'",
        "  __ :'__",
        " .'`__`-'",
        " :__/  ",
        " :/'",
    ],
}

# ─────────────────────────────────────────────
# IP Intelligence
# ─────────────────────────────────────────────
class IPIntelligence:
    """IP Geolocation and Threat Intelligence."""
    _PRIVATE_PREFIXES = (
        "10.", "192.168.", "172.16.", "127.", "localhost",
        "fe80:", "::1", "fc00:", "fd00:",
    )

    def __init__(self):
        self.cache: dict = {}
        self.cache_ttl = 3600  # 1 hour

    def get_geolocation(self, ip: str) -> dict:
        if ip in self.cache:
            entry = self.cache[ip]
            if time.time() - entry.get("timestamp", 0) < self.cache_ttl:
                return entry["geo"]

        if ip.startswith(self._PRIVATE_PREFIXES):
            geo = {
                "country": "LOCAL", "countryCode": "LO",
                "city": "Private Network", "isp": "Local Network", "threat": "SAFE",
            }
            self.cache[ip] = {"geo": geo, "timestamp": time.time()}
            return geo

        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,org,as"
            req = urllib.request.Request(url, headers={"User-Agent": "DEATH_STAR/1.7"})
            with urllib.request.urlopen(req, timeout=2) as resp:
                data = json.loads(resp.read().decode())
            if data.get("status") == "success":
                geo = {
                    "country":     data.get("country", "Unknown"),
                    "countryCode": data.get("countryCode", "??"),
                    "city":        data.get("city", "Unknown"),
                    "isp":         data.get("isp", "Unknown"),
                    "org":         data.get("org", ""),
                    "as":          data.get("as", ""),
                    "threat":      self._assess_threat(data),
                }
                self.cache[ip] = {"geo": geo, "timestamp": time.time()}
                return geo
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError):
            pass

        return {"country": "Unknown", "countryCode": "??",
                "city": "Unknown", "isp": "Unknown", "threat": "UNKNOWN"}

    def _assess_threat(self, geo_data: dict) -> str:
        org = geo_data.get("org", "").lower()
        isp = geo_data.get("isp", "").lower()
        if any(x in org or x in isp for x in
               ["amazon", "aws", "google cloud", "azure", "digitalocean", "ovh", "hetzner"]):
            return "CLOUD"
        if any(x in org or x in isp for x in
               ["hosting", "server", "datacenter", "vps", "dedicated"]):
            return "HOSTING"
        if any(x in isp for x in
               ["telecom", "comcast", "verizon", "att", "broadband", "cable"]):
            return "ISP"
        return "UNKNOWN"


# ─────────────────────────────────────────────
# Firewall Log Parser
# ─────────────────────────────────────────────
class FirewallLogParser:
    """Parse firewall logs and detect port scans."""
    PORT_NAMES = {
        "22": "SSH",    "80": "HTTP",   "443": "HTTPS",  "21": "FTP",
        "23": "Telnet", "25": "SMTP",   "3306": "MySQL", "3389": "RDP",
        "445": "SMB",   "1433": "MSSQL","5900": "VNC",   "8080": "HTTP-ALT",
        "137": "NetBIOS","138": "NetBIOS","139": "NetBIOS",
    }




    def __init__(self, log_path=None, enable_logging=True):
        self.platform    = sys.platform
        self.log_path    = log_path or self._get_default_log_path()
        self.ip_tracking: dict = {}
        self.scan_threshold = 5
        self.time_window    = 60
        self.running        = False
        self.connections    = deque(maxlen=20)
        self.ip_intel       = IPIntelligence()
        self.enable_logging = enable_logging
        self.log_dir        = Path("logs")
        self.csv_lock       = threading.Lock()
        self.current_log_file = None
        if self.enable_logging:
            self._setup_logging()






    def _setup_logging(self):
        try:
            self.log_dir.mkdir(exist_ok=True)
            today = datetime.now().strftime("%Y-%m-%d")
            self.current_log_file = self.log_dir / f"attacks_{today}.csv"
            if not self.current_log_file.exists():
                with open(self.current_log_file, "w", newline="", encoding="utf-8") as f:
                    csv.writer(f).writerow([
                        "Timestamp","Source_IP","Dest_IP","Port","Protocol",
                        "Service","Country","City","ISP","Threat_Level","Attack_Type","Action",
                    ])
        except Exception as e:
            print(f"Warning: Could not setup logging: {e}")
            self.enable_logging = False




    def _log_attack(self, conn):
        if not self.enable_logging:
            return
        try:
            today = datetime.now().strftime("%Y-%m-%d")
            expected = self.log_dir / f"attacks_{today}.csv"
            if expected != self.current_log_file:
                self._setup_logging()
            with self.csv_lock:
                with open(self.current_log_file, "a", newline="", encoding="utf-8") as f:
                    csv.writer(f).writerow([
                        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        getattr(conn, "ip",          "Unknown"),
                        getattr(conn, "dst_ip",      "Unknown"),
                        getattr(conn, "port",        "Unknown"),
                        getattr(conn, "protocol",    "Unknown"),
                        getattr(conn, "service",     "Unknown"),
                        getattr(conn, "country",     "??"),
                        getattr(conn, "city",        "Unknown"),
                        getattr(conn, "isp",         "Unknown"),
                        getattr(conn, "threat",      "UNKNOWN"),
                        getattr(conn, "attack_type", "PROBE"),
                        getattr(conn, "action",      "DROP"),
                    ])
        except Exception:
            pass

    

    def _get_default_log_path(self):
        if self.platform == "win32":
            return r"C:\Windows\System32\LogFiles\Firewall\pfirewall.log"
        
        
        ufw = Path("/var/log/ufw.log")
        if ufw.exists():
            return ufw
        
        kern = Path("var/;og/kern.log")
        if kern.exists():
            return kern
        return "journalctl"
        


    def parse_windows_log_line(self, line):
        if line.startswith("#") or not line.strip():
            return None
        try:
            parts = line.split()
            if len(parts) < 8:
                return None
            return {
                "timestamp": f"{parts[0]} {parts[1]}",
                "action":    parts[2],
                "protocol":  parts[3],
                "src_ip":    parts[4],
                "dst_ip":    parts[5],
                "src_port":  parts[6],
                "dst_port":  parts[7],
            }
        except Exception:
            return None



    def parse_linux_log_line(self, line):
        try:
            if "UFW" in line and ("BLOCK" in line or "DROP" in line):
                entry = {}
                if "SRC=" in line:
                    s = line.index("SRC=") + 4
                    entry["src_ip"] = line[s:line.index(" ", s)]
                if "DPT=" in line:
                    s = line.index("DPT=") + 4
                    e = line.find(" ", s)
                    entry["dst_port"] = line[s:] if e == -1 else line[s:e]
                if "PROTO=" in line:
                    s = line.index("PROTO=") + 6
                    entry["protocol"] = line[s:line.index(" ", s)]
                    entry["action"]    = "DROP"
                    entry["timestamp"] = " ".join(line.split()[0:3])
                if "src_ip" in entry and "dst_port" in entry:
                    entry.setdefault("dst_ip", "Unknown")
                    return entry
                if "IN=" in line and "SRC=" in line and ("DROP" in line or "BLOCK" in line):
                    entry = {"action": "DROP", "timestamp": " ".join(line.split()[0:3])}
                if "SRC=" in line:
                    s = line.index("SRC=") + 4
                    entry["src_ip"] = line[s:line.index(" ", s)]
                if "DPT=" in line:
                    s = line.index("DPT=") + 4
                    e = line.find(" ", s)
                    entry["dst_port"] = line[s:] if e == -1 else line[s:e]
                if "PROTO=" in line:
                    s = line.index("PROTO=") + 6
                    entry["protocol"] = line[s:line.index(" ", s)]
                else:
                    entry["protocol"] = "TCP"
                entry.setdefault("dst_ip", "Unknown")
                if "src_ip" in entry and "dst_port" in entry:
                    return entry
        except Exception:
            pass
            return None




    def detect_scan(self, src_ip):
        now = time.time()
        if src_ip in self.ip_tracking:
            self.ip_tracking[src_ip] = [
                (p, ts) for p, ts in self.ip_tracking[src_ip]
                if now - ts < self.time_window
            ]
            unique = {p for p, _ in self.ip_tracking[src_ip]}
            if len(unique) >= self.scan_threshold:
                return True, list(unique)
        return False, []




    def add_entry(self, entry):
        if not entry or entry.get("action") != "DROP":
            return
        src_ip   = entry["src_ip"]
        dst_port = entry.get("dst_port", "?")
        self.ip_tracking.setdefault(src_ip, []).append((dst_port, time.time()))
        is_scan, ports = self.detect_scan(src_ip)

        Conn = type("Connection", (), {})
        conn = Conn()
        conn.ip          = src_ip
        conn.dst_ip      = entry.get("dst_ip", "Unknown")
        conn.port        = dst_port
        conn.protocol    = entry.get("protocol", "TCP")
        conn.timestamp   = entry.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        conn.action      = entry.get("action", "DROP")
        conn.count       = sum(1 for c in self.connections
                               if hasattr(c, "ip") and c.ip == src_ip) + 1
        conn.service     = self.PORT_NAMES.get(str(dst_port), f"Port {dst_port}")
        conn.attack_type = f"SCAN ({len(ports)}p)" if is_scan else "PROBE"

        geo = self.ip_intel.get_geolocation(src_ip)
        conn.country      = geo.get("countryCode", "??")
        conn.country_full = geo.get("country",     "Unknown")
        conn.city         = geo.get("city",        "Unknown")
        conn.isp          = geo.get("isp",         "Unknown")
        conn.threat       = geo.get("threat",      "UNKNOWN")

        self.connections.append(conn)
        self._log_attack(conn)




    def tail_file(self):
        try:
            if self.log_path == "journalctl":
                return
            if not Path(self.log_path):
                return
            with Path(self.log_path).open("r", encoding="utf-8", errors="ignore") as f:
                f.seek(0)
                while self.running:
                    line = f.readline()
                    if line:
                        entry = (self.parse_windows_log_line(line)
                                 if self.platform == "win32"
                                 else self.parse_linux_log_line(line))
                        if entry:
                            self.add_entry(entry)
                    else:
                        time.sleep(0.01)
        except Exception:
            pass
    
    def _tail_journalctl(self):
        try:
            proc = subprocess.Popen(
                ["journalctl", "-k", "-f", "--no-pager", "-o", "short"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
            )
            while self.running:
                line = proc.stdout.readline()
                if line:
                    entry = self.parse_linux_log_line(line)
                    if entry:
                        self.add_entry(entry)
        except Exception:
            pass




    def start(self):
        self.running = True
        threading.Thread(target=self.tail_file, daemon=True).start()




    def stop(self):
        self.running = False




    def get_connections(self):
        return list(self.connections)





# ─────────────────────────────────────────────
# Network Scanner Panel
# ─────────────────────────────────────────────
class NetScanPanel:
    """Lightweight built-in network scanner shown when pressing S.
    Panel opens on first S press. Scan starts on second S press (or explicit call).
    If modes.netscan is available its scan_mode() is preferred."""

    def __init__(self):
        self.results: list[dict] = []
        self.scanning   = False
        self.scan_done  = False
        self.scan_range = ""
        self._lock      = threading.Lock()




    def _ping(self, ip: str) -> bool:
        try:
            flag = "-n" if sys.platform == "win32" else "-c"
            r = subprocess.run(
                ["ping", flag, "1", "-W", "1", ip],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=2,
            )
            return r.returncode == 0
        except Exception:
            return False




    def _get_hostname(self, ip: str) -> str:
        import socket
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return ""




    def _port_check(self, ip: str, ports=(22, 80, 443, 3389, 445, 3306)) -> list:
        import socket
        open_ports = []
        for p in ports:
            try:
                with socket.create_connection((ip, p), timeout=0.3):
                    open_ports.append(p)
            except Exception:
                pass
        return open_ports




    def _scan_host(self, ip: str):
        if not self._ping(ip):
            return
        hostname   = self._get_hostname(ip)
        open_ports = self._port_check(ip)
        os_guess   = self._os_detect(ip)
        entry = {"ip": ip, "hostname": hostname, "ports": open_ports,
                "os": os_guess, "ts": datetime.now().strftime("%H:%M:%S")}
        with self._lock:
            self.results.append(entry)




    def _os_detect(self, ip: str) -> str:
        try:
            r = subprocess.run(
                ["nmap", "-O", "--osscan-guess", ip],
                capture_output=True, text=True, timeout=10,
            )
            for line in r.stdout.splitlines():
                if "OS guess" in line or "OS details" in line:
                    return line.split(":", 1)[-1].strip()
        except Exception:
            pass
        return "-"




    def start_scan(self, subnet: str = ""):
        """Start a background ping sweep of the local /24.
        Only called when user explicitly presses S while panel is open."""
        if self.scanning:
            return
        self.results.clear()
        self.scan_done  = False
        self.scanning   = True
        self.scan_range = subnet



        def _worker():
            import socket
            base = subnet
            if not base:
                try:
                    hostname = socket.gethostname()
                    local_ip = socket.gethostbyname(hostname)
                    parts    = local_ip.rsplit(".", 1)
                    base     = parts[0] + "."
                except Exception:
                    base = "192.168.1."
            if not base.endswith("."):
                base = base.rsplit(".", 1)[0] + "."
            self.scan_range = base + "0/24"
            threads = []
            for i in range(1, 255):
                t = threading.Thread(target=self._scan_host,
                                     args=(f"{base}{i}",), daemon=True)
                t.start()
                threads.append(t)
            for t in threads:
                t.join(timeout=5)
            self.scanning  = False
            self.scan_done = True

        threading.Thread(target=_worker, daemon=True).start()




# ─────────────────────────────────────────────
# Globe renderer
# ─────────────────────────────────────────────
class Globe:
    """3D ASCII Globe renderer."""
    def __init__(self, width, height, aspect_ratio=2.0):
        self.width        = max(1, width)
        self.height       = max(1, height)
        self.aspect_ratio = aspect_ratio
        self.map_width    = len(EARTH_MAP[0])
        self.map_height   = len(EARTH_MAP)
        self.radius       = max(1.0, min(width / 2.5, height * aspect_ratio / 2.5))
        self.attacks: list = []
        self.lighting     = False
        self.plus_mode    = False




    def add_attack(self, lat, lon, label="*"):
        self.attacks.append((lat, lon, label))




    def sample_earth_at(self, lat, lon):
        y = int(((lat + 90) / 180) * (self.map_height - 1))
        x = int(((lon + 180) / 360) * (self.map_width - 1))
        y = max(0, min(y, self.map_height - 1))
        x = max(0, min(x, self.map_width - 1))
        return EARTH_MAP[y][x]




    def project_3d_to_2d(self, lat, lon, rotation):
        adj_lon = (((-lon + 90) + 180) % 360) - 180
        lat_r   = math.radians(lat)
        lon_r   = math.radians(adj_lon + math.degrees(rotation))
        x = math.cos(lat_r) * math.cos(lon_r)
        y = math.sin(lat_r)
        z = math.cos(lat_r) * math.sin(lon_r)
        if z < 0:
            return None, None, False
        sx = int(x * self.radius) + self.width  // 2
        sy = int(-y * self.radius / self.aspect_ratio) + self.height // 2
        if 0 <= sx < self.width and 0 <= sy < self.height:
            return sx, sy, True
        return None, None, False




    def render(self, rotation, rainbow_mode=False, skittles_mode=False):
        screen  = [[(" ", 0, False)] * self.width for _ in range(self.height)]
        density = [[0.0]            * self.width for _ in range(self.height)]
        attack  = [[False]          * self.width for _ in range(self.height)]
        cx, cy = self.width // 2, self.height // 2



        for lat, lon, _ in self.attacks:
            sx, sy, vis = self.project_3d_to_2d(lat, lon, rotation)
            if vis:
                attack[sy][sx] = True



        for y in range(self.height):
            for x in range(self.width):
                dx = float(x - cx)
                dy = float(y - cy) * self.aspect_ratio
                dist = math.sqrt(dx*dx + dy*dy)
                if dist <= self.radius:
                    nx, ny = dx / self.radius, dy / self.radius
                    nz2 = 1 - nx*nx - ny*ny
                    if nz2 >= 0:
                        nz  = math.sqrt(nz2)
                        lat = math.degrees(math.asin(ny))
                        lon = (math.degrees(math.atan2(nx, nz)) + math.degrees(rotation))
                        lon = ((lon + 180) % 360) - 180
                        ch  = self.sample_earth_at(lat, lon)
                        bd  = 1.0 if ch == "#" else (0.6 if ch == "." else (0.8 if ch != " " else 0.0))
                        density[y][x] += bd
                        if bd > 0:
                            aa = 0.05
                            if x > 0:                density[y][x-1] += aa
                            if x < self.width  - 1:  density[y][x+1] += aa
                            if y > 0:                density[y-1][x] += aa
                            if y < self.height - 1:  density[y+1][x] += aa
                if self.radius - 0.5 < dist < self.radius + 0.5:
                    density[y][x] += 0.2



        CHARS = [(" ", 0.0), ("`", 0.05), (".", 0.10), ("-", 0.15), ("+", 0.20),
                 ("=", 0.30), ("o", 0.40), ("%", 0.60), ("#", 0.80), ("@", 1.0)]



        for y in range(self.height):
            for x in range(self.width):
                d  = density[y][x]
                ch = " "
                for c, thr in reversed(CHARS):
                    if d >= thr:
                        ch = c; break
                if self.plus_mode and ch not in (" ", "`", ".", "-"):
                    ch = "+"
                if attack[y][x]:
                    ch = "*"
                shaded = self.lighting and ch != " "
                cidx   = 0
                if ch != " ":
                    if rainbow_mode:
                        cidx = ((x + y) % 7) + 1
                    elif skittles_mode:
                        h = (((x*2654435761)^(y*2246822519)^((x^y)*3266489917)) & 0xFFFFFFFF)
                        cidx = (h % 16) + 1
                screen[y][x] = (ch, cidx, shaded)
        return screen


# ─────────────────────────────────────────────
# System info helpers
# ─────────────────────────────────────────────
def get_system_info():
    info = {}
    os_name = platform.system()



    if sys.platform == "win32":
        try:
            r = subprocess.run(["wmic","os","get","BuildNumber"],
                               capture_output=True, text=True, timeout=2)
            nums = [l.strip() for l in r.stdout.split("\n")
                    if l.strip() and "BuildNumber" not in l]
            info["OS"] = f"{os_name} {platform.release()} (Build {nums[0]})" if nums else \
                         f"{os_name} {platform.release()}"
        except Exception:
            info["OS"] = f"{os_name} {platform.release()}"
    else:
        info["OS"] = f"{os_name} {platform.release()}"




    info["Kernel"]       = platform.version() if sys.platform == "win32" else platform.release()
    info["Architecture"] = platform.machine()
    info["Host"]         = platform.node()

    for var, name in [("WT_SESSION","Windows Terminal"),("ConEmuPID","ConEmu"),
                      ("HYPER_VERSION","Hyper"),("ALACRITTY_SOCKET","Alacritty")]:
        if os.environ.get(var):
            info["Terminal"] = name; break
    else:
        info["Terminal"] = (os.environ.get("TERM_PROGRAM") or
                            os.environ.get("TERM") or "Unknown")




    try:
        if sys.platform == "win32":
            r = subprocess.run(
                ["wmic","path","Win32_VideoController",
                 "get","CurrentHorizontalResolution,CurrentVerticalResolution"],
                capture_output=True, text=True, timeout=2)
            nums = [l.strip() for l in r.stdout.split("\n")
                    if l.strip() and "Current" not in l]
            parts = nums[0].split() if nums else []
            info["Resolution"] = f"{parts[0]}x{parts[1]}" if len(parts) >= 2 else "N/A"
        else:
            r = subprocess.run(["xrandr"], capture_output=True, text=True, timeout=2)
            info["Resolution"] = next(
                (l.split()[0] for l in r.stdout.split("\n") if "*" in l), "N/A")
    except Exception:
        info["Resolution"] = "N/A"




    try:
        if sys.platform == "win32":
            r = subprocess.run(["wmic","baseboard","get","Manufacturer,Product"],
                               capture_output=True, text=True, timeout=2)
            lines = [l.strip() for l in r.stdout.split("\n")
                     if l.strip() and "Manufacturer" not in l]
            info["Motherboard"] = lines[0] if lines else "N/A"
        else:
            r = subprocess.run(["dmidecode","-t","2"],
                               capture_output=True, text=True, timeout=2)
            mfr = prd = ""
            for line in r.stdout.split("\n"):
                if "Manufacturer:" in line: mfr = line.split(":")[1].strip()
                if "Product Name:" in line: prd = line.split(":")[1].strip()
            info["Motherboard"] = f"{mfr} {prd}".strip() or "N/A"
    except Exception:
        info["Motherboard"] = "N/A"

    info["CPU"] = platform.processor() or "N/A"





    try:
        if sys.platform == "win32":
            r = subprocess.run(["wmic","path","win32_VideoController","get","name"],
                               capture_output=True, text=True, timeout=2)
            gpus = [l.strip() for l in r.stdout.split("\n")
                    if l.strip() and "Name" not in l]
            info["GPU"] = gpus[0][:25] + ("..." if len(gpus[0]) > 25 else "") if gpus else "N/A"
        else:
            info["GPU"] = "N/A"
    except Exception:
        info["GPU"] = "N/A"





    try:
        if sys.platform == "win32":
            r = subprocess.run(["wmic","bios","get","SMBIOSBIOSVersion"],
                               capture_output=True, text=True, timeout=2)
            lines = [l.strip() for l in r.stdout.split("\n")
                     if l.strip() and "SMBIOS" not in l]
            info["BIOS"] = lines[0] if lines else "N/A"
        else:
            r = subprocess.run(["dmidecode","-s","bios-version"],
                               capture_output=True, text=True, timeout=2)
            info["BIOS"] = r.stdout.strip() or "N/A"
    except Exception:
        info["BIOS"] = "N/A"





    m = psutil.virtual_memory()
    info["RAM"] = f"{m.used//1024**3}GB / {m.total//1024**3}GB ({int(m.percent)}%)"

    try:
        d = psutil.disk_usage("C:\\" if sys.platform == "win32" else "/")
        info["Disk"] = f"{d.used//1024**3}GB / {d.total//1024**3}GB ({int(d.percent)}%)"
    except Exception:
        info["Disk"] = "N/A"





    try:
        if sys.platform == "win32":
            r = subprocess.run(["wmic","nic","where","NetEnabled=true","get","Name"],
                               capture_output=True, text=True, timeout=2)
            ntype = "Ethernet"
            for line in r.stdout.split("\n"):
                ll = line.lower()
                if any(w in ll for w in ("wireless","wi-fi","802.11","wifi")):
                    ntype = "WiFi"; break
            info["Network"] = ntype
        else:
            r = subprocess.run(["iwconfig"], capture_output=True, text=True, timeout=2)
            info["Network"] = "WiFi" if r.returncode == 0 and "no wireless" not in r.stderr.lower() \
                              else "Ethernet"
    except Exception:
        info["Network"] = "Unknown"





    try:
        up = datetime.now() - datetime.fromtimestamp(psutil.boot_time())
        d, h, m = up.days, up.seconds // 3600, (up.seconds % 3600) // 60
        info["Uptime"] = f"{d}d {h}h" if d else f"{h}h {m}m"
    except Exception:
        info["Uptime"] = "N/A"





    try:
        info["CPU Load"] = f"{psutil.cpu_percent(interval=0.1)}%"
    except Exception:
        info["CPU Load"] = "N/A"





    try:
        temps = psutil.sensors_temperatures() if hasattr(psutil,"sensors_temperatures") else {}
        cpu_t = None
        for name, ents in (temps or {}).items():
            if any(k in name.lower() for k in ("coretemp","cpu","k10temp")):
                if ents: cpu_t = ents[0].current; break
        info["CPU Temp"] = f"{int(cpu_t)}°C" if cpu_t else "N/A"
    except Exception:
        info["CPU Temp"] = "N/A"





    try:
        bat = psutil.sensors_battery()
        if bat:
            pct    = int(bat.percent)
            status = "Charging" if bat.power_plugged else "Discharging"
            if bat.secsleft not in (psutil.POWER_TIME_UNLIMITED, psutil.POWER_TIME_UNKNOWN):
                h, m_ = bat.secsleft // 3600, (bat.secsleft % 3600) // 60
                info["Battery"] = f"{pct}% ({status}) {h}h {m_}m"
            else:
                info["Battery"] = f"{pct}% ({status})"
        else:
            info["Battery"] = None
    except Exception:
        info["Battery"] = None

    return info, os_name


# ─────────────────────────────────────────────
# Dashboard
# ─────────────────────────────────────────────
class Dashboard:
    
    
    THEMES = {
        "matrix":   {"name":"Matrix",   "globe":"bright_green",   "feed":"bright_yellow", "stats":"bright_cyan"},
        "amber":    {"name":"Amber",    "globe":"bright-red",     "feed":"bright-red",    "stats":"red"},
        "nord":     {"name":"Nord",     "globe":"bright_cyan",    "feed":"bright_blue",   "stats":"bright_cyan"},
        "dracula":  {"name":"Dracula",  "globe":"bright_magenta", "feed":"bright_magenta","stats":"magenta"},
        "mono":     {"name":"Mono",     "globe":"bright_white",   "feed":"bright_white",  "stats":"white"},
        "rainbow":  {"name":"Rainbow",  "globe":"bright_green",   "feed":"bright_magenta","stats":"bright_cyan", "rainbow":True},
        "skittles": {"name":"Skittles", "globe":"bright_green",   "feed":"bright_yellow", "stats":"bright_magenta","skittles":True},
    }

    _RGB = {
        "bright_green":   (0,255,65),   "green":          (0,150,40),
        "bright_yellow":  (255,255,0),  "yellow":         (255,176,0),
        "bright_cyan":    (0,255,255),  "cyan":           (0,191,255),
        "bright_magenta": (255,0,255),  "magenta":        (255,0,255),
        "bright_blue":    (100,149,237),"blue":           (0,0,255),
        "bright_white":   (255,255,255),"white":          (200,200,200),
        "bright_red":     (255,0,0),    "red":            (255,0,0),
        "orange":         (255,165,0),  "purple":         (138,43,226),
    }
    _RAINBOW  = [(255,0,0),(255,127,0),(255,255,0),(0,255,0),
                 (0,191,255),(138,43,226),(255,0,255)]
    _SKITTLES = [(255,0,0),(255,69,0),(255,127,0),(255,165,0),(255,215,0),(255,255,0),
                 (173,255,47),(0,255,0),(0,255,127),(0,206,209),(0,191,255),(0,0,255),
                 (138,43,226),(148,0,211),(255,0,255),(255,20,147)]






    def __init__(self, rotation_period=50, theme="matrix", log_path=None):
        self.term        = Terminal()
        self.rotation_period = rotation_period
        self.start_time  = time.time()
        self.theme_names = list(self.THEMES)
        tidx             = self.theme_names.index(theme) if theme in self.THEMES else 0
        self.current_theme_index = tidx
        self.theme       = self.THEMES[self.theme_names[tidx]]

        # UI state flags
        self.paused             = False
        self.pause_rotation     = 0.0
        self.show_legend        = False
        self.lighting           = False
        self.plus_mode          = False
        self.death_star_mode    = False
        self.show_attack_details= False
        self.operator_mode      = False
        self.netscan_mode       = False   # S toggles panel open/closed
        self.netscan_panel_open = False   # True = panel visible; scan not yet started
        self.running            = True
        self.globe              = None

        # System-info cache
        self.sys_info_cache     = None
        self.sys_info_os        = None
        self.sys_info_last_upd  = 0
        self.sys_info_interval  = 2.0

        # Firewall log parser (live only)
        self.log_parser  = FirewallLogParser(log_path)
        self.use_real_logs = self._verify_firewall_logging_active()

        # Test locations on globe
        self.test_locations = [
            (40.7128,  -74.0060, "NYC"),
            (51.5074,   -0.1278, "LON"),
            (35.6762,  139.6503, "TYO"),
            (-33.8688, 151.2093, "SYD"),
        ]

        # Network scanner — panel and scan are separate actions
        self.netscan = NetScanPanel()





    # ── Firewall log verification ─────────────
    def _verify_firewall_logging_active(self):
        path = self.log_parser.log_path
        if not Path(str(path)).exists():
            return False
        try:
            st  = os.stat(path)
            age = time.time() - st.st_mtime
            if age < 86400:
                return True
            if st.st_size == 0:
                return False
            if age < 604800:
                return True
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()[:50]
            for ln in lines:
                ln = ln.strip()
                if ln.startswith(("#Fields:", "#Software:")):
                    return True
                if not ln or ln.startswith("#"):
                    continue
                if len(ln.split()) >= 8:
                    return True
            return False
        except Exception:
            return False





    # ── Theme helpers ─────────────────────────
    def cycle_theme(self):
        self.current_theme_index = (self.current_theme_index + 1) % len(self.theme_names)
        self.theme = self.THEMES[self.theme_names[self.current_theme_index]]

    def get_rotation(self):
        if self.paused:
            return self.pause_rotation
        elapsed = time.time() - self.start_time
        return -(elapsed / self.rotation_period) * 2 * math.pi

    def get_color(self, color_name, color_idx=0, dim=False):
        if color_idx > 0:
            palette = self._SKITTLES if self.theme.get("skittles") else self._RAINBOW
            r, g, b = palette[(color_idx - 1) % len(palette)]
        else:
            r, g, b = self._RGB.get(color_name, (255, 255, 255))
        if dim:
            r, g, b = int(r*.6), int(g*.6), int(b*.6)
        code = rgb(r, g, b)
        return lambda text: code + str(text) + RESET





    # ── Death Star renderer ───────────────────
    def render_death_star(self, width, height, rotation,
                          rainbow_mode=False, skittles_mode=False):
        screen = [[(" ", 0, False)] * width for _ in range(height)]
        art    = DEATH_STAR_STATIC
        sh, sw = len(art), max((len(l) for l in art), default=0)
        if sh == 0 or sw == 0:
            return screen
        radius = max(1.0, min(width/2.5, height*2.0/2.5))
        scale  = (radius * 2 * 0.65) / sh
        th, tw = int(sh * scale), int(sw * scale)
        sy0    = (height - th) // 2
        sx0    = (width  - tw) // 2
        for ry in range(th):
            if sy0 + ry >= height:
                break
            src_y = int(ry / scale)
            if src_y >= sh:
                continue
            line = art[src_y]
            for rx in range(tw):
                if sx0 + rx >= width:
                    break
                src_x = int(rx / scale)
                ch    = line[src_x] if src_x < len(line) else " "
                if ch == " ":
                    continue
                fx, fy = sx0 + rx, sy0 + ry
                shaded = self.lighting
                cidx   = 0
                if rainbow_mode:
                    cidx = ((fx + fy) % 7) + 1
                elif skittles_mode:
                    h = (((fx*2654435761)^(fy*2246822519)^((fx^fy)*3266489917)) & 0xFFFFFFFF)
                    cidx = (h % 16) + 1
                screen[fy][fx] = (ch, cidx, shaded)
        return screen






    # ── Operator panel ────────────────────────
    def render_operator_panel(self, width, height):
        screen = [[(" ", 0, False)] * width for _ in range(height)]
        conns  = self.log_parser.get_connections()
        tcp = sum(1 for c in conns if getattr(c,"protocol","") == "TCP")
        udp = sum(1 for c in conns if getattr(c,"protocol","") == "UDP")
        threat_map = {"SAFE":0,"ISP":0,"CLOUD":0,"HOSTING":0,"LOCAL":0,"UNKNOWN":0}
        for c in conns:
            t = getattr(c, "threat", "UNKNOWN")
            threat_map[t] = threat_map.get(t, 0) + 1
        ip_cnt   = {}
        port_cnt = {}
        for c in conns:
            ip   = getattr(c,"ip","?");   ip_cnt[ip]     = ip_cnt.get(ip,0)     + 1
            port = getattr(c,"port","?"); port_cnt[port]  = port_cnt.get(port,0) + 1
        top_ips   = sorted(ip_cnt.items(),   key=lambda x:-x[1])[:5]
        top_ports = sorted(port_cnt.items(), key=lambda x:-x[1])[:5]
        scan_cnt  = sum(1 for c in conns if "SCAN" in getattr(c,"attack_type",""))
        lines = [
            "═"*59,
            "OPERATOR MODE - DETAILED VIEW".center(59),
            "═"*59, "",
            "CONNECTION STATISTICS:",
            f"  Total : {len(conns)}   TCP: {tcp}   UDP: {udp}",
            "", "THREAT LEVEL BREAKDOWN:",
        ]
        for k, v in threat_map.items():
            lines.append(f"  {k:<8s}: {v}")
        lines += ["", f"PORT SCAN ATTEMPTS: {scan_cnt}", "", "TOP 5 SOURCE IPs:"]
        lines += [f"  {ip:<18s} ({cnt:3d})" for ip, cnt in top_ips] or ["  (none)"]
        lines += ["", "TOP 5 TARGETED PORTS:"]
        for port, cnt in top_ports:
            svc = next((getattr(c,"service","?") for c in conns
                        if getattr(c,"port","") == port), "?")
            lines.append(f"  :{port:<5s}  {svc:<10s}  {cnt:3d}")
        lines += ["", "═"*59, "Press [O] to return to globe view"]
        start_y = max(0, (height - len(lines)) // 2)
        for i, line in enumerate(lines):
            y = start_y + i
            if y >= height: break
            x0 = max(0, (width - len(line)) // 2)
            for j, ch in enumerate(line):
                if x0 + j < width:
                    screen[y][x0+j] = (ch, 0, False)
        return screen






    # ── Net-scan panel ────────────────────────
    def render_netscan_panel(self, width, height):
        """Render the network scanner panel (opened with S key).
        Scan only executes after user presses S a second time while panel is open."""
        screen = [[(" ", 0, False)] * width for _ in range(height)]

        with self.netscan._lock:
            results = list(self.netscan.results)

        if self.netscan.scanning:
            status = "SCANNING..."
        elif self.netscan.scan_done:
            status = f"DONE — {len(results)} host(s) found"
        else:
            status = "READY  (press S to start scan)"

        lines = [
            "═"*59,
            "NET SCAN PANEL".center(59),
            "═"*59,
            f"  Range  : {self.netscan.scan_range or 'auto-detect local /24'}",
            f"  Status : {status}",
            "─"*59,
            f"  {'IP':<16} {'HOSTNAME':<22} {'OPEN PORTS'}",
            "─"*59,
        ]

        if not results:
            if self.netscan.scanning:
                lines.append("  Scanning... please wait (~5s)")
            else:
                lines.append("  No results yet.  Press S to execute scan.")
        else:
            for r in results[-min(len(results), height - 14):]:
                ports_str = ",".join(str(p) for p in r["ports"]) if r["ports"] else "none"
                host      = r["hostname"][:20] if r["hostname"] else ""
                lines.append(f"  {r['ip']:<16} {host:<22} {ports_str}")

        lines += [
            "─"*59,
            "  [S] Start/restart scan   [O] Operator   [Q] Quit",
            "═"*59,
        ]

        if HAS_NETSCAN:
            lines.insert(3, "  (modes.netscan module detected)")

        start_y = max(0, (height - len(lines)) // 2)
        for i, line in enumerate(lines):
            y = start_y + i
            if y >= height: break
            x0 = max(0, (width - len(line)) // 2)
            for j, ch in enumerate(line):
                if x0 + j < width:
                    screen[y][x0+j] = (ch, 0, False)
        return screen






    # ── Analysis helpers ──────────────────────
    def analyze_ip_type(self, ip):
        for prefix, type_, meaning, threat in [
            ("fe80:",  "IPv6 Link-Local",  "Device on local network",            "Safe"),
            ("ff02:",  "IPv6 Multicast",   "Broadcast to local devices",         "Safe"),
            ("::1",    "IPv6 Localhost",   "Your own computer (loopback)",       "Safe"),
            ("fc00:","IPv6 Unique Local",  "Private IPv6 (like 192.168.x.x)",   "Safe"),
            ("fd00:","IPv6 Unique Local",  "Private IPv6 (like 192.168.x.x)",   "Safe"),
            ("10.",  "IPv4 Private",       "Home/office network device",         "Safe"),
            ("192.168.","IPv4 Private",    "Home/office network device",         "Safe"),
            ("172.16.", "IPv4 Private",    "Home/office network device",         "Safe"),
            ("127.",    "IPv4 Localhost",  "Your own computer",                  "Safe"),
        ]:
            if ip.startswith(prefix):
                return {"type": type_, "meaning": meaning, "threat": threat}
        return {"type": "Public Internet IP",
                "meaning": "External device from the internet",
                "threat": "Depends on activity"}






    # ── Main render ───────────────────────────
    def render(self):
        globe_w = int(self.term.width * 0.65)
        globe_h = self.term.height - 2

        if self.globe is None or self.globe.width != globe_w or self.globe.height != globe_h:
            print(self.term.home + self.term.clear, end="", flush=True)
            self.globe = Globe(globe_w, globe_h)
            for lat, lon, lbl in self.test_locations:
                self.globe.add_attack(lat, lon, lbl)

        rotation = self.get_rotation()
        rainbow  = self.theme.get("rainbow",  False)
        skittles = self.theme.get("skittles", False)

        # Choose left-panel content
        if self.netscan_mode:
            globe_screen = self.render_netscan_panel(globe_w, globe_h)
        elif self.operator_mode:
            globe_screen = self.render_operator_panel(globe_w, globe_h)
        elif self.death_star_mode:
            globe_screen = self.render_death_star(globe_w, globe_h, rotation, rainbow, skittles)
        else:
            self.globe.lighting  = self.lighting
            self.globe.plus_mode = self.plus_mode
            globe_screen = self.globe.render(rotation, rainbow, skittles)

        out = ["\033[?25l", self.term.home]






        # ── Left panel border ─────────────────
        if self.netscan_mode:
            border_color = self.get_color("bright_cyan")
            title = " Net Scan "
        elif self.operator_mode:
            border_color = self.get_color("bright_red")
            title = " Operator Mode "
        elif self.death_star_mode:
            border_color = self.get_color(self.theme["globe"])
            title = " Death Star "
        else:
            border_color = self.get_color(self.theme["globe"])
            title = " Attack Globe "

        out.append(self.term.move(0, 0) +
                   border_color("┌" + title + "─"*(globe_w-len(title)-2) + "┐") + RESET)
        for y in range(1, globe_h+1):
            out.append(self.term.move(y, 0)           + border_color("│") + RESET)
            out.append(self.term.move(y, globe_w-1)   + border_color("│") + RESET)

        # ── Globe / panel content ─────────────
        gc     = self.get_color(self.theme["globe"])
        gc_dim = self.get_color(self.theme["globe"], dim=True)

        for y, row in enumerate(globe_screen):
            line = []
            for x in range(min(len(row), globe_w-2)):
                ch, cidx, shaded = row[x]
                if ch != " ":
                    if rainbow or skittles:
                        col = self.get_color("", cidx, dim=shaded)
                    elif shaded:
                        col = gc_dim
                    elif self.netscan_mode:
                        col = self.get_color("bright_cyan")
                    elif self.operator_mode:
                        col = self.get_color("bright_red")
                    else:
                        col = gc
                    line.append(col(ch))
                else:
                    line.append(" ")
            if line:
                out.append(self.term.move(y+1, 1) + "".join(line))

        out.append(self.term.move(globe_h+1, 0) +
                   border_color("└" + "─"*(globe_w-2) + "┘") + RESET)

        # ── Right panel: Live Feed ────────────
        feed_x = globe_w + 2
        feed_w = max(20, self.term.width - feed_x - 1)
        feed_h = self.term.height // 2 - 2
        fc     = self.get_color(self.theme["feed"])

        for y in range(1, feed_h):
            out.append(self.term.move(y, feed_x+1) + " "*(feed_w-2))

        out.append(self.term.move(0, feed_x) +
                   fc("┌ Live Feed " + "─"*(feed_w-13) + "┐") + RESET)
        out.append(self.term.move(feed_h, feed_x) +
                   fc("└" + "─"*(feed_w-2) + "┘") + RESET)
        for y in range(1, feed_h):
            out.append(self.term.move(y, feed_x)        + fc("│") + RESET)
            out.append(self.term.move(y, feed_x+feed_w-1) + fc("│") + RESET)

        hdr = f"{'TIME':<8} {'SRC IP':<13} {'DST IP':<13} {'PORT':<5} {'PROTO':<5} {'STATUS':<8} {'SVC':<7} {'CC':<3} {'THREAT':<7}"
        out.append(self.term.move(1, feed_x+1) + self.term.bright_yellow(hdr[:feed_w-3]))
        out.append(self.term.move(2, feed_x+1) + fc("─"*min(len(hdr), feed_w-3)))






        conns = self.log_parser.get_connections()[-10:]
        for i, conn in enumerate(conns):
            yp = 3 + i
            if yp >= feed_h - 1:
                break
            ts      = getattr(conn, "timestamp", "")
            tstr    = ts.split()[1][:8] if " " in ts else ts[:8]
            svc     = getattr(conn, "service", "?")[:7]
            cc      = getattr(conn, "country", "??")
            threat  = getattr(conn, "threat",  "UNKNOWN")
            action  = getattr(conn, "action",  "DROP")
            dst_ip  = getattr(conn, "dst_ip",  "?")
            src_d   = conn.ip[:13]
            dst_d   = dst_ip[:13]
            st_txt  = "BLOCKED" if action == "DROP" else ("ALLOWED" if action == "ALLOW" else action.upper())
            st_col  = self.term.red   if action == "DROP" else self.term.green
            th_col  = (self.term.green  if threat in ("SAFE","ISP")
                       else self.term.yellow if threat == "CLOUD"
                       else self.term.red    if threat == "HOSTING"
                       else self.term.white)
            base = f"{tstr:<8} {src_d:<13} {dst_d:<13} {conn.port:<5} {conn.protocol:<5} "
            stat = f"{st_txt:<8} "
            svc_ = f"{svc:<7} {cc:<3} "
            thr_ = f"{threat:<7}"
            full = (base + stat + svc_ + thr_)[:feed_w-3]
            b, s, v = len(base), len(stat), len(svc_)
            out.append(
                self.term.move(yp, feed_x+1) +
                self.term.cyan(full[:b]) +
                st_col(full[b:b+s]) +
                self.term.cyan(full[b+s:b+s+v]) +
                th_col(full[b+s+v:])
            )






        # ── Right panel: Stats ────────────────
        stats_y = feed_h + 1
        sc      = self.get_color(self.theme["stats"])

        for y in range(stats_y+1, self.term.height-1):
            out.append(self.term.move(y, feed_x+1) + " "*(feed_w-2))

        st_title = f" Stats - {self.theme['name'].upper()} "
        out.append(self.term.move(stats_y, feed_x) +
                   sc("┌" + st_title + "─"*max(0, feed_w-len(st_title)-2) + "┐") + RESET)
        for y in range(stats_y+1, self.term.height-1):
            out.append(self.term.move(y, feed_x)        + sc("│") + RESET)
            out.append(self.term.move(y, feed_x+feed_w-1) + sc("│") + RESET)
        out.append(self.term.move(self.term.height-1, feed_x) +
                   sc("└" + "─"*(feed_w-2) + "┘") + RESET)






        # System info
        sys_info = self.sys_info_cache or {}
        import socket, uuid
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
            mac = ":".join(f"{(uuid.getnode()>>(8*i))&0xff:02x}" for i in range(5,-1,-1))
        except Exception:
            local_ip = mac = "Unknown"
        
        
        
        user = os.environ.get("USERNAME", os.environ.get("USER","user"))
        sys_info["System IP"] = local_ip
        sys_info["MAC Addr"]  = mac

        keys = ["System IP","MAC Addr","OS","Kernel","Architecture","BIOS","Host",
                "Network","Terminal","Resolution","Motherboard","CPU","CPU Load",
                "CPU Temp","GPU","RAM","Disk","Uptime"]
        if sys_info.get("Battery"):
            keys.append("Battery")

        row = stats_y + 1
        uh  = f"{user}@{sys_info.get('Host','?')}"[:feed_w-3]
        out.append(self.term.move(row,   feed_x+1) + self.term.bright_cyan(uh))
        out.append(self.term.move(row+1, feed_x+1) + sc("─"*len(uh)))




        for i, key in enumerate(keys):
            if row+2+i >= self.term.height-3:
                break
            val  = sys_info.get(key, "N/A")
            maxv = max(3, feed_w - len(key) - 5)
            if len(val) > maxv:
                val = val[:maxv-3] + "..."
            out.append(self.term.move(row+2+i, feed_x+1) +
                       sc(f"{key}: ") + self.term.white(val))

        
        
        
        
        # Status bar
        st_txt2  = "PAUSED" if self.paused else "RUNNING"
        st_col2  = self.term.red if self.paused else self.term.green
        leg_note = " | C for legend"
        ver_txt  = f"v{VERSION}"
        pad      = feed_w - 3 - len(st_txt2) - len(leg_note) - len(ver_txt)
        out.append(self.term.move(self.term.height-2, feed_x+1) +
                   st_col2(st_txt2) + self.term.cyan(leg_note) +
                   (" "*max(0,pad)) + self.term.bright_black(ver_txt))

       
       
       
       
        # Legend bar inside globe
        leg_y = globe_h
        if self.show_legend:
            legend = "[Space]Pause [T]Theme [L]Light [P]Plus [D]DeathStar [O]Operator [S]NetScan [A]Details [C]Legend [Q]Quit"
            out.append(self.term.move(leg_y, 1) +
                       self.term.on_black + self.term.bright_yellow(legend.center(globe_w-2)) + RESET)
        else:
            out.append(self.term.move(leg_y, 1) + " "*(globe_w-2))

       
       
       
       
        # Attack detail overlay
        if self.show_attack_details:
            all_c = self.log_parser.get_connections()
            if all_c:
                latest   = all_c[-1]
                pw       = min(feed_w-4, 50)
                ph       = 14
                px, py   = feed_x+2, 2
                pc       = self.term.bright_cyan
                for cy2 in range(py, py+ph+2):
                    out.append(self.term.move(cy2, px) + self.term.on_black + " "*pw + RESET)
                out.append(self.term.move(py, px) +
                           self.term.on_black + pc("┌─ Attack Details " + "─"*(pw-19) + "┐") + RESET)
                details = [
                    f"IP: {latest.ip}",
                    f"Location: {getattr(latest,'city','?')}, {getattr(latest,'country_full','?')} ({getattr(latest,'country','??')})",
                    f"ISP: {getattr(latest,'isp','?')}",
                    "",
                    f"Port: {latest.port} ({getattr(latest,'service','?')})",
                    f"Protocol: {latest.protocol}",
                    f"Time: {getattr(latest,'timestamp','?')}",
                    "",
                    f"Threat: {getattr(latest,'threat','?')}",
                    f"Type: {getattr(latest,'attack_type','?')}",
                    f"Count: {getattr(latest,'count',1)}",
                    "",
                ]
                for di, dl in enumerate(details):
                    dl = dl[:pw-4]
                    padl = f" {dl:<{pw-4}} "
                    out.append(self.term.move(py+1+di, px) +
                               self.term.on_black + pc("│") + self.term.white(padl) + pc("│") + RESET)
                bot = py + len(details) + 1
                out.append(self.term.move(bot,   px) +
                           self.term.on_black + pc("└"+"─"*(pw-2)+"┘") + RESET)
                out.append(self.term.move(bot+1, px) +
                           self.term.on_black + self.term.bright_yellow(" Press [A] to close ".center(pw)) + RESET)

        out.append(self.term.move(self.term.height-1, self.term.width-1))
        out.append("\033[?25l")
        sys.stdout.write("".join(out))
        sys.stdout.flush()

    
    
    
    
    
    # ── Background threads ────────────────────
    def update_system_info(self):
        while self.running:
            try:
                self.sys_info_cache, self.sys_info_os = get_system_info()
            except Exception:
                pass
            time.sleep(self.sys_info_interval)

    
    
    
    
    def handle_input(self):
        with self.term.cbreak():
            while self.running:
                key = self.term.inkey(timeout=0.05)
                if not key:
                    continue
                k = key.lower()

                if k in ("q", "x") or key.code == self.term.KEY_ESCAPE:
                    self.running = False

                elif key == " ":
                    if self.paused:
                        self.start_time = time.time() - \
                            (self.pause_rotation / (-2*math.pi)) * self.rotation_period
                    else:
                        self.pause_rotation = self.get_rotation()
                    self.paused = not self.paused

                elif k == "t":
                    self.cycle_theme()
                elif k == "l":
                    self.lighting  = not self.lighting
                elif k == "p":
                    self.plus_mode = not self.plus_mode
                elif k == "c":
                    self.show_legend = not self.show_legend
                elif k == "d":
                    self.death_star_mode = not self.death_star_mode
                elif k == "a":
                    self.show_attack_details = not self.show_attack_details

                elif k == "o":
                    self.operator_mode  = not self.operator_mode
                    if self.operator_mode:
                        self.netscan_mode = False   # exclusive

                elif k == "s":
                    if not self.netscan_mode:
                        # First S press: open the panel, do NOT start scan yet
                        self.netscan_mode  = True
                        self.operator_mode = False  # exclusive
                    else:
                        # Panel already open — second S press starts (or restarts) scan
                        if not self.netscan.scanning:
                            if self.netscan.scan_done:
                                # Restart: clear previous results
                                with self.netscan._lock:
                                    self.netscan.results.clear()
                                self.netscan.scan_done = False
                            self.netscan.start_scan()
                        # If already scanning, ignore additional presses






    # ── Main run loop ─────────────────────────
    def run(self):
        if self.use_real_logs:
            self.log_parser.start()

        
        
        
        # Initial system info
        try:
            self.sys_info_cache, self.sys_info_os = get_system_info()
        except Exception:
            pass

        threading.Thread(target=self.handle_input,       daemon=True).start()
        threading.Thread(target=self.update_system_info, daemon=True).start()

        print("\033[?25l", end="", flush=True)
        print("\033[2J\033[H", end="", flush=True)

        
        
        
        
        with self.term.fullscreen(), self.term.hidden_cursor():
            try:
                while self.running:
                    t0 = time.time()
                    self.render()
                    sleep = max(0, 0.050 - (time.time() - t0))
                    if sleep:
                        time.sleep(sleep)
            except KeyboardInterrupt:
                pass
            finally:
                self.running = False
                print("\033[?25h", end="", flush=True)


# ─────────────────────────────────────────────
# Boot animation
# ─────────────────────────────────────────────
def boot_animation():
    import random
    logo = r"""
        █████████    █████████   █████  █████ ███████████      ███████    ██████   █████
       ███░░░░░███  ███░░░░░███ ░░███  ░░███ ░░███░░░░░███   ███░░░░░███ ░░██████ ░░███
      ░███    ░░░  ░███    ░███  ░███   ░███  ░███    ░███  ███     ░░███ ░███░███ ░███
      ░░█████████  ░███████████  ░███   ░███  ░██████████  ░███      ░███ ░███░░███░███
       ░░░░░░░░███ ░███░░░░░███  ░███   ░███  ░███░░░░░███ ░███      ░███ ░███ ░░██████
       ███    ░███ ░███    ░███  ░███   ░███  ░███    ░███ ░░███     ███  ░███  ░░█████
       ░█████████  █████   █████ ░░████████   █████   █████ ░░░███████░   █████  ░░█████
        ░░░░░░░░░  ░░░░░   ░░░░░   ░░░░░░░░   ░░░░░   ░░░░░    ░░░░░░░    ░░░░░    ░░░░░

                      . . .. .      .  .          .         .   ....
                      .   ..    .       .   .    .     .  .       .  
                          .   .  .     .  .          .  .     .   ....
                           .      .  .   .  .     .             .  . .    
                                  ...:-=++****+=--:...               
                       .  .  ..=%%@@@@@@@@%%%@@%@@@@%#-.   ..   .   
                           .-#@@%%%##%%%%######%%%%%%%%@@@*:..      .
                         :#@%%#########*+--=++++***########%@*.      
                      .-%@%%%#######*+++=+*###**+=+++********#@#:.   
                    ..%@%###*##****+==+##*#=*%###*+====+*#####%%@#.  
                    .=@@%%%####*+*++==+*##%+++#%##**+=++*******%%@@@=.
                   +@@%%%###****++=-+*####+**#%%##*+++*******##%%%%@=
                   @@%######*+**++=-*##%%%+##*%####*++********###%%@@
                   @%%#*******+++==-+#%#%%*###%%%##*++**##*##*###%@@#
                   :%@%###*##***++===*##%%*#*#%%##*+++++****###%%@@#.
                   ..#@@%%%####**+++=+##%%%++%####*++*#***##%#%%@@#. 
                    .:#@%%%##%##****++*###%###*+**########%@@@@%-.  
                     . .:%@%#%%%%%#####**+++=++*###%%##%%%%%@@%:.    
                         ..=%@@%%@%%%%%%%%%%%%%%%%%%%%%%%@@%+:.    . 
                     .  .   .-#%@@@@@@%%@@@%@@%%@@@@@@%#=..         
                               ...:-+*#@@@@@@@@@@%*+-:...  .         
                                          .  .        .            . 
                      .   .    .    . .                   .   .     
                     .   .        . ..     .       .      .    .     
                               .    .                             .     
                     .  .                         .   .     . .    .

    """
    lines = logo.strip().split("\n")




    def _check_skip():
        if sys.platform == "win32":
            import msvcrt
            if msvcrt.kbhit():
                return msvcrt.getch() in (b"\r", b"\n")
        else:
            if select.select([sys.stdin], [], [], 0)[0]:
                return sys.stdin.read(1) in ("\r", "\n")
        return False

    for pct in (0.15, 0.30, 0.50, 0.70, 0.85, 1.0):
        print("\033[2J\033[H\033[31m")
        for ln in lines:
            print("".join(c if (c == " " or random.random() < pct) else " " for c in ln))
        if _check_skip():
            break
        time.sleep(0.4 if pct < 1.0 else 0)

    print("\033[2J\033[H\033[31m")
    print(logo)
    print("\033[0m\033[90m")
    print("Created by kizzycpt".center(96))
    print("\033[0m")
    time.sleep(1.5)






# ─────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Sauron - Network Attack Monitor Dashboard")
    parser.add_argument("--theme", choices=list(Dashboard.THEMES), default="matrix")
    parser.add_argument("--rotation", type=int, default=50,
                        help="Globe rotation period in seconds (default: 50)")
    parser.add_argument("--log-path", type=str, default=None,
                        help="Custom firewall log path (auto-detected if omitted)")
    args = parser.parse_args()

    boot_animation()

    dashboard = Dashboard(rotation_period=args.rotation, theme=args.theme,
                          log_path=args.log_path)

    
    
    
    # If no real logs found, warn user and ask how to proceed
    if not dashboard.use_real_logs:
        print("\033[2J\033[H\033[31m")
        lp = dashboard.log_parser.log_path
        
        
        if os.path.exists(lp):
            st  = os.stat(lp)
            age = int((time.time() - st.st_mtime) / 60)
            print(f"✗ Firewall log INACTIVE: {lp}")
            print(f"  Last updated {age} min ago  |  Size: {st.st_size} bytes")
        else:
            print(f"✗ Firewall log not found: {lp}")
        print("\033[33m")
        
        
        if sys.platform == "win32":
            print("  Enable via: Win+R → wf.msc → Properties → Logging → Log dropped packets = YES")
        else:
            print("  Enable UFW logging: sudo ufw logging on")
        print("\n\033[36m  Dashboard will run with no live data until logging is enabled.\033[0m\n")
        
        
        try:
            choice = input("\033[33m[1] Continue anyway  [2] Exit: \033[0m").strip()
            if choice == "2":
                sys.exit(0)
        except (KeyboardInterrupt, EOFError):
            sys.exit(0)

    try:
        dashboard.run()
    finally:
        print("\033[?25h", end="", flush=True)


if __name__ == "__main__":
    main()