import os
import sys
import csv
import time
import json
import threading
import subprocess
import urllib.request
import urllib.error
from datetime import datetime
from collections import deque
from pathlib import Path


class IPIntelligence:
    """IP geolocation and threat intelligence with TTL-based caching."""

    _PRIVATE_PREFIXES  = ("10.", "192.168.", "172.16.", "127.", "localhost",
                          "fe80:", "::1", "fc00:", "fd00:")
    _CLOUD_PROVIDERS   = ["amazon", "aws", "google cloud", "azure", "digitalocean", "ovh", "hetzner"]
    _HOSTING_KEYWORDS  = ["hosting", "server", "datacenter", "vps", "dedicated"]
    _ISP_KEYWORDS      = ["telecom", "comcast", "verizon", "att", "broadband", "cable"]

    def __init__(self):
        self.cache:     dict = {}
        self.cache_ttl: int  = 3600

    def get_geolocation(self, ip: str) -> dict:
        if ip in self.cache:
            entry = self.cache[ip]
            if time.time() - entry.get("timestamp", 0) < self.cache_ttl:
                return entry["geo"]

        if ip.startswith(self._PRIVATE_PREFIXES):
            return self._cache_and_return(ip, {
                "country": "LOCAL", "countryCode": "LO",
                "city": "Private Network", "isp": "Local Network", "threat": "SAFE",
            })

        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,org,as"
            req = urllib.request.Request(url, headers={"User-Agent": "SAURON/1.7"})
            with urllib.request.urlopen(req, timeout=2) as resp:
                data = json.loads(resp.read().decode())

            if data.get("status") == "success":
                return self._cache_and_return(ip, {
                    "country":     data.get("country",     "Unknown"),
                    "countryCode": data.get("countryCode", "??"),
                    "city":        data.get("city",        "Unknown"),
                    "isp":         data.get("isp",         "Unknown"),
                    "org":         data.get("org",         ""),
                    "as":          data.get("as",          ""),
                    "threat":      self._assess_threat(data),
                })
        except (urllib.error.URLError, urllib.error.HTTPError,
                TimeoutError, json.JSONDecodeError):
            pass

        return {"country": "Unknown", "countryCode": "??",
                "city": "Unknown", "isp": "Unknown", "threat": "UNKNOWN"}

    def _cache_and_return(self, ip: str, geo: dict) -> dict:
        self.cache[ip] = {"geo": geo, "timestamp": time.time()}
        return geo

    def _assess_threat(self, geo_data: dict) -> str:
        org = geo_data.get("org", "").lower()
        isp = geo_data.get("isp", "").lower()
        if any(x in org or x in isp for x in self._CLOUD_PROVIDERS):
            return "CLOUD"
        if any(x in org or x in isp for x in self._HOSTING_KEYWORDS):
            return "HOSTING"
        if any(x in isp for x in self._ISP_KEYWORDS):
            return "ISP"
        return "UNKNOWN"


class FirewallLogParser:
    """Parse firewall logs and detect port scans."""

    def __init__(self, log_path=None, demo_mode=False, enable_logging=True):
        self.platform       = sys.platform
        self.log_path       = log_path or self._get_default_log_path()
        self.ip_tracking    = {}
        self.scan_threshold = 5
        self.time_window    = 60
        self.running        = False
        self.connections    = deque(maxlen=20)
        self.demo_mode      = demo_mode
        self.ip_intel       = IPIntelligence()
        self.enable_logging = enable_logging
        self.log_dir        = Path("logs")
        self.csv_lock       = threading.Lock()

        if self.enable_logging:
            self._setup_logging()


    # ── CSV logging ───────────────────────────────────────────────────────────

    def _setup_logging(self):
        try:
            self.log_dir.mkdir(exist_ok=True)
            today                 = datetime.now().strftime("%Y-%m-%d")
            self.current_log_file = self.log_dir / f"attacks_{today}.csv"

            if not self.current_log_file.exists():
                with open(self.current_log_file, 'w', newline='', encoding='utf-8') as f:
                    csv.writer(f).writerow([
                        'Timestamp', 'Source_IP', 'Dest_IP', 'Port', 'Protocol',
                        'Service', 'Country', 'City', 'ISP', 'Threat_Level',
                        'Attack_Type', 'Action',
                    ])
        except Exception as e:
            print(f"Warning: Could not setup logging: {e}")
            self.enable_logging = False

    def _log_attack(self, conn):
        if not self.enable_logging:
            return
        try:
            today         = datetime.now().strftime("%Y-%m-%d")
            expected_file = self.log_dir / f"attacks_{today}.csv"
            if expected_file != self.current_log_file:
                self._setup_logging()

            with self.csv_lock:
                with open(self.current_log_file, 'a', newline='', encoding='utf-8') as f:
                    csv.writer(f).writerow([
                        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        getattr(conn, 'ip',          'Unknown'),
                        getattr(conn, 'dst_ip',      'Unknown'),
                        getattr(conn, 'port',        'Unknown'),
                        getattr(conn, 'protocol',    'Unknown'),
                        getattr(conn, 'service',     'Unknown'),
                        getattr(conn, 'country',     '??'),
                        getattr(conn, 'city',        'Unknown'),
                        getattr(conn, 'isp',         'Unknown'),
                        getattr(conn, 'threat',      'UNKNOWN'),
                        getattr(conn, 'attack_type', 'PROBE'),
                        getattr(conn, 'action',      'DROP'),
                    ])
        except Exception:
            pass


    # ── Platform log path ─────────────────────────────────────────────────────

    def _get_default_log_path(self):
        if self.platform == 'win32':
            return r"C:\Windows\System32\LogFiles\Firewall\pfirewall.log"

        for candidate in ("/var/log/syslog", "/var/log/ufw.log",
                          "/var/log/kern.log", "/var/log/messages"):
            if os.path.exists(candidate) and os.access(candidate, os.R_OK):
                return candidate
        return "journalctl"


    # ── Log line parsers ──────────────────────────────────────────────────────

    def parse_windows_log_line(self, line):
        if line.startswith('#') or not line.strip():
            return None
        try:
            parts = line.split()
            if len(parts) < 8:
                return None
            return {
                'timestamp': f"{parts[0]} {parts[1]}",
                'action':    parts[2],
                'protocol':  parts[3],
                'src_ip':    parts[4],
                'dst_ip':    parts[5],
                'src_port':  parts[6],
                'dst_port':  parts[7],
            }
        except Exception:
            return None

    def parse_linux_log_line(self, line):
        """Parse Linux UFW/iptables syslog lines (UFW BLOCK only)."""
        try:
            if 'UFW' not in line or 'BLOCK' not in line:
                return None

            entry  = {'action': 'DROP'}
            fields = {
                'SRC':   ('src_ip',   True),
                'DST':   ('dst_ip',   False),
                'PROTO': ('protocol', False),
                'DPT':   ('dst_port', False),
            }

            for key, (attr, required) in fields.items():
                tag = f"{key}="
                if tag in line:
                    start       = line.index(tag) + len(tag)
                    end         = line.find(' ', start)
                    entry[attr] = line[start: end if end != -1 else None].strip()
                elif required:
                    return None
                elif attr == 'dst_port':
                    entry['dst_port'] = entry.get('protocol', 'UNKNOWN')
                else:
                    entry[attr] = 'Unknown' if attr == 'dst_ip' else 'UNKNOWN'

            parts = line.split()
            ts    = ""
            for i, p in enumerate(parts):
                if len(p) == 8 and p[2] == ':' and p[5] == ':':
                    month = parts[i-2] if i >= 2 else ""
                    day   = parts[i-1] if i >= 1 else ""
                    ts    = f"{month} {day} {p}"
                    break
            entry['timestamp'] = ts or " ".join(parts[:3])
            return entry
        except Exception:
            return None


    # ── Scan detection ────────────────────────────────────────────────────────

    def detect_scan(self, src_ip):
        now = time.time()
        if src_ip in self.ip_tracking:
            self.ip_tracking[src_ip] = [
                (port, ts) for port, ts in self.ip_tracking[src_ip]
                if now - ts < self.time_window
            ]
            unique_ports = {port for port, _ in self.ip_tracking[src_ip]}
            if len(unique_ports) >= self.scan_threshold:
                return True, list(unique_ports)
        return False, []


    # ── Entry processing ──────────────────────────────────────────────────────

    def add_entry(self, entry):
        if not entry or entry.get('action') != 'DROP':
            return

        src_ip   = entry['src_ip']
        dst_port = entry['dst_port']

        self.ip_tracking.setdefault(src_ip, []).append((dst_port, time.time()))
        is_scan, ports = self.detect_scan(src_ip)

        Connection     = type('Connection', (), {})
        conn           = Connection()
        conn.ip        = src_ip
        conn.dst_ip    = entry.get('dst_ip',    'Unknown')
        conn.port      = dst_port
        conn.protocol  = entry.get('protocol',  'TCP')
        conn.timestamp = entry.get('timestamp', '')
        conn.action    = entry.get('action',    'DROP')
        conn.count     = sum(1 for c in self.connections
                             if getattr(c, 'ip', None) == src_ip) + 1

        port_names = {
            '22': 'SSH',     '80': 'HTTP',    '443': 'HTTPS',    '21': 'FTP',
            '23': 'Telnet',  '25': 'SMTP',    '3306': 'MySQL',   '3389': 'RDP',
            '445': 'SMB',    '1433': 'MSSQL', '5900': 'VNC',     '8080': 'HTTP-ALT',
            '137': 'NetBIOS','138': 'NetBIOS','139': 'NetBIOS',
        }
        conn.service      = port_names.get(dst_port, f'Port {dst_port}')
        conn.attack_type  = f"SCAN ({len(ports)}p)" if is_scan else "PROBE"

        geo               = self.ip_intel.get_geolocation(src_ip)
        conn.country      = geo.get('countryCode', '??')
        conn.country_full = geo.get('country',     'Unknown')
        conn.city         = geo.get('city',        'Unknown')
        conn.isp          = geo.get('isp',         'Unknown')
        conn.threat       = geo.get('threat',      'UNKNOWN')

        self.connections.append(conn)
        self._log_attack(conn)


    # ── Log tailing ───────────────────────────────────────────────────────────

    def tail_file(self):
        try:
            if self.log_path == "journalctl":
                self._tail_journalctl()
                return

            if not os.path.exists(self.log_path):
                return

            with open(self.log_path, 'r', encoding='utf-8', errors='ignore') as f:
                f.seek(0, 2)
                while self.running:
                    line = f.readline()
                    if line:
                        entry = self.parse_linux_log_line(line)
                        if entry:
                            self.add_entry(entry)
                    else:
                        time.sleep(0.01)
        except Exception:
            pass

    def _tail_journalctl(self):
        """Stream UFW BLOCK entries from systemd journal, replaying last 200 lines on start."""
        cmd = ["journalctl", "-k", "-f", "--no-pager", "-n", "200", "-o", "short"]
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, text=True, bufsize=1)
            while self.running:
                line = proc.stdout.readline()
                if not line:
                    time.sleep(0.05)
                    continue
                if 'UFW' in line and 'BLOCK' in line:
                    entry = self.parse_linux_log_line(line)
                    if entry:
                        self.add_entry(entry)
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
        except FileNotFoundError:
            pass
        except Exception:
            pass


    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self):
        self.running = True
        if self.demo_mode:
            target = (self.generate_screenshot_demo_traffic
                      if '--demo-screenshot' in sys.argv
                      else self.generate_demo_traffic)
            if target != self.generate_screenshot_demo_traffic:
                threading.Thread(target=target, daemon=True).start()
            else:
                target()
        else:
            threading.Thread(target=self.tail_file, daemon=True).start()

    def stop(self):
        self.running = False

    def get_connections(self):
        return list(self.connections)