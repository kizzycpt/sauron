import os
import sys
import math
import time
import socket
import threading
import subprocess
import uuid
from pathlib import Path

from blessed import Terminal

from frontend.globe                 import Globe
from frontend.icons                 import DEATH_STAR_STATIC
from variables.nodeinfo.firewall    import FirewallLogParser
from variables.nodeinfo.system_info import get_system_info
from modes.netscan                  import net_scan_panel
from modes.IDS                      import ids_panel
from variables.poisons.ARP          import arp_p, arp_poison
from frontend.constants             import VERSION, RESET, rgb, rgb_bg

class Dashboard:
    THEMES = {
        "matrix":   {"name": "Matrix",   "globe": "bright_green",   "feed": "bright_yellow", "stats": "bright_cyan"},
        "amber":    {"name": "Amber",    "globe": "bright_red",     "feed": "bright_red",    "stats": "red"},
        "nord":     {"name": "Nord",     "globe": "bright_cyan",    "feed": "bright_blue",   "stats": "bright_cyan"},
        "dracula":  {"name": "Dracula",  "globe": "bright_magenta", "feed": "bright_magenta","stats": "magenta"},
        "mono":     {"name": "Mono",     "globe": "bright_white",   "feed": "bright_white",  "stats": "white"},
        "rainbow":  {"name": "Rainbow",  "globe": "bright_green",   "feed": "bright_magenta","stats": "bright_cyan",    "rainbow":  True},
        "skittles": {"name": "Skittles", "globe": "bright_green",   "feed": "bright_yellow", "stats": "bright_magenta", "skittles": True},
    }

    _RGB = {
        "bright_green":   (0,   255, 65),  "green":          (0,   150, 40),
        "bright_yellow":  (255, 255, 0),   "yellow":         (255, 176, 0),
        "bright_cyan":    (0,   255, 255), "cyan":           (0,   191, 255),
        "bright_magenta": (255, 0,   255), "magenta":        (255, 0,   255),
        "bright_blue":    (100, 149, 237), "blue":           (0,   0,   255),
        "bright_white":   (255, 255, 255), "white":          (200, 200, 200),
        "bright_red":     (255, 0,   0),   "red":            (255, 0,   0),
        "orange":         (255, 165, 0),   "purple":         (138, 43,  226),
    }

    _RAINBOW  = [(255,0,0), (255,127,0), (255,255,0), (0,255,0), (0,191,255), (138,43,226), (255,0,255)]

    _SKITTLES = [
        (255,0,0),   (255,69,0),   (255,127,0), (255,165,0),
        (255,215,0), (255,255,0),  (173,255,47),(0,255,0),
        (0,255,127), (0,206,209),  (0,191,255), (0,0,255),
        (138,43,226),(148,0,211),  (255,0,255), (255,20,147),
    ]

    def __init__(self, rotation_period=50, theme="matrix", log_path=None):
        self.term                = Terminal()
        self.rotation_period     = rotation_period
        self.start_time          = time.time()
        self.theme_names         = list(self.THEMES)
        tidx                     = self.theme_names.index(theme) if theme in self.THEMES else 0
        self.current_theme_index = tidx
        self.theme               = self.THEMES[self.theme_names[tidx]]

        # UI state
        self.paused                 = False
        self.pause_rotation         = 0.0
        self.show_legend            = False
        self.lighting               = False
        self.plus_mode              = False
        self.death_star_mode        = False
        self.show_attack_details    = False
        self.operator_mode          = False
        self.netscan_mode           = False
        self.netscan_panel_open     = False
        self.ids_mode               = False
        self.arp_posion_mode        = False
        self.ids_panel_open         = False
        self.running                = True
        self.globe                  = None
        self.ids_panel_state        = 0
        self.arp_poison_panel_state = 0

        # System info cache
        self.sys_info_cache    = None
        self.sys_info_os       = None
        self.sys_info_last_upd = 0
        self.sys_info_interval = 2.0

        # Firewall parser
        self.log_parser    = FirewallLogParser(log_path)
        self.use_real_logs = self._verify_firewall_logging_active()

        # Test locations
        self.test_locations = [
            (40.7128,  -74.0060, "NYC"),
            (51.5074,   -0.1278, "LON"),
            (35.6762,  139.6503, "TYO"),
            (-33.8688, 151.2093, "SYD"),
        ]

        # Panel references
        self.netscan                     = net_scan_panel
        self.ids_panel                   = ids_panel
        self.arp_poison_panel            = arp_p
        self.arp_poison_mode             = arp_poison
        self.ids_panel.stop_requested    = False
        self.ids_panel.scanning          = False
        self.ids_mode                    = False
        self.arp_poison_panel.active     = False
        self.arp_poison_panel.inactive   = False


    # ── Firewall log verification ─────────────────────────────────────────────

    def _verify_firewall_logging_active(self):
        path = self.log_parser.log_path

        if path == "journalctl":
            try:
                r = subprocess.run(["journalctl", "-k", "-n", "1", "--no-pager"],
                                   capture_output=True, timeout=3)
                return r.returncode == 0
            except Exception:
                return False

        path = Path(path)
        if not path.exists():
            return False

        try:
            st  = path.stat()
            age = time.time() - st.st_mtime

            if st.st_size == 0:
                return False
            if age < 604800:
                return True

            for ln in path.read_text(encoding="utf-8", errors="ignore").splitlines()[:50]:
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


    # ── Theme helpers ─────────────────────────────────────────────────────────

    def cycle_theme(self):
        self.current_theme_index = (self.current_theme_index + 1) % len(self.theme_names)
        self.theme = self.THEMES[self.theme_names[self.current_theme_index]]

    def get_rotation(self):
        if self.paused:
            return self.pause_rotation
        return -(time.time() - self.start_time) / self.rotation_period * 2 * math.pi

    def get_color(self, color_name, color_idx=0, dim=False):
        if color_idx > 0:
            palette = self._SKITTLES if self.theme.get("skittles") else self._RAINBOW
            r, g, b = palette[(color_idx - 1) % len(palette)]
        else:
            r, g, b = self._RGB.get(color_name, (255, 255, 255))

        if dim:
            r, g, b = int(r * .6), int(g * .6), int(b * .6)

        code = rgb(r, g, b)
        return lambda text: code + str(text) + RESET


    # ── Death Star renderer ───────────────────────────────────────────────────

    def render_death_star(self, width, height, rotation, rainbow_mode=False, skittles_mode=False):
        screen = [[(" ", 0, False)] * width for _ in range(height)]
        art    = DEATH_STAR_STATIC
        sh, sw = len(art), max((len(l) for l in art), default=0)

        if not sh or not sw:
            return screen

        radius = max(1.0, min(width / 2.5, height * 2.0 / 2.5))
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
                cidx   = 0
                if rainbow_mode:
                    cidx = ((fx + fy) % 7) + 1
                elif skittles_mode:
                    h    = (((fx*2654435761) ^ (fy*2246822519) ^ ((fx^fy)*3266489917)) & 0xFFFFFFFF)
                    cidx = (h % 16) + 1

                screen[fy][fx] = (ch, cidx, self.lighting)

        return screen


    # ── Operator panel ────────────────────────────────────────────────────────

    def render_operator_panel(self, width, height):
        screen = [[(" ", 0, False)] * width for _ in range(height)]
        conns  = self.log_parser.get_connections()
        tcp    = sum(1 for c in conns if getattr(c, "protocol", "") == "TCP")
        udp    = sum(1 for c in conns if getattr(c, "protocol", "") == "UDP")

        threat_map = {"SAFE": 0, "ISP": 0, "CLOUD": 0, "HOSTING": 0, "LOCAL": 0, "UNKNOWN": 0}
        for c in conns:
            t = getattr(c, "threat", "UNKNOWN")
            threat_map[t] = threat_map.get(t, 0) + 1

        ip_cnt, port_cnt = {}, {}
        for c in conns:
            ip   = getattr(c, "ip",   "?")
            port = getattr(c, "port", "?")
            ip_cnt[ip]     = ip_cnt.get(ip,     0) + 1
            port_cnt[port] = port_cnt.get(port, 0) + 1

        top_ips   = sorted(ip_cnt.items(),   key=lambda x: -x[1])[:5]
        top_ports = sorted(port_cnt.items(), key=lambda x: -x[1])[:5]
        scan_cnt  = sum(1 for c in conns if "SCAN" in getattr(c, "attack_type", ""))

        lines = [
            "═" * 59,
            "OPERATOR MODE - DETAILED VIEW".center(59),
            "═" * 59, "",
            "CONNECTION STATISTICS:",
            f"  Total : {len(conns)}   TCP: {tcp}   UDP: {udp}",
            "", "THREAT LEVEL BREAKDOWN:",
            *[f"  {k:<8s}: {v}" for k, v in threat_map.items()],
            "", f"PORT SCAN ATTEMPTS: {scan_cnt}", "", "TOP 5 SOURCE IPs:",
            *([f"  {ip:<18s} ({cnt:3d})" for ip, cnt in top_ips] or ["  (none)"]),
            "", "TOP 5 TARGETED PORTS:",
        ]

        for port, cnt in top_ports:
            svc = next((getattr(c, "service", "?") for c in conns
                        if getattr(c, "port", "") == port), "?")
            lines.append(f"  :{port:<5s}  {svc:<10s}  {cnt:3d}")

        lines += ["", "═" * 59, "Press [O] to return to globe view"]
        start_y = max(0, (height - len(lines)) // 2)

        for i, line in enumerate(lines):
            y = start_y + i
            if y >= height:
                break
            x0 = max(0, (width - len(line)) // 2)
            for j, ch in enumerate(line):
                if x0 + j < width:
                    screen[y][x0+j] = (ch, 0, False)

        return screen


    # ── Net-scan panel ────────────────────────────────────────────────────────

    def render_netscan_panel(self, width, height):
        screen = [[(" ", 0, False)] * width for _ in range(height)]

        with self.netscan._lock:
            results = list(self.netscan.results)

        if self.netscan.scanning:
            status = "SCANNING..."
        elif self.netscan.scan_done:
            status = f"DONE — {len(results)} host(s) found"
        else:
            status = "READY  (press S to start scan)"

        inner_w = width - 4
        pad     = lambda text: text[:inner_w].ljust(inner_w)
        sep     = "═" * inner_w
        dash    = "─" * inner_w

        lines = [
            sep,
            "NET SCAN PANEL".center(inner_w),
            sep,
            pad(f"  Range  : {self.netscan.scan_range or 'auto-detect local /24'}"),
            pad(f"  Status : {status}"),
            dash,
            pad(f"  {'IP':<16} {'HOSTNAME':<22} {'OPEN PORTS'}"),
            dash,
        ]

        # HAS_NETSCAN is resolved at the sauron.py level and injected via import
        try:
            from modes.netscan import scan_mode
            lines.insert(3, pad("  (modes.netscan module detected)"))
        except ImportError:
            pass

        max_result_rows = height - len(lines) - 5

        if not results:
            lines.append(pad("  Scanning... please wait (~5s)" if self.netscan.scanning
                             else "  No results yet.  Press S to execute scan."))
        else:
            for r in results[-max(1, max_result_rows):]:
                ports_str = ",".join(str(p) for p in r["ports"]) if r["ports"] else "none"
                host      = r["hostname"][:20] if r["hostname"] else ""
                lines.append(pad(f"  {r['ip']:<16} {host:<22} {ports_str}"))

        lines += [dash, pad("  [S] Start/restart scan   [O] Operator   [Q] Quit"), sep]

        start_y = max(0, (height - len(lines)) // 2)
        for i, line in enumerate(lines):
            y = start_y + i
            if y >= height:
                break
            for j, ch in enumerate(line):
                if 2 + j < width - 2:
                    screen[y][2 + j] = (ch, 0, False)

        return screen


    # ── IDS panel ─────────────────────────────────────────────────────────────

    def render_ids_panel(self, width, height):
        screen = [[(" ", 0, False)] * width for _ in range(height)]

        if self.ids_panel.scanning:
            status = "MONITORING NETWORK... (press I to stop)"
        elif self.ids_panel.scan_complete:
            status = "IDS TERMINATED. (press I to close panel)"
        else:
            status = "IDS ON STANDBY (press I to start scan)"

        inner_w = width - 4
        pad     = lambda text: text[:inner_w].ljust(inner_w)
        sep     = "═" * inner_w
        dash    = "─" * inner_w

        lines = [
            sep,
            "Intrusion Detection System".center(inner_w),
            sep,
            pad(f"  Subnet  : {self.ids_panel.subnet or 'auto-detect'}"),
            pad(f"  Status  : {status}"),
            pad(f"  Devices : {len(self.ids_panel.current_devices)}"),
            pad(f"  Alerts  : {len(self.ids_panel.alerts) if hasattr(self.ids_panel, 'alerts') else 0}"),
            dash,
        ]

        try:
            from modes.IDS import ids_loop
            lines.insert(3, pad("  (modes.IDS module detected)"))
        except ImportError:
            pass

        alerts         = self.ids_panel.alerts if hasattr(self.ids_panel, "alerts") else []
        max_alert_rows = height - len(lines) - 5

        if alerts:
            for a in alerts[-max(1, max_alert_rows):]:
                lines.append(pad(f"  {a.split(chr(10))[0]}"))
        else:
            lines.append(pad("  Scanning... waiting for results." if self.ids_panel.scanning
                             else "  No alerts yet."))

        lines += [dash, pad("  [I] Start/Stop      [O] Operator    [Q] Quit"), sep]

        start_y = max(0, (height - len(lines)) // 2)
        for i, line in enumerate(lines):
            y = start_y + i
            if y >= height:
                break
            for j, ch in enumerate(line):
                if 2 + j < width - 2:
                    screen[y][2 + j] = (ch, 0, False)

        return screen


    # ── ARP Poison panel ──────────────────────────────────────────────────────

    def render_arp_poison_panel(self, width, height):
        screen = [[(" ", 0, False)] * width for _ in range(height)]

        if self.arp_poison_panel.active:
            status = "POISONING ARP CACHE.... (Press X to disengage)"
        elif self.arp_poison_panel.inactive:
            status = "POISON ATTACK DISENGAGED. (Press X to close panel)"
        else:
            status = "POISON PAYLOAD ARMED (Press X to Activate)"

        # Fix: use self.arp_poison_panel.target_ip consistently
        selected = getattr(self.arp_poison_panel, "target_ip", None) or "None selected"

        pad  = lambda text: text[:width].ljust(width)
        sep  = "═" * width
        dash = "─" * width

        lines = [
            sep,
            "ARP Cache Poison".center(width),
            sep,
            pad(f"  Router   : {self.arp_poison_panel.router_ip or 'auto-detect'}"),
            pad(f"  Status   : {status}"),
            pad(f"  Target   : {selected}"),
            dash,
        ]

        try:
            from variables.poisons.ARP import arp_poison as _
            lines.insert(3, pad("[!]ARP Cache Payload Detected[!]"))
        except ImportError:
            pass

        response       = getattr(self.arp_poison_panel, "response", [])
        if isinstance(response, dict):
            response = list(response.values())
        max_alert_rows = height - len(lines) - 5

        if response:
            for a in response[-max(1, max_alert_rows):]:
                lines.append(pad(f"  {str(a).split(chr(10))[0]}"))
        else:
            lines.append(pad("  Deploying Payload... Please Wait (5s)" if self.arp_poison_panel.active
                             else "  [X] No Response [X]"))

        lines += [dash, pad("  [X] Start/Stop      [O] Operator    [Q] Quit"), sep]

        start_y = max(0, (height - len(lines)) // 2)
        for i, line in enumerate(lines):
            y = start_y + i
            if y >= height:
                break
            for j, ch in enumerate(line):
                if j < width:
                    screen[y][j] = (ch, 0, False)

        return screen


    # ── Analysis helpers ──────────────────────────────────────────────────────

    def analyze_ip_type(self, ip):
        for prefix, type_, meaning, threat in [
            ("fe80:",    "IPv6 Link-Local",   "Device on local network",          "Safe"),
            ("ff02:",    "IPv6 Multicast",    "Broadcast to local devices",       "Safe"),
            ("::1",      "IPv6 Localhost",    "Your own computer (loopback)",     "Safe"),
            ("fc00:",    "IPv6 Unique Local", "Private IPv6 (like 192.168.x.x)", "Safe"),
            ("fd00:",    "IPv6 Unique Local", "Private IPv6 (like 192.168.x.x)", "Safe"),
            ("10.",      "IPv4 Private",      "Home/office network device",       "Safe"),
            ("192.168.", "IPv4 Private",      "Home/office network device",       "Safe"),
            ("172.16.",  "IPv4 Private",      "Home/office network device",       "Safe"),
            ("127.",     "IPv4 Localhost",    "Your own computer",                "Safe"),
        ]:
            if ip.startswith(prefix):
                return {"type": type_, "meaning": meaning, "threat": threat}

        return {"type": "Public Internet IP", "meaning": "External device from the internet",
                "threat": "Depends on activity"}


    # ── Main render ───────────────────────────────────────────────────────────

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

        if self.netscan_mode:
            globe_screen = self.render_netscan_panel(globe_w, globe_h)
            title        = " Net Scan "
        elif self.operator_mode:
            globe_screen = self.render_operator_panel(globe_w, globe_h)
            title        = " Operator Mode "
        elif self.death_star_mode:
            globe_screen = self.render_death_star(globe_w, globe_h, rotation, rainbow, skittles)
            title        = " Death Star "
        elif self.ids_mode:
            globe_screen = self.render_ids_panel(globe_w, globe_h)
            title        = "Intrusion Detection System"
        elif self.arp_posion_mode:
            globe_screen = self.render_arp_poison_panel(globe_w, globe_h)
            title        = "ARP Cache Poison"
        else:
            self.globe.lighting  = self.lighting
            self.globe.plus_mode = self.plus_mode
            globe_screen = self.globe.render(rotation, rainbow, skittles)
            title        = " Attack Globe "

        border_color = self.get_color(self.theme["globe"])
        out = ["\033[?25l", self.term.home]

        out.append(self.term.move(0, 0) +
                   border_color("┌" + title + "─" * (globe_w - len(title) - 2) + "┐") + RESET)

        for y in range(1, globe_h + 1):
            out.append(self.term.move(y, 0)           + border_color("│") + RESET)
            out.append(self.term.move(y, globe_w - 1) + border_color("│") + RESET)

        gc     = self.get_color(self.theme["globe"])
        gc_dim = self.get_color(self.theme["globe"], dim=True)

        for y, row in enumerate(globe_screen):
            line = []
            for x in range(min(len(row), globe_w - 2)):
                ch, cidx, shaded = row[x]
                if ch == " ":
                    line.append(" ")
                    continue

                if rainbow or skittles:
                    col = self.get_color("", cidx, dim=shaded)
                elif shaded:
                    col = gc_dim
                else:
                    col = gc

                line.append(col(ch))

            if line:
                out.append(self.term.move(y + 1, 1) + "".join(line))

        out.append(self.term.move(globe_h + 1, 0) +
                   border_color("└" + "─" * (globe_w - 2) + "┘") + RESET)

        # ── Right panel: Live Feed ────────────────────────────────────────────
        feed_x = globe_w + 2
        feed_w = max(20, self.term.width - feed_x - 1)
        feed_h = self.term.height // 2 - 2
        fc     = self.get_color(self.theme["feed"])

        for y in range(1, feed_h):
            out.append(self.term.move(y, feed_x + 1) + " " * (feed_w - 2))

        out.append(self.term.move(0, feed_x) +
                   fc("┌ Live Feed " + "─" * (feed_w - 13) + "┐") + RESET)
        out.append(self.term.move(feed_h, feed_x) +
                   fc("└" + "─" * (feed_w - 2) + "┘") + RESET)

        for y in range(1, feed_h):
            out.append(self.term.move(y, feed_x)              + fc("│") + RESET)
            out.append(self.term.move(y, feed_x + feed_w - 1) + fc("│") + RESET) 

        hdr = (f"{'TIME':<8} {'SRC IP':<13} {'DST IP':<13} "
               f"{'PORT':<5} {'PROTO':<5} {'STATUS':<8} {'SVC':<7} {'CC':<3} {'THREAT':<7}")
        out.append(self.term.move(1, feed_x + 1) + self.term.bright_yellow(hdr[:feed_w-3]))
        out.append(self.term.move(2, feed_x + 1) + fc("─" * min(len(hdr), feed_w - 3)))

        for i, conn in enumerate(self.log_parser.get_connections()[-10:]):
            yp = 3 + i
            if yp >= feed_h - 1:
                break

            ts     = getattr(conn, "timestamp", "")
            tstr   = ts.split()[-1][:8] if ts.split() else "--------"
            svc    = getattr(conn, "service", "?")[:7]
            cc     = getattr(conn, "country", "??")
            threat = getattr(conn, "threat",  "UNKNOWN")
            action = getattr(conn, "action",  "DROP")
            dst_ip = getattr(conn, "dst_ip",  "?")

            st_txt = "BLOCKED" if action == "DROP" else "ALLOWED" if action == "ALLOW" else action.upper()
            st_col = self.term.red if action == "DROP" else self.term.green
            th_col = (self.term.green  if threat in ("SAFE", "ISP") else
                      self.term.yellow if threat == "CLOUD"          else
                      self.term.red    if threat == "HOSTING"        else self.term.white)

            base = f"{tstr:<8} {conn.ip[:13]:<13} {dst_ip[:13]:<13} {conn.port:<5} {conn.protocol:<5} "
            stat = f"{st_txt:<8} "
            svc_ = f"{svc:<7} {cc:<3} "
            thr_ = f"{threat:<7}"
            full = (base + stat + svc_ + thr_)[:feed_w - 3]
            b, s, v = len(base), len(stat), len(svc_)

            out.append(
                self.term.move(yp, feed_x + 1) +
                self.term.cyan(full[:b])        +
                st_col(full[b:b+s])             +
                self.term.cyan(full[b+s:b+s+v]) +
                th_col(full[b+s+v:])
            )

        # ── Right panel: Stats ────────────────────────────────────────────────
        stats_y  = feed_h + 1
        sc       = self.get_color(self.theme["stats"])
        st_title = f" Stats - {self.theme['name'].upper()} "

        for y in range(stats_y + 1, self.term.height - 1):
            out.append(self.term.move(y, feed_x + 1) + " " * (feed_w - 2))

        out.append(self.term.move(stats_y, feed_x) +
                   sc("┌" + st_title + "─" * max(0, feed_w - len(st_title) - 2) + "┐") + RESET)

        for y in range(stats_y + 1, self.term.height - 1):
            out.append(self.term.move(y, feed_x)              + sc("│") + RESET)
            out.append(self.term.move(y, feed_x + feed_w - 1) + sc("│") + RESET)

        out.append(self.term.move(self.term.height - 1, feed_x) +
                   sc("└" + "─" * (feed_w - 2) + "┘") + RESET)

        # System info
        sys_info = self.sys_info_cache or {}
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
            mac      = ":".join(f"{(uuid.getnode() >> (8*i)) & 0xff:02x}" for i in range(5, -1, -1))
        except Exception:
            local_ip = mac = "Unknown"

        user = os.environ.get("USERNAME", os.environ.get("USER", "user"))
        sys_info["System IP"] = local_ip
        sys_info["MAC Addr"]  = mac

        keys = ["System IP", "MAC Addr", "OS", "Kernel", "Architecture", "BIOS",
                "Host", "Network", "Terminal", "Resolution", "Motherboard",
                "CPU", "CPU Load", "CPU Temp", "GPU", "RAM", "Disk", "Uptime"]
        if sys_info.get("Battery"):
            keys.append("Battery")

        row = stats_y + 1
        uh  = f"{user}@{sys_info.get('Host', '?')}"[:feed_w - 3]

        out.append(self.term.move(row,     feed_x + 1) + self.term.bright_cyan(uh))
        out.append(self.term.move(row + 1, feed_x + 1) + sc("─" * len(uh)))

        for i, key in enumerate(keys):
            if row + 2 + i >= self.term.height - 3:
                break
            val  = sys_info.get(key, "N/A")
            maxv = max(3, feed_w - len(key) - 5)
            if len(val) > maxv:
                val = val[:maxv - 3] + "..."
            out.append(self.term.move(row + 2 + i, feed_x + 1) +
                       sc(f"{key}: ") + self.term.white(val))

        # Status bar
        st_txt2  = "PAUSED" if self.paused else "RUNNING"
        st_col2  = self.term.red if self.paused else self.term.green
        leg_note = " | C for legend"
        ver_txt  = f"v{VERSION}"
        pad_w    = feed_w - 3 - len(st_txt2) - len(leg_note) - len(ver_txt)

        out.append(self.term.move(self.term.height - 2, feed_x + 1) +
                   st_col2(st_txt2) + self.term.cyan(leg_note) +
                   (" " * max(0, pad_w)) + self.term.bright_black(ver_txt))

        # Legend bar
        if self.show_legend:
            legend = ("[Space]Pause [A]Details [C]Legend [D]DeathStar [I]IDS [L]Light "
                      "[P]Plus [S]NetScan [T]Theme [O]Operator [Z]Poison [Q]Quit")
            out.append(self.term.move(globe_h, 1) +
                       self.term.on_black +
                       self.term.bright_yellow(legend.center(globe_w - 2)) + RESET)
        else:
            out.append(self.term.move(globe_h, 1) + " " * (globe_w - 2))

        # Attack detail overlay
        if self.show_attack_details:
            all_c = self.log_parser.get_connections()
            if all_c:
                latest = all_c[-1]
                pw     = min(feed_w - 4, 50)
                px, py = feed_x + 2, 2
                pc     = self.term.bright_cyan

                for cy2 in range(py, py + 16):
                    out.append(self.term.move(cy2, px) + self.term.on_black + " " * pw + RESET)

                out.append(self.term.move(py, px) +
                           self.term.on_black +
                           pc("┌─ Attack Details " + "─" * (pw - 19) + "┐") + RESET)

                details = [
                    f"IP: {latest.ip}",
                    (f"Location: {getattr(latest,'city','?')}, "
                     f"{getattr(latest,'country_full','?')} ({getattr(latest,'country','??')})"),
                    f"ISP: {getattr(latest,'isp','?')}", "",
                    f"Port: {latest.port} ({getattr(latest,'service','?')})",
                    f"Protocol: {latest.protocol}",
                    f"Time: {getattr(latest,'timestamp','?')}", "",
                    f"Threat: {getattr(latest,'threat','?')}",
                    f"Type: {getattr(latest,'attack_type','?')}",
                    f"Count: {getattr(latest,'count',1)}", "",
                ]

                for di, dl in enumerate(details):
                    padl = f" {dl[:pw-4]:<{pw-4}} "
                    out.append(self.term.move(py + 1 + di, px) +
                               self.term.on_black +
                               pc("│") + self.term.white(padl) + pc("│") + RESET)

                bot = py + len(details) + 1
                out.append(self.term.move(bot, px) +
                           self.term.on_black + pc("└" + "─" * (pw - 2) + "┘") + RESET)
                out.append(self.term.move(bot + 1, px) +
                           self.term.on_black +
                           self.term.bright_yellow(" Press [A] to close ".center(pw)) + RESET)

        out.append(self.term.move(self.term.height - 1, self.term.width - 1))
        out.append("\033[?25l")
        sys.stdout.write("".join(out))
        sys.stdout.flush()


    # ── Background threads ────────────────────────────────────────────────────

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

                if k in ("q",) or key.code == self.term.KEY_ESCAPE:
                    self.running = False

                elif key == " ":
                    if self.paused:
                        self.start_time = (time.time() -
                                           (self.pause_rotation / (-2 * math.pi)) *
                                           self.rotation_period)
                    else:
                        self.pause_rotation = self.get_rotation()
                    self.paused = not self.paused

                elif k == "t": self.cycle_theme()
                elif k == "l": self.lighting            = not self.lighting
                elif k == "p": self.plus_mode           = not self.plus_mode
                elif k == "c": self.show_legend         = not self.show_legend
                elif k == "d": self.death_star_mode     = not self.death_star_mode
                elif k == "a": self.show_attack_details = not self.show_attack_details

                elif k == "o":
                    self.operator_mode = not self.operator_mode
                    if self.operator_mode:
                        self.netscan_mode = False

                elif k == "i":
                    if self.ids_panel_state == 0:       # open panel
                        self.ids_panel_state          = 1
                        self.ids_mode                 = True
                        self.netscan_mode             = False
                        self.operator_mode            = False
                        self.ids_panel.stop_requested = False
                        self.ids_panel.scanning       = False
                        self.ids_panel.scan_complete  = False

                    elif self.ids_panel_state == 1:     # start scan
                        self.ids_panel_state          = 2
                        self.ids_panel.stop_requested = False
                        self.ids_panel.scanning       = False
                        self.ids_panel.scan_complete  = False
                        threading.Thread(target=self.ids_panel.run_loop, daemon=True).start()

                    elif self.ids_panel_state == 2:     # stop scan
                        self.ids_panel_state          = 3
                        self.ids_panel.stop_requested = True
                        self.ids_panel.scanning       = False

                    elif self.ids_panel_state == 3:     # close panel
                        self.ids_panel_state          = 0
                        self.ids_mode                 = False
                        self.ids_panel.scan_complete  = False
                        self.ids_panel.stop_requested = False

                
                elif  k == "x":                   
                    if self.arp_poison_panel_state == 0:    # open panel
                        self.arp_poison_panel_state          = 1
                        self.arp_posion_mode                 = True
                        self.arp_poison_panel.active         = False
                        self.arp_poison_panel.inactive       = False
                        self.arp_poison_panel.stop_requested = False
                        self.ids_mode = self.netscan_mode = self.operator_mode = False

                    elif self.arp_poison_panel_state == 1:  # start payload
                        self.arp_poison_panel_state          = 2
                        self.arp_poison_panel.active         = False
                        self.arp_poison_panel.inactive       = False
                        self.arp_poison_panel.stop_requested = False
                        threading.Thread(target=self.arp_poison_panel.cache_poison,
                                         daemon=True).start()

                    elif self.arp_poison_panel_state == 2:  # stop payload
                        self.arp_poison_panel_state          = 3
                        self.arp_poison_panel.active         = False
                        self.arp_poison_panel.inactive       = False
                        self.arp_poison_panel.stop_requested = True

                    elif self.arp_poison_panel_state == 3:  # close panel
                        self.arp_poison_panel_state          = 0
                        self.arp_posion_mode                 = False
                        self.arp_poison_panel.stop_requested = False
                        self.arp_poison_panel.inactive       = False

                elif k == "s":
                    if not self.netscan_mode:
                        self.netscan_mode  = True
                        self.operator_mode = False
                        self.ids_mode      = False
                    elif not self.netscan.scanning:
                        if self.netscan.scan_done:
                            with self.netscan._lock:
                                self.netscan.results.clear()
                            self.netscan.scan_done = False
                        self.netscan.start_scan()

                elif k == "x":
                    # X closes the ARP panel if open, otherwise quits
                    if self.arp_posion_mode:
                        self.arp_poison_panel_state          = 0
                        self.arp_posion_mode                 = False
                        self.arp_poison_panel.stop_requested = True
                        self.arp_poison_panel.inactive       = False
                    else:
                        self.running = False


    # ── Main run loop ─────────────────────────────────────────────────────────

    def run(self):
        if self.use_real_logs:
            self.log_parser.start()

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
                    t0    = time.time()
                    self.render()
                    sleep = max(0, 0.050 - (time.time() - t0))
                    if sleep:
                        time.sleep(sleep)
            except KeyboardInterrupt:
                pass
            finally:
                self.running = False
                print("\033[?25h", end="", flush=True)