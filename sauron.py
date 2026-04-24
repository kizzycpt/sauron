#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sauron - Net Attack/Monitor Dashboard
    recreated by kizzycpt (ringmst4r)

- Neofetch-style system information
- IDS monitoring and counter-intelligence tools
- Network scanner  (S → open panel, S again → start scan)
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
import ctypes
import psutil

from blessed import Terminal
from datetime import datetime, timedelta
from collections import deque
from pathlib import Path


# ── Core panel objects ────────────────────────────────────────────────────────
from modes.netscan          import net_scan_panel
from modes.IDS              import ids_panel
from variables.poisons.ARP  import arp_p, arp_poison, vlan_poison

# ── Dashboard / renderer classes ──────────────────────────────────────────────
from frontend.globe                         import Globe
from variables.nodeinfo.firewall            import FirewallLogParser
from frontend.dashboard                     import Dashboard
from frontend.animations                    import boot_animation
from frontend.icons                         import *
from frontend.constants                     import VERSION, RESET, rgb, rgb_bg

# ── Optional feature modules ─────────────────────────────────────────────────
try:
    from modes.netscan import scan_mode
    HAS_NETSCAN = True
except ImportError:
    HAS_NETSCAN = False

try:
    from modes.IDS import ids_loop
    HAS_IDS = True
except ImportError:
    HAS_IDS = False



try:
    from variables.poisons.ARP import arp_poison
    HAS_ARP_POISON = True
except ImportError:
    HAS_ARP_POISON = False



# ── Windows VT100 / UTF-8 setup ───────────────────────────────────────────────
if sys.platform == "win32":
    try:
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass



# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Sauron - Network Attack Monitor Dashboard")
    parser.add_argument("--theme",    choices=list(Dashboard.THEMES), default="matrix")
    parser.add_argument("--rotation", type=int, default=50,
                        help="Globe rotation period in seconds (default: 50)")
    parser.add_argument("--log-path", type=str, default=None,
                        help="Custom firewall log path (auto-detected if omitted)")
    args = parser.parse_args()

    boot_animation()

    dashboard = Dashboard(
        rotation_period = args.rotation,
        theme           = args.theme,
        log_path        = args.log_path,
    )

    if not dashboard.use_real_logs:
        _warn_no_logs(dashboard)

    try:
        dashboard.run()
    finally:
        print("\033[?25h", end="", flush=True)


def _warn_no_logs(dashboard: Dashboard):
    """Diagnostic output when no active firewall log source is found."""
    import time
    from pathlib import Path

    print("\033[2J\033[H\033[31m")
    lp      = dashboard.log_parser.log_path
    lp_path = Path(str(lp))

    if lp == "journalctl":
        print("✗ journalctl is unavailable or returned no kernel messages.")
    elif lp_path.exists():
        import time as _t
        st  = lp_path.stat()
        age = int((_t.time() - st.st_mtime) / 60)
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


# good luck ;)
if __name__ == "__main__":
    main()