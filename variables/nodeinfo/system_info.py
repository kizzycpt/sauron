import os
import sys
import platform
import subprocess
from datetime import datetime

import psutil


def get_system_info() -> tuple[dict, str]:
    info    = {}
    os_name = platform.system()

    # OS
    if sys.platform == "win32":
        try:
            r    = subprocess.run(["wmic", "os", "get", "BuildNumber"],
                                  capture_output=True, text=True, timeout=2)
            nums = [l.strip() for l in r.stdout.split("\n")
                    if l.strip() and "BuildNumber" not in l]
            info["OS"] = (f"{os_name} {platform.release()} (Build {nums[0]})"
                          if nums else f"{os_name} {platform.release()}")
        except Exception:
            info["OS"] = f"{os_name} {platform.release()}"
    else:
        info["OS"] = f"{os_name} {platform.release()}"

    info["Kernel"]       = platform.version() if sys.platform == "win32" else platform.release()
    info["Architecture"] = platform.machine()
    info["Host"]         = platform.node()



    # Terminal
    for var, name in [("WT_SESSION", "Windows Terminal"), ("ConEmuPID", "ConEmu"),
                      ("HYPER_VERSION", "Hyper"), ("ALACRITTY_SOCKET", "Alacritty")]:
        if os.environ.get(var):
            info["Terminal"] = name
            break
    else:
        info["Terminal"] = os.environ.get("TERM_PROGRAM") or os.environ.get("TERM") or "Unknown"



    # Resolution
    try:
        if sys.platform == "win32":
            r     = subprocess.run(
                ["wmic", "path", "Win32_VideoController",
                 "get", "CurrentHorizontalResolution,CurrentVerticalResolution"],
                capture_output=True, text=True, timeout=2)
            nums  = [l.strip() for l in r.stdout.split("\n")
                     if l.strip() and "Current" not in l]
            parts = nums[0].split() if nums else []
            info["Resolution"] = f"{parts[0]}x{parts[1]}" if len(parts) >= 2 else "N/A"
        else:
            r = subprocess.run(["xrandr"], capture_output=True, text=True, timeout=2)
            info["Resolution"] = next(
                (l.split()[0] for l in r.stdout.split("\n") if "*" in l), "N/A")
    except Exception:
        info["Resolution"] = "N/A"

    # Motherboard
    try:
        if sys.platform == "win32":
            r     = subprocess.run(["wmic", "baseboard", "get", "Manufacturer,Product"],
                                   capture_output=True, text=True, timeout=2)
            lines = [l.strip() for l in r.stdout.split("\n")
                     if l.strip() and "Manufacturer" not in l]
            info["Motherboard"] = lines[0] if lines else "N/A"
        else:
            r   = subprocess.run(["dmidecode", "-t", "2"],
                                 capture_output=True, text=True, timeout=2)
            mfr = prd = ""
            for line in r.stdout.split("\n"):
                if "Manufacturer:" in line: mfr = line.split(":")[1].strip()
                if "Product Name:" in line: prd = line.split(":")[1].strip()
            info["Motherboard"] = f"{mfr} {prd}".strip() or "N/A"
    except Exception:
        info["Motherboard"] = "N/A"

    info["CPU"] = platform.processor() or "N/A"

    # GPU
    try:
        if sys.platform == "win32":
            r    = subprocess.run(["wmic", "path", "win32_VideoController", "get", "name"],
                                  capture_output=True, text=True, timeout=2)
            gpus = [l.strip() for l in r.stdout.split("\n")
                    if l.strip() and "Name" not in l]
            info["GPU"] = (gpus[0][:25] + ("..." if len(gpus[0]) > 25 else "")) if gpus else "N/A"
        else:
            info["GPU"] = "N/A"
    except Exception:
        info["GPU"] = "N/A"

    # BIOS
    try:
        if sys.platform == "win32":
            r     = subprocess.run(["wmic", "bios", "get", "SMBIOSBIOSVersion"],
                                   capture_output=True, text=True, timeout=2)
            lines = [l.strip() for l in r.stdout.split("\n")
                     if l.strip() and "SMBIOS" not in l]
            info["BIOS"] = lines[0] if lines else "N/A"
        else:
            r = subprocess.run(["dmidecode", "-s", "bios-version"],
                               capture_output=True, text=True, timeout=2)
            info["BIOS"] = r.stdout.strip() or "N/A"
    except Exception:
        info["BIOS"] = "N/A"

    # RAM / Disk
    m = psutil.virtual_memory()
    info["RAM"] = f"{m.used//1024**3}GB / {m.total//1024**3}GB ({int(m.percent)}%)"

    try:
        d = psutil.disk_usage("C:\\" if sys.platform == "win32" else "/")
        info["Disk"] = f"{d.used//1024**3}GB / {d.total//1024**3}GB ({int(d.percent)}%)"
    except Exception:
        info["Disk"] = "N/A"

    # Network type
    try:
        if sys.platform == "win32":
            r     = subprocess.run(["wmic", "nic", "where", "NetEnabled=true", "get", "Name"],
                                   capture_output=True, text=True, timeout=2)
            ntype = "Ethernet"
            for line in r.stdout.split("\n"):
                if any(w in line.lower() for w in ("wireless", "wi-fi", "802.11", "wifi")):
                    ntype = "WiFi"
                    break
            info["Network"] = ntype
        else:
            r = subprocess.run(["iwconfig"], capture_output=True, text=True, timeout=2)
            info["Network"] = ("WiFi" if r.returncode == 0
                               and "no wireless" not in r.stderr.lower() else "Ethernet")
    except Exception:
        info["Network"] = "Unknown"

    # Uptime
    try:
        up   = datetime.now() - datetime.fromtimestamp(psutil.boot_time())
        d, h = up.days, up.seconds // 3600
        m_   = (up.seconds % 3600) // 60
        info["Uptime"] = f"{d}d {h}h" if d else f"{h}h {m_}m"
    except Exception:
        info["Uptime"] = "N/A"

    # CPU load / temp
    try:
        info["CPU Load"] = f"{psutil.cpu_percent(interval=0.1)}%"
    except Exception:
        info["CPU Load"] = "N/A"

    try:
        temps = psutil.sensors_temperatures() if hasattr(psutil, "sensors_temperatures") else {}
        cpu_t = None
        for name, ents in (temps or {}).items():
            if any(k in name.lower() for k in ("coretemp", "cpu", "k10temp")):
                if ents:
                    cpu_t = ents[0].current
                    break
        info["CPU Temp"] = f"{int(cpu_t)}°C" if cpu_t else "N/A"
    except Exception:
        info["CPU Temp"] = "N/A"

    # Battery
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