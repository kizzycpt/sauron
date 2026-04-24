# Sauron — Network Attack & Monitor Dashboard

```
███████  █████  ██  ██ ██████   ██████  ███  ██
██      ██   ██ ██  ██ ██   ██ ██    ██ ████ ██
███████ ███████ ██  ██ ██████  ██    ██ ██ ████
     ██ ██   ██ ██  ██ ██   ██ ██    ██ ██  ███
███████ ██   ██  ████  ██   ██  ██████  ██   ██
```

> *Recreated by* **kizzycpt** *(concept by ringmst4r/DEATH-STAR)*

A terminal-based network security dashboard featuring a live 3D ASCII globe,
firewall log monitoring, intrusion detection, and network scanning — all in one
full-screen TUI.

---

## Features

- **3D ASCII Globe** — real-time rotating Earth with attack origin markers
- **Live Firewall Feed** — tails UFW/iptables/journalctl and parses blocked connections
- **IP Intelligence** — geolocation + threat classification (CLOUD / HOSTING / ISP / SAFE)
- **IDS Mode** — ARP-based intrusion detection, baseline comparison, and alert logging
- **Net Scan Panel** — local subnet scanner with hostname, port, and OS detection
- **Operator Mode** — detailed stats: top IPs, top ports, protocol breakdown, scan attempts
- **Attack Detail Overlay** — deep-dive on the latest blocked connection
- **7 Themes** — Matrix, Amber, Nord, Dracula, Mono, Rainbow, Skittles
- **CSV + Markdown Logging** — all attacks and IDS runs saved to `logs/`
- **Death Star Mode** — prebuilt feature cuz i like star wars

---

## Requirements

### Python
Python 3.8+

### Dependencies

```bash
# Debian / Ubuntu / Kali (recommended)
sudo apt install python3-psutil python3-blessed

# Or via pip
pip3 install psutil blessed --break-system-packages

# Or from requirements.txt
pip3 install -r requirements.txt --break-system-packages
```

### System Tools (optional but recommended)
| Tool | Purpose |
|------|---------|
| `ufw` | Firewall log source |
| `journalctl` | systemd journal log source (Arch / any systemd distro) |
| `dmidecode` | Motherboard / BIOS info |
| `xrandr` | Screen resolution detection |
| `nmap` | Enhanced port scanning (if integrated) |

---

## Installation

```bash
git clone https://github.com/kizzycpt/sauron.git
cd sauron
pip3 install -r requirements.txt --break-system-packages
```

---

## Usage

```bash
python3 evileye.py
```

### Options

```bash
python3 evileye.py --theme matrix       # Set startup theme
python3 evileye.py --rotation 30        # Globe rotation speed in seconds
python3 evileye.py --log-path /var/log/ufw.log  # Custom firewall log path
```

---

## Keybinds

| Key | Action |
|-----|--------|
| `Space` | Pause / resume globe rotation |
| `T` | Cycle theme |
| `D` | Toggle Death Star mode |
| `L` | Toggle lighting / shading |
| `P` | Toggle plus-char mode |
| `C` | Toggle legend bar |
| `A` | Toggle attack detail overlay |
| `O` | Toggle operator mode |
| `S` | Open net scan panel → press again to start scan |
| `I` | IDS: Open → Start → Stop → Close (4-press cycle) |
| `Q` / `X` / `Esc` | Quit |

---

## IDS Toggle Cycle

The IDS uses a deliberate 4-press cycle to prevent accidental scans:

```
Press 1 → Panel opens    (idle, no scan running)
Press 2 → Scan starts    (ARP sweep + port check begins)
Press 3 → Scan stops     (panel stays open, shows TERMINATED)
Press 4 → Panel closes   (returns to globe view)
```

---

## Firewall Logging Setup

Sauron needs an active firewall log to display live data.

### Linux — UFW
```bash
sudo ufw enable
sudo ufw logging on
```

### Arch / systemd (journalctl)
```bash
# Add your user to the systemd-journal group
sudo usermod -aG systemd-journal $USER

# Log out and back in, then verify
groups | grep systemd-journal
```

### Windows
```
Win+R → wf.msc → Properties → Logging → Log dropped packets = YES
```

If no active log is found at launch, Sauron will warn you and offer to
continue without live data.

---

## Log Output

All data is saved automatically under `logs/`:


### CSV Fields (attacks)
`Timestamp, Source_IP, Dest_IP, Port, Protocol, Service, Country, City, ISP, Threat_Level, Attack_Type, Action`

---

## Project Structure

```
evileye/
├── evileye.py                   # Dashboard entry point
├── config.py                    # Configuration
├── requirements.txt
├── README.md
├── .gitignore
├── venv/                        # Virtual environment
├── modes/
│   ├── IDS.py                   # Intrusion detection module
│   └── netscan.py               # Network scanner module
├── variables/
│   ├── ether/
│   │   ├── gateway.py           # Gateway detection
│   │   ├── icmp.py              # Ping / ICMP utilities
│   │   ├── L2.py                # ARP scanning
│   │   ├── mac.py               # MAC address helpers
│   │   └── ports.py             # Port scanner
│   ├── nodeinfo/
│   │   ├── hostname.py          # Hostname resolution
│   │   └── os.py                # OS fingerprinting
│   ├── ui/
│   │   └── banners.py           # ASCII banners
│   └── utils/
│       ├── alerts.py            # Alert helpers
│       ├── baseline.py          # Baseline read/write
│       ├── inventory.py         # Device inventory
│       └── signals.py           # SIGINT handler
└── logs/                        # Auto-generated log output
    ├── attacks_YYYY-MM-DD.csv
    └── IDS/
        ├── ids.log
        └── runs/
            └── YYYY-MM-DD_HH-MM-SS/
                ├── devices.csv
                └── report.md
```

---

## Threat Classification

| Level | Meaning |
|-------|---------|
| `CLOUD` | AWS, GCP, Azure, DigitalOcean, Cloudflare, etc. |
| `HOSTING` | VPS, dedicated servers, datacenters |
| `ISP` | Residential / commercial ISP addresses |
| `SAFE` | Known clean residential traffic |
| `LOCAL` | Private network address |
| `UNKNOWN` | Could not classify |

---

## Linux Capabilities & Alias Setup

For full functionality on Linux (raw socket access, nmap scanning), grant capabilities
instead of running as root:

```bash
# Grant raw network capabilities to Python
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/python3

# Grant capabilities to nmap
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service,cap_dac_override+eip /usr/bin/nmap

# Add a sauron alias (adjust path to match your install)
echo "alias sauron='sudo /home/$USER/Documents/programs/evileye/venv/bin/python /home/$USER/Documents/programs/evileye/evileye.py'" >> ~/.bashrc
source ~/.bashrc

# Then launch with:
sauron
```

---

## Troubleshooting

### Live Feed Not Showing Data

---

#### Arch Linux / systemd systems

Arch does not write UFW logs to `/var/log/ufw.log` by default. Instead, rsyslog
routes them to `/var/log/syslog`. The dashboard auto-detects this, but the file
may not be readable by your user.

**Find where UFW logs are going:**
```bash
sudo grep -r "UFW BLOCK" /var/log/ 2>/dev/null | head -3
```

**Check if the log file is readable:**
```bash
ls -la /var/log/syslog
```
- `-rw-r--r--` → you are fine
- `-rw-r-----` (root/adm only) → fix it:

```bash
# Option 1: open permissions
sudo chmod o+r /var/log/syslog

# Option 2: add yourself to the log group
sudo usermod -aG adm $USER
newgrp adm
```

**Make sure rsyslog is running:**
```bash
systemctl status rsyslog

# If not installed:
sudo pacman -S rsyslog
sudo systemctl enable --now rsyslog
```

**Make sure UFW logging is enabled:**
```bash
sudo ufw logging on
sudo ufw status verbose
# Output should show "Logging: on"
```

---

#### Ubuntu / Debian / Kali

UFW logs directly to `/var/log/ufw.log`. If the feed is empty:

```bash
sudo ufw logging on
sudo ufw reload
tail -f /var/log/ufw.log
```

The `tail` command lets you verify logs are flowing in real time before
launching the dashboard.

---

### Feed Only Shows Local IPs (192.168.x.x)

If your feed shows only local network blocks like `192.168.0.1` hitting
`224.0.0.251`, that is normal and expected — those are IGMP multicast
packets from devices on your LAN being blocked by UFW. It means the
firewall is active and logging correctly. External attack traffic will
appear once your machine receives probes from the public internet.

---

### Other Issues

**IDS panel doesn't appear**
→ Make sure `self.ids_panel_state = 0` is set in `Dashboard.__init__`. See IDS toggle cycle above.

**`blessed` or `psutil` not found**
→ Run `pip3 install psutil blessed --break-system-packages`

**journalctl permission denied**
```bash
sudo usermod -aG systemd-journal $USER
# then log out and back in
```

**Dashboard shows no live data at all**
-> Enable UFW logging (`sudo ufw logging on`) or ensure journalctl has read permissions.

---

## License

MIT — do whatever you want, just don't use it for evil doe.

---

*"I see you. -Sauron"*
# sauron
