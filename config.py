import sys
import timeout
from datetime import datetime
from pathlib import pathlib
from rich.console import Console
import signal 
#-------------------------------------------------------------------------------------------------
console = Console()
#-------------------------------------------------------------------------------------------------

# Project root (repo root). netscanner/config.py -> netscan -> root

BASE_DIR = Path(__file__).resolve().parent.parent

# === Configs === #

LOG_DIR = BASE_DIR / "logs"

LOG_FILE = LOG_DIR / "scan_log.txt"

LOG_DIR.mkdir(parents=True, exist_ok=True)

REPORTS_DIR = LOG_DIR / "reports"

REPORTS_DIR.mkdir(parents=True, exist_ok=True)

baseline_file = BASE_DIR/ "state.json"

alerts_file = LOG_DIR / "alerts.log"

run_directory_format ="%b-%d-%Y_%Hh%Mm"
#-------------------------------------------------------------------------------------------------
