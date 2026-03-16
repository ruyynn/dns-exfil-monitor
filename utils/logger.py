"""
Logger - simpan semua aktivitas ke file JSON & TXT.
"""

import json
import os
from datetime import datetime


LOG_DIR = os.path.join(os.path.expanduser("~"), ".dns_exfil_monitor", "logs")


def ensure_log_dir():
    os.makedirs(LOG_DIR, exist_ok=True)


def get_log_path(ext="json"):
    ensure_log_dir()
    date_str = datetime.now().strftime("%Y%m%d")
    return os.path.join(LOG_DIR, f"dns_exfil_{date_str}.{ext}")


def log_event(event: dict):
    """Append event ke log JSON harian."""
    path = get_log_path("json")
    events = []
    if os.path.exists(path):
        try:
            with open(path, "r") as f:
                events = json.load(f)
        except Exception:
            events = []
    events.append(event)
    with open(path, "w") as f:
        json.dump(events, f, indent=2)


def log_text(message: str):
    """Append plain text log."""
    path = get_log_path("txt")
    with open(path, "a") as f:
        f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {message}\n")


def get_log_dir():
    return LOG_DIR
