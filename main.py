#!/usr/bin/env python3
"""
DNS Exfiltration Monitor - Main Entry Point
by Ruyynn | github.com/ruyynn
"""

import sys
import signal
import argparse
import threading
import time

# Fix import path
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rich.live import Live
from rich.console import Console

from core.sniffer import DNSSniffer, get_interfaces
from core.analyzer import DNSAnalyzer
from cli.interface import DashboardUI, print_banner, print_error, print_info, print_success
from utils.logger import log_event, log_text, get_log_dir

console = Console()

# ── Global state ──────────────────────────────────────────
analyzer = DNSAnalyzer()
ui = DashboardUI()
sniffer = None
_running = True


def on_dns_packet(event: dict):
    """Callback tiap ada DNS packet."""
    global _running
    if not _running:
        return

    alert = analyzer.analyze(event)
    ui.update_stats(analyzer.stats)

    if alert:
        ui.add_alert(alert)
        log_event(alert)
        log_text(
            f"[{alert['severity']}] {alert['domain']} | "
            f"src={alert['src_ip']} | entropy={alert['entropy']} | "
            f"reasons={', '.join(alert['reasons'])}"
        )


def signal_handler(sig, frame):
    global _running, sniffer
    _running = False
    if sniffer:
        sniffer.stop()
    console.print("\n[bold yellow][*] Monitoring dihentikan. Sampai jumpa! 👋[/bold yellow]")
    console.print(f"[dim]Log tersimpan di: {get_log_dir()}[/dim]")
    sys.exit(0)


def reset_subdomains_periodically():
    """Reset unique subdomain tracker tiap menit."""
    while _running:
        time.sleep(60)
        analyzer.reset_subdomains()


def main():
    global sniffer

    parser = argparse.ArgumentParser(
        description="DNS Exfiltration Monitor by Ruyynn",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Contoh:
  sudo python3 main.py                    # Auto detect interface
  sudo python3 main.py -i eth0            # Interface spesifik
  sudo python3 main.py -i wlan0 -v        # Verbose mode
  sudo python3 main.py --list-interfaces  # Lihat interface tersedia
        """
    )
    parser.add_argument("-i", "--interface", help="Network interface (default: auto)", default=None)
    parser.add_argument("-v", "--verbose", action="store_true", help="Tampilkan semua DNS query")
    parser.add_argument("--list-interfaces", action="store_true", help="List interface tersedia")
    parser.add_argument("--threshold", type=int, default=15, help="Query/menit threshold (default: 15)")
    args = parser.parse_args()

    # List interfaces
    if args.list_interfaces:
        ifaces = get_interfaces()
        console.print("[bold cyan]Interface tersedia:[/bold cyan]")
        for iface in ifaces:
            console.print(f"  • {iface}")
        return

    print_banner()

    # Threshold custom
    import core.analyzer as ana_mod
    ana_mod.QUERY_FREQ_THRESHOLD = args.threshold

    iface_display = args.interface or "auto"
    ui.set_interface(iface_display)

    print_info(f"Interface: [bold]{iface_display}[/bold]")
    print_info(f"Threshold: [bold]{args.threshold} query/menit[/bold]")
    print_info(f"Log dir: [bold]{get_log_dir()}[/bold]")
    print_info("Memulai monitoring DNS... (Ctrl+C untuk berhenti)\n")

    # Signal handler
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Background thread reset subdomain tracker
    reset_thread = threading.Thread(target=reset_subdomains_periodically, daemon=True)
    reset_thread.start()

    # Start sniffer
    try:
        sniffer = DNSSniffer(interface=args.interface, callback=on_dns_packet)
        sniffer.start()
    except PermissionError as e:
        print_error(str(e))
        sys.exit(1)
    except RuntimeError as e:
        print_error(str(e))
        sys.exit(1)

    # Live dashboard
    with Live(ui.render(), refresh_per_second=2, screen=True) as live:
        while _running:
            ui.update_stats(analyzer.stats)
            live.update(ui.render())
            time.sleep(0.5)


if __name__ == "__main__":
    main()
