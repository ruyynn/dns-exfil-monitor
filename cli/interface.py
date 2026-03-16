"""
CLI Interface - Tampilan terminal keren pake Rich.
"""

import time
from datetime import datetime
from collections import deque

from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
from rich.layout import Layout
from rich.text import Text
from rich.columns import Columns
from rich import box
from rich.align import Align
from rich.rule import Rule

console = Console()

BANNER = """[bold cyan]
██████╗ ███╗   ██╗███████╗    ███████╗██╗  ██╗███████╗██╗██╗     
██╔══██╗████╗  ██║██╔════╝    ██╔════╝╚██╗██╔╝██╔════╝██║██║     
██║  ██║██╔██╗ ██║███████╗    █████╗   ╚███╔╝ █████╗  ██║██║     
██║  ██║██║╚██╗██║╚════██║    ██╔══╝   ██╔██╗ ██╔══╝  ██║██║     
██████╔╝██║ ╚████║███████║    ███████╗██╔╝ ██╗██║     ██║███████╗
╚═════╝ ╚═╝  ╚═══╝╚══════╝    ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝
[/bold cyan][bold yellow]
         ⚡ DNS Exfiltration Monitor v1.0 by Ruyynn ⚡
[/bold yellow][dim]    Deteksi pencurian data lewat DNS secara realtime[/dim]
[dim]         github.com/ruyynn | Made with ❤️ in 🇮🇩[/dim]
"""

SEVERITY_STYLE = {
    "HIGH":   "[bold red]🔴 HIGH[/bold red]",
    "MEDIUM": "[bold yellow]🟡 MEDIUM[/bold yellow]",
    "LOW":    "[bold green]🟢 LOW[/bold green]",
}

MAX_ALERTS_DISPLAY = 12


class DashboardUI:
    def __init__(self):
        self._alerts = deque(maxlen=MAX_ALERTS_DISPLAY)
        self._stats = {"total": 0, "alerts": 0, "high": 0, "medium": 0, "low": 0, "whitelisted": 0}
        self._start_time = time.time()
        self._interface = "auto"

    def set_interface(self, iface: str):
        self._interface = iface

    def update_stats(self, stats: dict):
        self._stats.update(stats)

    def add_alert(self, alert: dict):
        self._alerts.append(alert)

    def _make_header(self) -> Panel:
        elapsed = int(time.time() - self._start_time)
        mins, secs = divmod(elapsed, 60)
        hrs, mins = divmod(mins, 60)
        uptime = f"{hrs:02d}:{mins:02d}:{secs:02d}"

        text = Text()
        text.append("  Interface: ", style="dim")
        text.append(self._interface, style="cyan bold")
        text.append("   |   Uptime: ", style="dim")
        text.append(uptime, style="green bold")
        text.append("   |   ", style="dim")
        text.append(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), style="dim")

        return Panel(Align.center(text), style="cyan", height=3)

    def _make_stats(self) -> Panel:
        s = self._stats
        text = Text(justify="center")
        text.append("📊 Total Query: ", style="dim")
        text.append(str(s.get("total", 0)), style="bold white")
        text.append("   |   ", style="dim")
        text.append("🚨 Alerts: ", style="dim")
        text.append(str(s.get("alerts", 0)), style="bold red")
        text.append("   |   ", style="dim")
        text.append("🔴 High: ", style="dim")
        text.append(str(s.get("high", 0)), style="bold red")
        text.append("  🟡 Med: ", style="dim")
        text.append(str(s.get("medium", 0)), style="bold yellow")
        text.append("  🟢 Low: ", style="dim")
        text.append(str(s.get("low", 0)), style="bold green")
        text.append("   |   ✅ Whitelisted: ", style="dim")
        text.append(str(s.get("whitelisted", 0)), style="dim green")

        return Panel(Align.center(text), style="blue", height=3)

    def _make_alert_table(self) -> Table:
        table = Table(
            title="🔍 DNS Exfiltration Alerts",
            box=box.ROUNDED,
            border_style="red",
            header_style="bold magenta",
            show_lines=True,
            expand=True,
        )
        table.add_column("Waktu", style="dim", width=10, no_wrap=True)
        table.add_column("Severity", width=14, no_wrap=True)
        table.add_column("Domain", style="cyan", min_width=30)
        table.add_column("Src IP", style="yellow", width=16, no_wrap=True)
        table.add_column("Entropy", justify="center", width=8, no_wrap=True)
        table.add_column("Freq/min", justify="center", width=9, no_wrap=True)
        table.add_column("Alasan", style="white", min_width=25)

        for alert in reversed(list(self._alerts)):
            entropy = alert.get("entropy", 0)
            entropy_style = "red" if entropy > 4.5 else "yellow" if entropy > 3.8 else "green"
            reasons_short = ", ".join(alert.get("reasons", [])[:2])

            table.add_row(
                alert["time"],
                SEVERITY_STYLE.get(alert["severity"], alert["severity"]),
                alert["domain"][:55] + ("…" if len(alert["domain"]) > 55 else ""),
                alert.get("src_ip", "?"),
                f"[{entropy_style}]{entropy:.2f}[/{entropy_style}]",
                str(alert.get("freq_per_min", 0)),
                reasons_short[:45] + ("…" if len(reasons_short) > 45 else ""),
            )

        if not self._alerts:
            table.add_row(
                "–", "–",
                "[dim]Memantau DNS traffic... belum ada anomali terdeteksi[/dim]",
                "–", "–", "–", "–"
            )

        return table

    def _make_footer(self) -> Text:
        text = Text(justify="center")
        text.append("  [Ctrl+C] Berhenti  ", style="dim")
        text.append("  [L] Lihat logs  ", style="dim")
        text.append("  Log disimpan di: ~/.dns_exfil_monitor/logs/  ", style="dim")
        return text

    def render(self):
        layout = Layout()
        layout.split_column(
            Layout(self._make_header(), size=3),
            Layout(self._make_stats(), size=3),
            Layout(self._make_alert_table()),
            Layout(self._make_footer(), size=1),
        )
        return layout


def print_banner():
    console.print(BANNER)


def print_error(msg: str):
    console.print(f"[bold red][!] {msg}[/bold red]")


def print_info(msg: str):
    console.print(f"[cyan][*] {msg}[/cyan]")


def print_success(msg: str):
    console.print(f"[bold green][✓] {msg}[/bold green]")
