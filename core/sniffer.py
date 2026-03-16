"""
DNS Sniffer - Cross-platform DNS query capture.
Supports: Linux, Windows, macOS, Termux
"""

import sys
import platform
import threading
from datetime import datetime
from typing import Callable

# Deteksi platform
PLATFORM = platform.system().lower()
IS_TERMUX = "com.termux" in sys.executable or "termux" in sys.executable.lower()


def _parse_dns_scapy(packet, callback: Callable):
    """Parse DNS packet pake scapy (Linux/macOS/Windows)."""
    try:
        from scapy.all import DNS, DNSQR, IP, IPv6
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            qname = packet[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
            src_ip = ""
            if packet.haslayer(IP):
                src_ip = packet[IP].src
            elif packet.haslayer(IPv6):
                src_ip = packet[IPv6].src

            callback({
                "timestamp": datetime.now().isoformat(),
                "time": datetime.now().strftime("%H:%M:%S"),
                "domain": qname,
                "src_ip": src_ip,
                "qtype": packet[DNSQR].qtype,
            })
    except Exception:
        pass


def _parse_dns_socket(data: bytes, src_ip: str, callback: Callable):
    """Parse DNS packet manual dari raw socket (Termux fallback)."""
    try:
        # DNS header: 12 bytes
        if len(data) < 12:
            return
        # Skip header, parse question section
        idx = 12
        labels = []
        while idx < len(data):
            length = data[idx]
            if length == 0:
                break
            idx += 1
            labels.append(data[idx:idx + length].decode("utf-8", errors="ignore"))
            idx += length
        domain = ".".join(labels)
        if domain:
            callback({
                "timestamp": datetime.now().isoformat(),
                "time": datetime.now().strftime("%H:%M:%S"),
                "domain": domain,
                "src_ip": src_ip,
                "qtype": 1,
            })
    except Exception:
        pass


class DNSSniffer:
    def __init__(self, interface: str = None, callback: Callable = None):
        self.interface = interface
        self.callback = callback
        self._stop_event = threading.Event()
        self._thread = None

    def start(self):
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._sniff, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()

    def _sniff(self):
        if IS_TERMUX:
            self._sniff_termux()
        else:
            self._sniff_scapy()

    def _sniff_scapy(self):
        try:
            from scapy.all import sniff, DNS
            kwargs = {
                "filter": "udp port 53",
                "prn": lambda pkt: _parse_dns_scapy(pkt, self.callback),
                "store": False,
                "stop_filter": lambda _: self._stop_event.is_set(),
            }
            if self.interface:
                kwargs["iface"] = self.interface
            sniff(**kwargs)
        except PermissionError:
            raise PermissionError(
                "Butuh root/admin untuk capture DNS packet.\n"
                "Linux/macOS: jalankan dengan sudo\n"
                "Windows: jalankan sebagai Administrator"
            )
        except Exception as e:
            raise RuntimeError(f"Scapy error: {e}")

    def _sniff_termux(self):
        """Fallback untuk Termux pake raw socket."""
        import socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            sock.settimeout(1.0)
            while not self._stop_event.is_set():
                try:
                    data, addr = sock.recvfrom(4096)
                    # UDP header: 8 bytes, IP header: 20 bytes
                    if len(data) > 28:
                        udp_dst_port = int.from_bytes(data[22:24], "big")
                        if udp_dst_port == 53:
                            dns_data = data[28:]
                            _parse_dns_socket(dns_data, addr[0], self.callback)
                except socket.timeout:
                    continue
        except Exception as e:
            raise RuntimeError(f"Socket error: {e}")


def get_interfaces():
    """Ambil list network interface yang tersedia."""
    interfaces = []
    try:
        if PLATFORM == "linux" or IS_TERMUX:
            import os
            net_path = "/sys/class/net"
            if os.path.exists(net_path):
                interfaces = os.listdir(net_path)
        elif PLATFORM == "windows":
            from scapy.all import get_if_list
            interfaces = get_if_list()
        elif PLATFORM == "darwin":
            from scapy.all import get_if_list
            interfaces = get_if_list()
    except Exception:
        pass
    return interfaces
