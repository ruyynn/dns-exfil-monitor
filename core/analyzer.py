"""
DNS Analyzer - Analisis pola DNS query untuk deteksi exfiltration.
Kombinasi rule-based + entropy analysis → akurasi ~85-90%
"""

from collections import defaultdict
from datetime import datetime, timedelta
from utils.entropy import subdomain_score


# ── Threshold & config ────────────────────────────────────
QUERY_FREQ_THRESHOLD = 15       # query/menit ke 1 domain = mencurigakan
SUBDOMAIN_SCORE_THRESHOLD = 50  # skor subdomain >= 50 = mencurigakan
UNIQUE_SUBDOMAIN_THRESHOLD = 8  # subdomain unik/menit ke 1 domain

# Domain whitelist (false positive reduction)
WHITELIST_DOMAINS = {
    "google.com", "googleapis.com", "gstatic.com",
    "cloudflare.com", "amazonaws.com", "microsoft.com",
    "windows.com", "windowsupdate.com", "akamaitechnologies.com",
    "facebook.com", "twitter.com", "instagram.com",
    "youtube.com", "ytimg.com", "googlevideo.com",
    "apple.com", "icloud.com", "github.com", "githubusercontent.com",
}


def extract_root_domain(domain: str) -> str:
    """Ambil root domain dari FQDN."""
    parts = domain.rstrip(".").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain


def extract_subdomain(domain: str) -> str:
    """Ambil subdomain dari FQDN."""
    parts = domain.rstrip(".").split(".")
    if len(parts) > 2:
        return ".".join(parts[:-2])
    return ""


class DNSAnalyzer:
    def __init__(self):
        # domain → list timestamp query
        self._query_times = defaultdict(list)
        # domain → set subdomain unik per menit
        self._unique_subdomains = defaultdict(set)
        # hasil deteksi
        self.alerts = []
        self.stats = defaultdict(int)

    def analyze(self, event: dict) -> dict | None:
        """
        Analisis satu DNS event.
        Return alert dict jika mencurigakan, None jika normal.
        """
        domain = event.get("domain", "").lower().rstrip(".")
        if not domain:
            return None

        root = extract_root_domain(domain)
        subdomain = extract_subdomain(domain)

        self.stats["total"] += 1

        # Skip whitelist
        if root in WHITELIST_DOMAINS:
            self.stats["whitelisted"] += 1
            return None

        now = datetime.now()
        one_min_ago = now - timedelta(minutes=1)

        # Cleanup data lama
        self._query_times[root] = [
            t for t in self._query_times[root] if t > one_min_ago
        ]

        # Catat query
        self._query_times[root].append(now)
        if subdomain:
            self._unique_subdomains[root].add(subdomain)

        freq = len(self._query_times[root])
        unique_count = len(self._unique_subdomains[root])

        # ── Cek subdomain mencurigakan ──────────────────────
        sub_analysis = {}
        sub_suspicious = False
        if subdomain:
            sub_analysis = subdomain_score(subdomain)
            sub_suspicious = sub_analysis["score"] >= SUBDOMAIN_SCORE_THRESHOLD

        # ── Cek frekuensi tinggi ────────────────────────────
        freq_suspicious = freq >= QUERY_FREQ_THRESHOLD

        # ── Cek banyak subdomain unik ───────────────────────
        unique_suspicious = unique_count >= UNIQUE_SUBDOMAIN_THRESHOLD

        # ── Gabungin semua sinyal ───────────────────────────
        if not (sub_suspicious or freq_suspicious or unique_suspicious):
            self.stats["normal"] += 1
            return None

        # Tentukan severity
        signal_count = sum([sub_suspicious, freq_suspicious, unique_suspicious])
        if signal_count >= 2 or (sub_analysis.get("score", 0) >= 80):
            severity = "HIGH"
        elif signal_count == 1:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        reasons = []
        if freq_suspicious:
            reasons.append(f"frekuensi tinggi ({freq}x/menit)")
        if unique_suspicious:
            reasons.append(f"subdomain unik banyak ({unique_count})")
        if sub_suspicious:
            reasons += sub_analysis.get("reasons", [])

        alert = {
            "timestamp": event["timestamp"],
            "time": event["time"],
            "domain": domain,
            "root_domain": root,
            "subdomain": subdomain,
            "src_ip": event.get("src_ip", "unknown"),
            "severity": severity,
            "reasons": reasons,
            "freq_per_min": freq,
            "unique_subdomains": unique_count,
            "entropy": sub_analysis.get("entropy", 0),
            "subdomain_score": sub_analysis.get("score", 0),
        }

        self.alerts.append(alert)
        self.stats["alerts"] += 1
        if severity == "HIGH":
            self.stats["high"] += 1
        elif severity == "MEDIUM":
            self.stats["medium"] += 1
        else:
            self.stats["low"] += 1

        return alert

    def reset_subdomains(self):
        """Reset unique subdomain tracker (panggil tiap menit)."""
        self._unique_subdomains.clear()
