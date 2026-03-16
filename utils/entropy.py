"""
Entropy & string analysis utilities untuk deteksi DNS exfiltration.
"""

import math
import re
from collections import Counter


def shannon_entropy(data: str) -> float:
    """
    Hitung Shannon entropy dari string.
    Makin tinggi = makin random = makin mencurigakan.
    Normal domain: ~2.5-3.5
    Exfil domain:  ~4.5-6.0
    """
    if not data:
        return 0.0
    counter = Counter(data.lower())
    length = len(data)
    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in counter.values()
    )
    return round(entropy, 4)


def is_base64_like(s: str) -> bool:
    """Cek apakah string mirip base64."""
    base64_pattern = re.compile(r'^[A-Za-z0-9+/=\-_]{8,}$')
    return bool(base64_pattern.match(s)) and len(s) >= 8


def is_hex_like(s: str) -> bool:
    """Cek apakah string mirip hex encoding."""
    hex_pattern = re.compile(r'^[0-9a-fA-F]{8,}$')
    return bool(hex_pattern.match(s))


def subdomain_score(subdomain: str) -> dict:
    """
    Skor kecurigaan subdomain (0-100).
    Semakin tinggi = semakin mencurigakan.
    """
    score = 0
    reasons = []

    entropy = shannon_entropy(subdomain)

    # Entropy tinggi
    if entropy > 4.5:
        score += 40
        reasons.append(f"entropy tinggi ({entropy})")
    elif entropy > 3.8:
        score += 20
        reasons.append(f"entropy medium ({entropy})")

    # Panjang subdomain
    if len(subdomain) > 40:
        score += 30
        reasons.append(f"subdomain sangat panjang ({len(subdomain)} chars)")
    elif len(subdomain) > 25:
        score += 15
        reasons.append(f"subdomain panjang ({len(subdomain)} chars)")

    # Base64 atau hex
    if is_base64_like(subdomain):
        score += 20
        reasons.append("mirip base64")
    if is_hex_like(subdomain):
        score += 20
        reasons.append("mirip hex")

    # Banyak angka
    digit_ratio = sum(c.isdigit() for c in subdomain) / max(len(subdomain), 1)
    if digit_ratio > 0.4:
        score += 10
        reasons.append(f"banyak angka ({digit_ratio:.0%})")

    # Karakter unik terlalu banyak
    unique_ratio = len(set(subdomain.lower())) / max(len(subdomain), 1)
    if unique_ratio > 0.7:
        score += 10
        reasons.append("karakter sangat beragam")

    return {
        "score": min(score, 100),
        "entropy": entropy,
        "reasons": reasons,
        "length": len(subdomain),
    }
