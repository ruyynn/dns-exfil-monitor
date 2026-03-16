# DNS Exfiltration Monitor 🔍

**Deteksi pencurian data lewat DNS secara realtime**

[![Python](https://img.shields.io/badge/Python-3.8+-blue)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS%20%7C%20Termux-orange)]()
[![License](https://img.shields.io/badge/License-MIT-lightgrey)]()
[![Author](https://img.shields.io/badge/Author-Ruyynn-cyan)](https://github.com/ruyynn)

---

## 🔎 Apa itu DNS Exfiltration?

DNS Exfiltration adalah teknik hacker mencuri data lewat DNS query yang terlihat normal oleh firewall. Data di-encode di subdomain dan dikirim pelan-pelan ke server attacker:

```
dGhpcyBpcyBzZWNyZXQ.attacker.com  ← data tersembunyi di subdomain
aGVsbG8gd29ybGQ.attacker.com
```

Tools ini mendeteksi pola mencurigakan tersebut secara realtime.

---

## ✨ Fitur

- 🔍 **Realtime monitoring** DNS traffic
- 📊 **Shannon entropy analysis** — deteksi subdomain ter-encode
- 📈 **Frequency analysis** — deteksi query berulang ke satu domain
- 🎯 **Rule-based detection** — akurasi ~85-90%
- 🖥️ **Cross-platform** — Linux, Windows, macOS, Termux
- 📝 **Auto logging** — JSON & TXT log harian
- 🎨 **Dashboard CLI**

---

## 🛠️ Instalasi

```bash
git clone https://github.com/ruyynn/dns-exfil-monitor.git
cd dns-exfil-monitor
pip install -r requirements.txt
```

---

## 🚀 Cara Pakai

```bash
# Linux / macOS / Kali
sudo python3 main.py

# Interface spesifik
sudo python3 main.py -i eth0
sudo python3 main.py -i wlan0

# Lihat interface tersedia
sudo python3 main.py --list-interfaces

# Custom threshold (default: 15 query/menit)
sudo python3 main.py --threshold 10

# Windows (jalankan sebagai Administrator)
python main.py

# Termux
python main.py
```

---

## 📊 Cara Deteksi

| Metode | Deskripsi |
|--------|-----------|
| **Shannon Entropy** | Subdomain random/encoded punya entropy tinggi (>4.5) |
| **Frequency Check** | >15 query/menit ke 1 domain = mencurigakan |
| **Subdomain Length** | Subdomain >40 karakter = red flag |
| **Base64/Hex Check** | Pola encoding umum dideteksi otomatis |
| **Unique Subdomain** | >8 subdomain unik/menit ke 1 domain |

---

## ⚠️ Disclaimer

Tools ini untuk **edukasi dan monitoring jaringan sendiri**. Gunakan secara bertanggung jawab dan hanya pada jaringan yang Anda miliki atau memiliki izin eksplisit.

---

## 🤝 Kontribusi

PR dan issues sangat diterima!

---

*Made with ❤️ in 🇮🇩 by Ruyynn*
