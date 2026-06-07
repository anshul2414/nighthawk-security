<div align="center">

<img src="https://img.shields.io/badge/Python-3.12-blue?style=for-the-badge&logo=python&logoColor=white"/>
<img src="https://img.shields.io/badge/Flask-3.0.3-black?style=for-the-badge&logo=flask&logoColor=white"/>
<img src="https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white"/>
<img src="https://img.shields.io/badge/Modules-30-00c896?style=for-the-badge"/>
<img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge"/>

<br/><br/>

<h1>🦅 NightHawk</h1>
<h3>Cybersecurity Intelligence Platform</h3>

<p><strong>30 offensive & defensive security modules in a single self-hosted dashboard.<br/>No login required. Clone, run, and start scanning in under 60 seconds.</strong></p>

<a href="https://anshul2414.github.io/nighthawk-security">🌐 Live Demo</a> &nbsp;·&nbsp;
<a href="#-quick-start">🚀 Quick Start</a> &nbsp;·&nbsp;
<a href="#-modules">📦 30 Modules</a> &nbsp;·&nbsp;
<a href="#-docker">🐳 Docker</a>

</div>

---

## ✨ Overview

**NightHawk** is a powerful, self-hosted cybersecurity intelligence platform built with Python & Flask. Designed for **penetration testers**, **ethical hackers**, and **security researchers** — it packs 30 active security scanning modules into one sleek web dashboard.

> Built by [Anshul](https://github.com/anshul2414) — Penetration Tester & Certified Ethical Hacker (CEH)

---

## 📦 Modules (30 Total)

### 🔵 Core Reconnaissance — 16 Modules

| Module | Description |
|--------|-------------|
| **URL Check** | URL safety, redirects & response metadata |
| **Port Scanner** | TCP port scanning with service detection |
| **DNS Lookup** | Full enumeration — A, MX, NS, TXT, AAAA |
| **SSL Inspector** | Certificate chain, expiry, cipher suite |
| **WHOIS Lookup** | Domain registration & ownership |
| **Tech Detect** | Web technologies, frameworks & CMS |
| **Email Security** | SPF, DKIM, DMARC validation |
| **Security Headers** | HSTS, CSP, X-Frame-Options audit |
| **CORS Analyzer** | Cross-Origin misconfiguration check |
| **WAF Detect** | Web Application Firewall fingerprinting |
| **Subdomain Enum** | Passive subdomain discovery |
| **IP Geolocation** | ASN, ISP, geo & threat data |
| **Hash Tools** | MD5, SHA-1, SHA-256/512 generation |
| **Password Analyzer** | Strength scoring & entropy |
| **Robots.txt Parser** | Hidden paths & disallowed resources |
| **CVE Search** | CVE database vulnerability intelligence |

### 🔴 Advanced Offensive — 14 Modules

| Module | Description |
|--------|-------------|
| **Traceroute** | Network path tracing & hop latency |
| **Dir Fuzzer** | Directory & endpoint brute-force |
| **XSS / SQLi / LFI Scanner** | Automated injection vulnerability scanner |
| **Open Redirect** | Open redirect chain detection |
| **Cookie Analyzer** | HttpOnly, Secure, SameSite audit |
| **JWT Analyzer** | Decode, audit & fuzz JWT tokens |
| **TLS Deep Scan** | TLS version, ciphers & pinning |
| **Firewall Detect** | Active firewall & IDS/IPS detection |
| **Email Header Forensics** | Header trace & spoofing analysis |
| **CIDR Scanner** | Bulk IP range scanning |
| **Banner Grabber** | Service banner fingerprinting |
| **API Security Tester** | REST/GraphQL endpoint enumeration |
| **Network Fingerprinter** | OS & service stack detection |
| **SSRF / Cloud Probe** | SSRF detection & cloud metadata testing |

---

## 🚀 Quick Start

```bash
git clone https://github.com/anshul2414/nighthawk-security.git
cd nighthawk-security
pip install -r requirements.txt
python app.py
# Open → http://localhost:5000
```

---

## 🐳 Docker

```bash
docker-compose up -d
# Open → http://localhost:8080
```

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | Python 3.12, Flask 3.0 |
| **Frontend** | Vanilla JS, Chart.js, Font Awesome, Geist UI |
| **Database** | SQLite (scan history) |
| **Server** | Gunicorn (production) |
| **Container** | Docker + Docker Compose |

---

## 📁 Structure

```
nighthawk-security/
├── app.py                  # Core — 30 security modules
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── run.bat                 # Windows launcher
└── templates/
    └── index.html          # Dashboard UI
```

---

## ⚠️ Legal Disclaimer

> For **authorized security testing and educational purposes only.**  
> Never scan systems you do not own or have explicit written permission to test.

---

## 📬 Contact

**Anshul** — Penetration Tester & Certified Ethical Hacker

| | |
|--|--|
| 💼 LinkedIn | [linkedin.com/in/anshul-9800a3275](https://linkedin.com/in/anshul-9800a3275) |
| 🐙 GitHub | [github.com/anshul2414](https://github.com/anshul2414) |
| 🎯 TryHackMe | [tryhackme.com/p/anshul28054](https://tryhackme.com/p/anshul28054) |
| 📱 Phone | +91-8091402414 |

---

<div align="center">

⭐ **Star this repo if NightHawk helps your security work!**

Made with ❤️ by [Anshul](https://github.com/anshul2414)

</div>
