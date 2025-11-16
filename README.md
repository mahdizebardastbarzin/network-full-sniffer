# 🛰️ Network Sniffer – Full Packet Analysis Framework

A Complete Multi-Layer Network Traffic Analyzer (HTTP / DNS / TLS / ARP / Security Engine)

---

# 🇬🇧 English Documentation

## 🔵 Overview

This project is a **full-featured network traffic sniffer and analyzer**, built with Python and Scapy. It captures packets in real time, extracts protocol data, analyzes network behavior, detects suspicious activity, and generates professional **HTML + JSON reports**.

---

## ⚙️ Features

* Live Layer-2 and Layer-3 packet sniffing
* HTTP request analyzer (host, path, headers)
* DNS query analyzer
* TLS ClientHello parser (SNI extractor)
* ARP monitoring (spoofing detection)
* Security engine for attack detection
* Real-time terminal dashboard with colors
* Statistics engine (counters, top hosts, protocol map)
* Automatic professional report generator (HTML + JSON)
* Customizable template system

---

## 🖥️ Requirements

### 1) Python Version

Python 3.8+

### 2) Install Dependencies

```bash
pip install -r requirements.txt
```

### 3) Required on Windows: Install Npcap

Download from: [https://nmap.org/npcap/](https://nmap.org/npcap/)

During installation:

* Enable **"Install Npcap in WinPcap API-compatible Mode"**

Restart Windows after installation.

### 4) Using Scapy Without Npcap (Layer 3 Mode)

If Npcap is not installed, the sniffer will automatically run in **Layer-3 mode (IP)**.

---

## 📦 Project Structure

network-sniffer/
│
├── sniffer.py ← Core sniffer engine
├── analyzer_http.py ← HTTP analyzer
├── analyzer_dns.py ← DNS analyzer
├── analyzer_tls.py ← TLS SNI extractor
├── analyzer_arp.py ← ARP monitor
├── analyzer_security.py ← Attack detection
│
├── stats_engine.py ← Statistics engine
├── formatter_terminal.py ← Terminal dashboard
├── report_builder.py ← HTML + JSON report generator
│
├── requirements.txt
├── README.md
│
├── templates/
│ └── report_template.html
│
└── results/
├── report.json
└── report.html

---

## ▶️ How to Run

### Basic Run

```bash
python sniffer.py
```

### Choose Interface

```bash
python sniffer.py --iface eth0
```

### Save HTML + JSON Report

```bash
python sniffer.py --report
```

### Filter by Protocol

```bash
python sniffer.py --filter http
```

---

## 📄 Output Files

### 1) report.json

Full structured report for further analysis.

### 2) report.html

Dark-theme professional report:

* Summary
* HTTP
* DNS
* TLS/SNI
* ARP
* Security alerts

---

## 🔐 Security Features

* ARP Spoofing detection
* Suspicious TCP flags
* DNS abnormal behavior detection
* Flooding & high-frequency traffic detection

---

## 🛠️ Technologies Used

* Python
* Scapy
* Jinja2
* Rich / Colorama
* HTML / CSS

---

# 🇮🇷 مستندات فارسی

## 🟣 معرفی

این پروژه یک **اسنیفر کامل تحلیل ترافیک شبکه** است که با پایتون و Scapy ساخته شده است. ترافیک شبکه را به‌صورت زنده شنود می‌کند، پروتکل‌ها را تحلیل می‌کند و گزارش حرفه‌ای **HTML + JSON** تولید می‌کند.

---

## ⚙️ قابلیت‌ها

* اسنیفر لایه ۲ و لایه ۳
* تحلیل کامل HTTP
* تحلیل DNS
* استخراج SNI از TLS
* مانیتورینگ ARP و تشخیص ARP Spoofing
* موتور تشخیص حملات
* داشبورد رنگی در ترمینال
* موتور آمار پیشرفته
* تولید گزارش HTML و JSON
* سیستم قالب‌بندی قابل توسعه

---

## 🖥️ پیش‌نیازها

### ۱) نسخه پایتون

Python 3.8+

### ۲) نصب کتابخانه‌ها

```bash
pip install -r requirements.txt
```

### ۳) نصب Npcap در ویندوز

لینک دانلود: [https://nmap.org/npcap/](https://nmap.org/npcap/)

در هنگام نصب:

* گزینه **Install Npcap in WinPcap API-compatible Mode** را فعال کنید.

سپس ویندوز را ریستارت کنید.

### ۴) اجرا بدون Npcap (لایه ۳)

در صورت عدم نصب Npcap، اسنیفر روی **لایه ۳ (IP)** اجرا می‌شود.

---

## 📦 ساختار پروژه

network-sniffer/
│
├── sniffer.py ← هسته اسنیفر
├── analyzer_http.py ← تحلیل HTTP
├── analyzer_dns.py ← تحلیل DNS
├── analyzer_tls.py ← استخراج SNI
├── analyzer_arp.py ← مانیتورینگ ARP
├── analyzer_security.py ← تشخیص تهدید
│
├── stats_engine.py ← آمار و شمارنده‌ها
├── formatter_terminal.py ← داشبورد ترمینال
├── report_builder.py ← گزارش HTML + JSON
│
├── requirements.txt
├── README.md
│
├── templates/
│ └── report_template.html
│
└── results/
├── report.json
└── report.html

---

## ▶️ نحوه اجرا

### اجرای ساده

```bash
python sniffer.py
```

### انتخاب رابط شبکه

```bash
python sniffer.py --iface eth0
```

### ذخیره گزارش‌ها

```bash
python sniffer.py --report
```

### شنود پروتکل خاص

```bash
python sniffer.py --filter http
```

---

## 📄 خروجی‌ها

### report.json

خروجی کامل و ساخت‌یافته.

### report.html

گزارش حرفه‌ای با قالب تاریک شامل:

* خلاصه وضعیت
* بخش HTTP
* بخش DNS
* بخش TLS / SNI
* بخش ARP
* هشدارهای امنیتی

---

## 🔐 ویژگی‌های امنیتی

* تشخیص ARP Spoofing
* تشخیص فلگ‌های غیرعادی TCP
* تشخیص درخواست‌های مشکوک DNS
* تشخیص حملات Flood

---

## 🛠️ تکنولوژی‌های استفاده شده

* Python
* Scapy
* Jinja2
* Rich / Colorama
* HTML + CSS

---
## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guidelines](https://github.com/mahdizebardastbarzin/mahdizebardastbarzin/blob/main/CONTRIBUTING.md) to get started.

## 🤝 مشارکت

مشارکت‌های شما خوش‌آمد است! لطفاً [راهنمای مشارکت](https://github.com/mahdizebardastbarzin/mahdizebardastbarzin/blob/main/CONTRIBUTING.md) را مطالعه کنید.

## 📜 License

This project is provided for educational and research purposes.

