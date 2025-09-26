# Portable OSINT Tool

[![Build Status](https://img.shields.io/github/actions/workflow/status/your-org/portable-osint-tool/ci.yml?branch=main)](https://github.com/your-org/portable-osint-tool/actions)  
[![License](https://img.shields.io/github/license/your-org/portable-osint-tool)](LICENSE)  
[![Version](https://img.shields.io/github/v/release/your-org/portable-osint-tool)](https://github.com/your-org/portable-osint-tool/releases)  
[![Contributions welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](CONTRIBUTING.md)

The **Portable OSINT Tool** is an all-in-one, investigator-focused platform designed to gather, analyze, and visualize open-source intelligence (OSINT). Built with portability, security, and efficiency in mind, it enables researchers, analysts, and investigators to work effectively both online and offline.

---

## 🚀 Features

### Core OSINT Data Sources
- **Domains / Infrastructure**
  - WHOIS & RDAP queries  
  - Subdomain enumeration  
  - Passive DNS & reverse IP lookups  

- **IP Intelligence**
  - Geolocation  
  - Threat/abuse reports (AbuseIPDB, OTX, VirusTotal)  
  - Lightweight port scanning  

- **File / Metadata Analysis**
  - EXIF extraction  
  - Document metadata parsing  
  - Hash lookups  
  - YARA rule scanning  

- **Vehicle / Registry Data**
  - VIN decoding (NHTSA vPIC)  
  - License plate lookups (DVLA & APIs)  
  - MOT / inspection history  

- **Social Media & Username Intelligence**
  - Username availability checker  
  - Public profile scraping  
  - Archived content lookup  

- **Dark Web / Paste Sites**
  - Onion keyword search (via Tor)  
  - Pastebin / Ghostbin monitoring  
  - Leak site scraping  

---

### 🤖 AI-Enhanced Capabilities
- Automated **data validation & cross-corroboration**  
- Entity extraction & graphing of names, emails, IPs, domains, and phone numbers  
- Lead generation: AI suggests new pivot points for investigation  
- Clustering & similarity detection of related documents/accounts/infrastructure  
- AI-assisted reporting with summaries & confidence scoring  

---

### 📊 Visualization & Reporting
- Interactive graph view of entities and connections  
- Timeline view of events and activity  
- Export reports as **PDF, HTML, or Markdown**  
- Tagging system for organizing findings  

---

### 🔒 Security & Portability
- Encrypted local database (SQLCipher)  
- Encrypted API key vault  
- Full audit logging of all actions  
- Air-gapped / offline mode support  

---

### 🛠 Investigator Utilities
- Regex search for emails, phone numbers, crypto addresses  
- Automatic enrichment of links with threat intel & metadata  
- Quick search hub (Google Dorking, Shodan, Censys, etc.)  
- Case management system to group queries and results per project  

---

### 🧩 Advanced Add-ons (Stretch Goals)
- Geospatial mapping of IPs, EXIF data, and addresses  
- Portable mini-Tor browser integration  
- Offline intelligence packs (breach corpuses, CT logs)  
- Machine vision: OCR & object/logo detection in images  

---

## 📦 Installation

```bash
# Example setup (to be updated)
git clone https://github.com/your-org/portable-osint-tool.git
cd portable-osint-tool
pip install -r requirements.txt
