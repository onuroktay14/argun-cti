# 🛡️ ARGUN CTI — Cyber Threat Intelligence Platform

**AI-Powered Threat Intelligence Dashboard by [ARGUN Security](https://www.argunsec.com)**

> Clear Vision, Absolute Security

[![GitHub Actions](https://github.com/onuroktay14/argun-cti/actions/workflows/update_data.yml/badge.svg)](https://github.com/onuroktay14/argun-cti/actions)
[![Live](https://img.shields.io/badge/Live-cti.argunsec.com-00e5ff)](https://cti.argunsec.com)

---

## 🎯 Nedir?

ARGUN CTI, birden fazla açık kaynak tehdit istihbarat kaynağından veri toplayarak, **ARGUN Threat Score (ATS)** algoritmasıyla önceliklendiren, gerçek zamanlı bir siber tehdit istihbarat platformudur.

**Klasik CVE listelerinin ötesine geçerek:**
- Hangi zafiyet **aktif olarak sömürülüyor**?
- Hangisi için **public PoC** mevcut?
- İnfosec topluluğu **hangi CVE'yi konuşuyor**?
- Hangi **IP adresleri** şu anda tehdit oluşturuyor?

## 🏗️ Mimari

```
GitHub Actions (2 saatte bir)
├── NVD API 2.0 → CVE verileri
├── CISA KEV → Bilinen exploit'ler
├── FIRST EPSS → Exploit olasılık skorları
├── FediSecFeeds → Fediverse sosyal sinyaller
├── GitHub Search → PoC & Nuclei template tespiti
├── 8+ IP Feed → Kötücül IP agregasyonu
└── Enrichment → MITRE ATT&CK + ATS Scoring
         ↓
    data/*.json (GitHub Pages)
         ↓
    Static Frontend (SPA)
```

## 🧮 ARGUN Threat Score (ATS)

0-100 arası composite risk skoru:

| Boyut | Max Puan | Kaynak |
|-------|----------|--------|
| Teknik Ciddiyet | 30 | CVSS base score |
| Exploit Olasılığı | 25 | EPSS score |
| Silahlandırma | 20 | KEV + PoC + Nuclei |
| Sosyal Sinyal | 15 | Fediverse post/repo sayısı |
| Zaman Faktörü | 10 | Yayınlanma tarihi |

| ATS | Seviye | Aksiyon |
|-----|--------|---------|
| 80-100 | 🔴 CRITICAL | Acil patch/mitigasyon |
| 60-79 | 🟠 HIGH | 24 saat içinde değerlendir |
| 40-59 | 🟡 MEDIUM | Planlı patch döngüsü |
| 20-39 | 🔵 LOW | Takipte tut |
| 0-19 | ⚪ INFO | Bilgi amaçlı |

## 📡 Veri Kaynakları

### CVE & Vulnerability
- **NVD** — NIST National Vulnerability Database (API 2.0)
- **CISA KEV** — Known Exploited Vulnerabilities Catalog
- **FIRST EPSS** — Exploit Prediction Scoring System
- **FediSecFeeds** — Fediverse CVE social intelligence
- **GitHub** — PoC repository & Nuclei template detection

### IP Threat Intelligence
- **stamparm/ipsum** — 30+ blacklist aggregation
- **abuse.ch** — Feodo Tracker, SSL Blacklist, URLhaus
- **Blocklist.de** — Brute force / DDoS IPs
- **Emerging Threats** — Proofpoint threat IPs
- **CINS Army** — Sentinel-based threat data
- **Binary Defense** — Artillery threat feed

## 🚀 Kurulum

### 1. Repository'yi fork/clone edin

```bash
git clone https://github.com/onuroktay14/argun-cti.git
cd argun-cti
pip install -r requirements.txt
```

### 2. Pipeline'ı çalıştırın

```bash
python main.py
```

### 3. GitHub Pages'i aktif edin

Settings → Pages → Source: `main` branch → Save

### 4. Custom domain (opsiyonel)

DNS'te CNAME kaydı ekleyin:
```
cti.argunsec.com → onuroktay14.github.io
```

### 5. GitHub Secrets (opsiyonel ama önerilen)

| Secret | Açıklama |
|--------|----------|
| `NVD_API_KEY` | NVD API rate limit artışı (50 req/30s) |

## 📊 API Endpoints

Tüm veriler JSON olarak açık erişimlidir:

| Endpoint | Açıklama |
|----------|----------|
| `data/cve_feed.json` | CVE feed (ATS ile sıralı) |
| `data/ip_blacklist.json` | IP kara liste (enriched) |
| `data/stats.json` | Dashboard istatistikleri |
| `data/blacklist.txt` | Firewall-ready IP listesi |

## 📁 Proje Yapısı

```
argun-cti/
├── .github/workflows/
│   └── update_data.yml     # GitHub Actions pipeline
├── collectors/
│   ├── nvd_collector.py    # NVD API 2.0
│   ├── kev_collector.py    # CISA KEV
│   ├── epss_collector.py   # FIRST EPSS
│   ├── fedi_collector.py   # FediSecFeeds + Mastodon
│   ├── poc_collector.py    # GitHub PoC & Nuclei
│   └── ip_collector.py     # IP blacklist aggregation
├── enrichment/
│   ├── ats_scorer.py       # ARGUN Threat Score
│   └── mitre_mapper.py     # CWE → MITRE ATT&CK
├── output/
│   └── json_generator.py   # JSON output files
├── data/                   # Generated data (auto-updated)
│   ├── cve_feed.json
│   ├── ip_blacklist.json
│   ├── stats.json
│   └── blacklist.txt
├── index.html              # Frontend dashboard
├── main.py                 # Pipeline orchestrator
├── requirements.txt
├── CNAME                   # Custom domain
└── README.md
```

## 🔗 İlişkili Projeler

- [SOCNova](https://github.com/onuroktay14) — AI-Powered Security Operations Center
- [ARGUN Security](https://www.argunsec.com) — Comprehensive Cybersecurity Services

## 📜 Lisans

MIT License — Özgürce kullanabilir, değiştirebilir ve dağıtabilirsiniz.

## 👤 Geliştirici

**Onur Oktay** — Senior Cyber Security Engineer  
[LinkedIn](https://www.linkedin.com/in/onuroktaycom/) | [ARGUN Security](https://www.argunsec.com)

---

*ARGUN Security — Clear Vision, Absolute Security*
