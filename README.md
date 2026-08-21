# ⚡ WEBTRACE

<div align="center">

![License](https://img.shields.io/badge/License-Apache--2.0-blue.svg?style=for-the-badge)
![Vercel](https://img.shields.io/badge/Frontend-Vercel-000000?style=for-the-badge&logo=vercel&logoColor=white)
![Cloudflare Workers](https://img.shields.io/badge/Backend-Cloudflare_Workers-F38020?style=for-the-badge&logo=cloudflare&logoColor=white)
![TypeScript](https://img.shields.io/badge/Language-TypeScript-3178C6?style=for-the-badge&logo=typescript&logoColor=white)
![Gemini AI](https://img.shields.io/badge/AI-Gemini_2.5_Flash-8E75B2?style=for-the-badge&logo=googlegemini&logoColor=white)

<br />

**Real-time OSINT Domain Intelligence & Attack Surface Analyzer.**

[🌐 **Live Demo (Frontend)**](https://frontend-theta-seven-61.vercel.app) • [⚡ **Edge API (Worker)**](https://webtrace.phish-x.workers.dev)

</div>

---

## 🎯 What is WEBTRACE?

**WEBTRACE** is a high-speed domain reconnaissance tool that queries multiple intelligence sources in parallel (DNS, RDAP WHOIS, SSL logs, Shodan, threat feeds, and Wayback history) and generates an executive AI security brief using Google Gemini.

### 🌐 Live URLs

- **Frontend App (Vercel):** [https://frontend-theta-seven-61.vercel.app](https://frontend-theta-seven-61.vercel.app)
- **API Endpoint (Cloudflare Worker):** [https://webtrace.phish-x.workers.dev/api/analyze](https://webtrace.phish-x.workers.dev/api/analyze)

---

## 🔄 Architecture

```mermaid
flowchart TD
    A[Client Browser] -->|POST /api/analyze| B[Cloudflare Worker / Hono]
    
    B --> C1[DNS & Network Topology]
    B --> C2[Domain & IP WHOIS]
    B --> C3[SSL / TLS & CT Logs]
    B --> C4[Shodan Exposure & Ports]
    B --> C5[Threat Intel Feeds]
    B --> C6[Wayback Machine History]
    
    C1 --> D[Gemini 2.5 Flash Summary]
    C2 --> D
    C3 --> D
    C4 --> D
    C5 --> D
    C6 --> D
    
    D --> E[Full Analysis JSON]
    E --> A
```

---

## ✨ Features

- **🌐 DNS & Topology:** `A`, `AAAA`, `MX`, `TXT`, `NS`, `SOA`, `CAA` records via Cloudflare DoH, plus PTR reverse DNS and CDN detection.
- **🛡️ Email Security:** SPF (`v=spf1`), DMARC (`_dmarc`), and common DKIM selector checks.
- **📜 RDAP WHOIS:** Domain age, registrar details, nameservers, and ARIN network CIDR/ASN.
- **🔒 SSL Analysis:** Cert validity, expiry countdown, SANs coverage, and free CA detection.
- **🎯 Open Ports & CVEs:** Shodan InternetDB lookup for open ports, CPEs, and known vulnerabilities.
- **🔎 Subdomain Discovery:** Enumerates subdomains from CT logs and flags high-value targets (`admin`, `vpn`, `staging`).
- **🚨 Multi-Engine Threat Intel:** Aggregates OTX, AbuseIPDB, ThreatFox, GreyNoise, and URLhaus into a single verdict (`CLEAN`, `SUSPICIOUS`, `MALICIOUS`).
- **🤖 AI Security Brief:** 3–4 sentence plain-English summary powered by **Gemini 2.5 Flash**.

---

## 💻 Tech Stack

- **Frontend:** React 19, TypeScript, Vite, TailwindCSS, Lucide Icons, Framer Motion — *Hosted on Vercel*
- **Backend:** TypeScript, Hono v4, Cloudflare Workers (Edge Serverless) — *Hosted on Cloudflare*

---

## 🚀 Quickstart

### 1. Run Backend Worker Locally
```bash
cd backend-worker
npm install
npm run dev
# Running on http://localhost:8787
```

### 2. Run Frontend Locally
```bash
cd frontend
npm install
npm run dev
# Running on http://localhost:5173
```

---

## 📡 API Example

```bash
curl -X POST "https://webtrace.phish-x.workers.dev/api/analyze" \
  -H "Content-Type: application/json" \
  -d '{"url": "google.com"}'
```

---

## ⚖️ License

Distributed under the **Apache 2.0 License**. For authorized cybersecurity research and testing only.
