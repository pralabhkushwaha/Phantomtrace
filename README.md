# PhantomTrace v2.1.0
**Professional Phishing Detection & Cyber Fraud Intelligence Platform**  
*Built for UP Police Cyber Cell — Uttar Pradesh, India*

---

## What's New in v2.1.0

### ✅ Upgraded Modules
| Module | What Changed |
|--------|-------------|
| **Indian Scam Scanner** | Rebuilt from scratch — 12 scam categories, 100+ regex patterns, severity scoring, dedicated `/api/indian-scam/analyze` endpoint |
| **IP Intelligence** | Added AbuseIPDB (abuse score + reports), AlienVault OTX (threat pulses), Shodan (ports + CVEs) enrichment |
| **Domain Intelligence** | **NEW** — WHOIS/RDAP, DNS records (A/MX/NS/TXT), SSL certificate analysis, Shodan port data, risk scoring |

### ✅ New Indian Scam Categories (all in English)
1. **Digital Arrest Scam** — CBI/ED/Interpol/TRAI impersonation, "stay on call", digital arrest
2. **UPI Payment Fraud** — QR-to-receive tricks, PIN entry on Google Pay/PhonePe/Paytm
3. **KYC / Banking Fraud** — Fake SBI/HDFC/ICICI/RBI alerts, Aadhaar/PAN verification hooks
4. **WhatsApp APK Scam** — Remote access tools (AnyDesk), malicious APK distribution
5. **SIM Swap Fraud** — TRAI notices, number porting, OTP on old SIM
6. **Loan App Harassment** — Data threats (contacts/gallery), recovery agent threats
7. **OLX / Classifieds Scam** — Army/defence seller impersonation, advance payment
8. **Investment / Trading Scam** — Telegram groups, guaranteed returns, SEBI fake claims
9. **OTP / Credential Phishing** — ATM PIN, MPIN, net banking credential extraction
10. **Fear & Authority Manipulation** — Court notices, warrant threats, asset seizure
11. **Fake Job / Task Scam** — YouTube like tasks, deposit-to-start, WFH earning scams
12. **Urgency Pressure** — Time-limit tactics, "within 30 minutes" pressure

---

## Project Structure

```
phantomtrace/
├── backend/
│   ├── app/
│   │   ├── main.py                    # FastAPI app — v2.1.0
│   │   ├── core/
│   │   │   ├── indian_scam_analyzer.py  ← NEW: 12-category scam engine
│   │   │   ├── domain_intel.py          ← NEW: WHOIS/DNS/SSL/Shodan
│   │   │   ├── url_analyzer.py          (VirusTotal, URLHaus, PhishTank, GSB, OTX, AbuseIPDB, urlscan.io)
│   │   │   ├── malware_detector.py      (MalwareBazaar, PE analysis, APK patterns)
│   │   │   ├── phone_upi_osint.py
│   │   │   └── ...
│   │   └── routers/
│   │       ├── indian_scam_routes.py    ← NEW: /api/indian-scam/analyze
│   │       ├── domain_routes.py         ← NEW: /api/domain/analyze
│   │       ├── ip_intel_routes.py       ← UPGRADED: +AbuseIPDB, OTX, Shodan
│   │       └── ...
│   └── .env.example
└── frontend/
    └── src/
        ├── pages/
        │   ├── DomainIntelligence.jsx   ← NEW
        │   ├── IndianScamScanner.jsx    ← REBUILT v2
        │   ├── IPIntelligence.jsx       ← UPGRADED
        │   └── ...
        └── components/
            └── Sidebar.jsx              ← Updated — 14 modules
```

---

## Setup

### Backend
```bash
cd backend
pip install -r requirements.txt
cp .env.example .env
# Fill in API keys in .env
uvicorn app.main:app --reload --port 8000
```

### Frontend
```bash
cd frontend
npm install
cp .env.example .env
# Set VITE_API_URL=http://localhost:8000
npm run dev
```

---

## API Keys (all free tiers available)

| Key | Service | Free Tier | Get It |
|-----|---------|-----------|--------|
| `VIRUSTOTAL_API_KEY` | URL/hash reputation | 4 req/min | virustotal.com |
| `ABUSEIPDB_API_KEY` | IP abuse reports | 1000/day | abuseipdb.com |
| `OTX_API_KEY` | Threat intelligence | Unlimited | otx.alienvault.com |
| `URLSCAN_API_KEY` | URL screenshot+scan | 100/day | urlscan.io |
| `GOOGLE_SAFE_BROWSING_API_KEY` | URL blocklist | Free | developers.google.com |
| `WHOISXML_API_KEY` | WHOIS enrichment | 500/month | whoisxmlapi.com |
| `SHODAN_API_KEY` | Port/CVE scanning | Free (limited) | shodan.io |
| `NUMVERIFY_API_KEY` | Phone validation | 100/month | numverify.com |

**All modules work without API keys** using heuristic analysis. API keys add live threat intelligence.

---

## All 14 Modules

**Investigation Modules**  
Dashboard · Email Forensics · Homograph Detector · URL Intelligence · Domain Intelligence · Fraud Detection · Malware Detection

**India OSINT**  
Indian Scam Scanner (12 categories) · Phone & UPI OSINT · IP Intelligence · Social Media OSINT

**Case Management**  
Cases & FIR Tracking · Risk Assessment · History

---

*PhantomTrace v2.1.0 — UP Police Cyber Cell OSINT Platform*
