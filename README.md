# 🛡️ PhantomTrace

A professional phishing detection, email forensics, and fraud intelligence platform for cybersecurity analysts. Investigate suspicious emails, malicious URLs, brand impersonation attacks, homograph domains, and online fraud attempts — with explainable, evidence-based risk scoring.

> ⚠️ PhantomTrace never claims absolute attribution of an attacker. All findings include confidence scores and supporting evidence so investigators can make informed judgments.

---

## ✨ Features

| Module | What it does |
|---|---|
| **Email Header Forensics** | Parses `.eml` files / pasted headers. Checks SPF, DKIM, DMARC, Reply-To mismatch, Return-Path mismatch, display-name spoofing, Received-chain hop analysis, originating IP extraction. |
| **Homograph & Brand Impersonation** | Detects Unicode/punycode spoofing, mixed-script tricks, digit substitution (`g00gle.com`), and compound attack domains (`faceb00k-login.com`, `linkedln-login.com`) against 50+ known brands (tech, payments, Indian banks, government). |
| **URL Intelligence** | HTTPS check, suspicious TLDs, URL shorteners, IP-literal URLs, redirect-chain following, domain age (RDAP), and reputation aggregation across VirusTotal + URLHaus + PhishTank. |
| **Fraud / Content Detection** | Regex-based detector for urgency tactics, fear tactics, fake rewards, credential theft, OTP requests, banking/KYC scams, and APK download scams (English + Hinglish phrasing). |
| **Attachment Analyzer** | Flags dangerous extensions, double-extension tricks (`Invoice.pdf.exe`), and MIME-type mismatches. |
| **Risk Scoring Engine** | Aggregates every module into one explainable 0–100 score with a Low/Medium/High/Critical rating. |
| **Prevention Engine** | Auto-generates a prioritised, context-aware action checklist tailored to what was actually found. |
| **Investigation History** | Every analysis is persisted to SQLite and browsable/searchable later. |

---

## 🏗️ Tech Stack

- **Frontend:** React 18 + Vite + Tailwind CSS (dark cyber/SOC theme)
- **Backend:** FastAPI (Python) + SQLAlchemy
- **Database:** SQLite (zero-config, file-based)
- **Deployment:** Frontend → Netlify · Backend → Render

---

## 📁 Project Structure

```
phantomtrace/
├── backend/
│   ├── app/
│   │   ├── core/                  # All detection engines
│   │   │   ├── header_analyzer.py     # .eml parsing, SPF/DKIM/DMARC
│   │   │   ├── attribution.py         # IP geo / ASN / registrar lookup
│   │   │   ├── homograph.py           # Unicode/typosquat detector
│   │   │   ├── brand_list.py          # Known brand domains reference
│   │   │   ├── content_analyzer.py    # Social-engineering pattern detector
│   │   │   ├── attachment_analyzer.py # Dangerous attachment detector
│   │   │   ├── url_analyzer.py        # URL reputation & intelligence
│   │   │   ├── risk_engine.py         # Aggregate risk scoring
│   │   │   ├── prevention.py          # Recommendation generator
│   │   │   ├── analyzer.py            # Orchestrates all modules
│   │   │   └── dns_utils.py           # DNS-over-HTTPS / RDAP / IP-geo helpers
│   │   ├── routers/                # FastAPI route handlers
│   │   ├── models.py               # SQLAlchemy models
│   │   ├── database.py             # DB session/engine setup
│   │   └── main.py                 # FastAPI app entrypoint
│   ├── requirements.txt
│   └── .env.example
├── frontend/
│   ├── src/
│   │   ├── api/client.js           # Axios API client
│   │   ├── components/             # Sidebar, Header, shared UI components
│   │   ├── pages/                  # Dashboard, Email Forensics, Homograph, URL, Fraud, Risk, History
│   │   ├── App.jsx
│   │   ├── main.jsx
│   │   └── index.css
│   ├── package.json
│   ├── vite.config.js
│   ├── tailwind.config.js
│   └── .env.example
├── render.yaml              # Render deployment config (backend)
├── netlify.toml             # Netlify deployment config (frontend)
└── README.md
```

---

## 🚀 Local Installation

### Prerequisites
- Python 3.10+
- Node.js 18+ and npm

### 1. Backend Setup

```bash
cd backend
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env            # optional: add VirusTotal/AbuseIPDB keys

uvicorn app.main:app --reload --port 8000
```

Backend runs at `http://localhost:8000` — interactive API docs at `http://localhost:8000/docs`.

### 2. Frontend Setup

Open a new terminal:

```bash
cd frontend
npm install
npm run dev
```

Frontend runs at `http://localhost:5173` and proxies `/api/*` calls to the backend automatically (see `vite.config.js`).

Open your browser to **http://localhost:5173** 🎉

---

## ☁️ Deployment

### Backend → Render

1. Push this repo to GitHub/GitLab.
2. In Render, choose **New → Blueprint** and point it at this repo (it will pick up `render.yaml` automatically), **or** manually create a Web Service with:
   - **Root Directory:** `backend`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
3. (Optional) Add environment variables in Render's dashboard:
   - `VIRUSTOTAL_API_KEY` — enables live VirusTotal URL reputation checks
   - `ABUSEIPDB_API_KEY` — reserved for future IP-reputation enhancement
4. Note your deployed backend URL, e.g. `https://phantomtrace-backend.onrender.com`

### Frontend → Netlify

1. In Netlify, **New site from Git**, point at this repo (it will pick up `netlify.toml` automatically: base `frontend`, build `npm run build`, publish `dist`).
2. Set the environment variable:
   - `VITE_API_URL` = `https://phantomtrace-backend.onrender.com` (your Render backend URL from above)
3. Deploy. Netlify will build and serve the React app.
4. **Important:** Update the CORS `allow_origins` list in `backend/app/main.py` from `["*"]` to your actual Netlify URL before going to production.

---

## 🔑 Optional API Keys (for enhanced accuracy)

PhantomTrace works fully out-of-the-box with **zero API keys** using free, key-less services (DNS-over-HTTPS, RDAP, ip-api.com, URLHaus, PhishTank). Adding these is optional but improves URL reputation accuracy:

| Service | Get a free key | Used for |
|---|---|---|
| VirusTotal | https://www.virustotal.com/gui/sign-in | Multi-engine URL malware scanning |
| AbuseIPDB | https://www.abuseipdb.com/api | (reserved for future IP reputation module) |

Add them to `backend/.env`:
```
VIRUSTOTAL_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
```

---

## 🧪 Try It Out

**Homograph Detector** — paste any of these to see brand impersonation detection in action:
```
faceb00k-login.com
linkedln-login.com
micros0ft-security.com
paypaI.com
amaz0n-kyc-verify.ru
```

**Fraud Detection** — paste this sample text:
```
Subject: Urgent: KYC Update Required
Your account will be suspended within 24 hours. Download APK to verify your KYC immediately. Share your OTP to confirm.
```

**Email Forensics** — upload any `.eml` file exported from Gmail/Outlook ("Download message" / "Show original" → save as `.eml`), or paste raw headers directly.

---

## ⚖️ Responsible Use & Limitations

- This tool provides **risk indicators and confidence scores**, not definitive proof of malicious intent or attacker identity.
- IP-based geolocation and ASN attribution are **probabilistic** — VPNs, proxies, and compromised relays can mask true origin.
- All findings should be corroborated with additional evidence before being used in legal or HR proceedings.
- The tool is intended for security analysts, SOC teams, and researchers investigating suspicious emails they have legitimately received — not for scanning third parties' private communications.

---

## 📄 License

MIT — use, modify, and deploy freely for personal or commercial security tooling.
