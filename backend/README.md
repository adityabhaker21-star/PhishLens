# PhishLens Backend — Detection Engine & API

PhishLens is a real-time phishing detection backend built with **FastAPI**, **SQLite**, and a heuristic **Rule-Based Scoring Engine**. Designed for the 24-hour hackathon.

---

## 🚀 Quick Start

### 1. Activate Virtual Environment & Run Server
Open your terminal in `d:\Phishsing\backend`:

```powershell
uvicorn app:app --reload --port 8000
```

### 2. Open Swagger Documentation
Navigate to:
👉 **http://127.0.0.1:8000/docs**

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Health check and engine status |
| `POST` | `/analyze` | Main scan endpoint (takes URL, text, forms; returns score, verdict, signals) |
| `GET` / `POST` | `/explain/{scan_id}` | AI-style human explanation and security advice for a scan |
| `GET` | `/events?limit=50` | Recent scans list from SQLite for Person C's Dashboard |
| `GET` | `/threat-feed` | Status of loaded threat intelligence blocklist |

---

## 🎯 Scoring System & Thresholds

| Signal | Points | Detection Condition |
|---|---:|---|
| **Threat Feed Hit** | 100 | URL/Domain in active threat intelligence blocklist (`threat_feed.json`) |
| **Brand Mismatch** | 30 | Page mentions a known brand (e.g. Nova Bank) on an unofficial domain |
| **Lookalike Domain** | 25 | Typosquatting / character substitution (e.g. `novabnak.test`, `g00gle.com`) |
| **Form Action Mismatch**| 20 | Form submits credentials to an external foreign domain or plain HTTP |
| **New Domain** | 15 | Domain registered < 30 days ago (RDAP / mock feed) |
| **Insecure HTTP / IP** | 15 | Website uses unencrypted HTTP or raw IP address |
| **Urgency Language** | 10 | High-pressure urgency phrases (`kyc`, `account suspended`, `immediately`) |
| **Suspicious URL Shape**| 10 | Long URL, excessive subdomains (4+), cheap TLDs (`.xyz`, `.top`, `.online`) |

### Verdicts:
- **0 – 29**: `safe` (Green)
- **30 – 59**: `suspicious` (Yellow)
- **60 – 100**: `danger` (Red) — Score is capped at 100.

---

## 🧪 Demo Test Payloads (in `samples/`)

1. **Legitimate Site (Score: 0 | safe)**:
   - File: `samples/legitimate_novabank.json`
   - URL: `https://novabank.test/login`
2. **Fake Phishing KYC Page (Score: 80+ | danger)**:
   - File: `samples/fake_novabank_kyc.json`
   - URL: `http://novabank-kyc-verify.xyz/login.php`
3. **Borderline Suspicious (Score: 35 | suspicious)**:
   - File: `samples/borderline_suspicious.json`
   - URL: `http://secure-verify-update.top/portal`
4. **Threat Feed Blocklist Hit (Score: 100 | danger)**:
   - File: `samples/threat_feed_hit.json`
   - URL: `http://malicious-phish-bank.com/login.php`

---

## 📦 Project Structure

```
Phishing/
├── .gitignore
└── backend/
    ├── app.py              # FastAPI endpoints (/analyze, /explain, /events)
    ├── signals.py          # All 8 detection signals
    ├── database.py         # SQLite persistence & query functions (phishlens.db)
    ├── brands.json         # Known brands & official domains database
    ├── threat_feed.json    # Threat intelligence blocklist
    ├── test_suite.py       # Automated signal & DB test suite
    ├── req.txt             # Project dependencies
    └── samples/            # Test payloads for Swagger / Extension
```
