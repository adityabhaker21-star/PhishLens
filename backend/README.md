# PhishLens Backend — Detection Engine & Community Reporting API

PhishLens is a real-time phishing detection backend built with **FastAPI**, **SQLite**, and a heuristic **Rule-Based Scoring Engine**. Designed for the 24-hour hackathon.

---

## 🚀 Quick Start

### 1. Run Server
Open your terminal in `d:\Phishsing\backend`:

```powershell
uvicorn app:app --reload --port 8000
```

### 2. Open Swagger Documentation
👉 **http://127.0.0.1:8000/docs**

### 3. Open Live Report Button Demo
👉 **http://127.0.0.1:8000/preview-button**

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Health check and engine status |
| `POST` | `/analyze` | Main scan endpoint (returns score, verdict, signals, AND `reports_count`) |
| `POST` | `/report` | **Community Report**: Increments report count for a malicious URL in SQLite |
| `GET` | `/report?url=...` | **Get Reports**: Retrieves total reports submitted for a website |
| `GET` / `POST` | `/explain/{scan_id}` | AI-style human explanation and security advice for a scan |
| `GET` | `/events?limit=50` | Recent scans list from SQLite for Person C's Dashboard |
| `GET` | `/threat-feed` | Status of loaded threat intelligence blocklist |
| `GET` | `/preview-button` | Interactive browser preview of the Report Button and live badge |

---

## 🚩 Community Reporting Feature ("Report Phishing" Button)

When any user encounters a phishing page, they can click the **"Report this page as Phishing"** button:
1. Frontend makes a `POST /report` with `{ "url": "http://suspicious-site.com" }`.
2. Backend increments the report counter in SQLite (`reports` table).
3. Whenever ANY user scans or visits that URL via `POST /analyze` or `GET /report`, the backend returns `"reports_count": N`.
4. The UI displays: `⚠️ Reported by N users as phishing`.

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
