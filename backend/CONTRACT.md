# PhishLens Interface Contract

## Overview
This document specifies the exact API contract between the Chrome extension and the FastAPI backend for PhishLens.

## Decisions Settled
- **API Base URL**: `http://localhost:8000`
- **Signal IDs**:
  - `threat_feed` (100 pts)
  - `brand_mismatch` (30 pts)
  - `lookalike_domain` (25 pts)
  - `form_action_mismatch` (20 pts)
  - `new_domain` (15 pts)
  - `insecure_or_ip` (15 pts)
  - `urgency_language` (10 pts)
  - `url_shape` (10 pts)
  - `logo_match` (25 pts - stretch)
- **Verdict Bands & Values**:
  - `/analyze` returns `verdict`:
    - `0` to `29`: `"safe"`
    - `30` to `59`: `"suspicious"`
    - `60` to `100`: `"danger"`
  - `/explain` returns `verdict`: `"safe"`, `"suspicious"`, or `"phishing"`
- **Brand Format**:
  ```json
  {
    "name": "Nova Bank",
    "domains": ["novabank.test"],
    "keywords": ["nova bank", "novabank"]
  }
  ```
- **Test Hostnames (Local Demo)**:
  - `novabank.test` (real bank login)
  - `novabank-kyc-verify.test` (fake KYC phishing page)
  - `collect.test` (fake form exfiltration action endpoint)
  - `borderline.test` (suspicious / borderline page)

---

## Endpoints

### 1. `POST /analyze`
Called by the extension service worker when a password field is detected.
- **Timeout**: 3 seconds
- **CORS**: Open to all origins

#### Request Body (`application/json`)
```json
{
  "url": "https://novabank-kyc-verify.test/login",
  "title": "Nova Bank Net Banking Login",
  "text_snippet": "first 1500 visible characters",
  "forms": [
    {
      "action": "https://collect.example.net/p.php",
      "has_password": true,
      "input_names": ["user", "pass"]
    }
  ],
  "external_link_ratio": 0.8,
  "favicon_url": "https://novabank-kyc-verify.test/favicon.ico",
  "meta": {
    "https": true,
    "iframe_count": 1
  }
}
```

#### Response Body (`application/json`)
```json
{
  "scan_id": "a1b2c3",
  "score": 87,
  "verdict": "danger",
  "signals": [
    {
      "id": "form_action_mismatch",
      "points": 20,
      "detail": "Password form posts to collect.example.net, not this site"
    }
  ]
}
```

---

### 2. `POST /explain/{scan_id}`
Called if `score >= 30`. Runs asynchronously to provide an LLM-backed plain-English explanation without blocking initial UI warning.
- **Timeout**: 4 seconds

#### Response Body (`application/json`)
```json
{
  "verdict": "phishing",
  "confidence": 0.93,
  "reasons": [
    "Domain name novabank-kyc-verify.test is not an official Nova Bank domain.",
    "Form submits credentials to an external server (collect.example.net).",
    "Uses artificial urgency threatening account suspension."
  ],
  "advice": "Do not enter your password. Return to official novabank.test."
}
```

---

### 3. `GET /events?limit=50`
Polled every 2 seconds by the live dashboard.
Returns list of scans, newest first.

#### Response Body (`application/json`)
```json
[
  {
    "scan_id": "a1b2c3",
    "timestamp": "2026-11-14T15:00:00Z",
    "url": "https://novabank-kyc-verify.test/login",
    "score": 87,
    "verdict": "danger",
    "signals": [
      {
        "id": "form_action_mismatch",
        "points": 20,
        "detail": "Password form posts to collect.example.net, not this site"
      }
    ],
    "explanation": {
      "verdict": "phishing",
      "confidence": 0.93,
      "reasons": ["..."],
      "advice": "..."
    }
  }
]
```

