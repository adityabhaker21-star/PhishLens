# PhishLens - 3-Minute Pitch & Slide Deck

## Slide 1: Title & The Problem
- **Title**: PhishLens — Protecting Users Before Credentials Are Lost
- **Problem**: 
  - Over 3.4 billion phishing emails and lures circulate daily.
  - Phishing sites take minutes to spin up and look 100% identical to genuine portals.
  - Non-technical users cannot evaluate complex URLs or subtle domain spoofing on mobile or browser bars.
- **The Gap**: Traditional blocklists are reactive (updated hours or days later); generic warnings are ignored because users don't understand technical jargon.

---

## Slide 2: The Solution (Sub-Second Heuristics + LLM Explainability)
- **Fast Rule Engine (<1s)**: Instantly detects credential-harvesting anomalies, lookalike domains, unencrypted HTTP, and external form submissions.
- **Plain-English AI Explanation**: An asynchronous LLM translates technical anomalies into 3 clear, digestible reasons and 1 line of actionable advice.
- **Zero-Friction on Legitimate Sites**: Real sites produce zero intrusive popups or interruptions.

---

## Slide 3: The Live Demo (30s Real vs Fake)
- **Step 1 (The Real Site)**:
  - Visit `http://novabank.test:8080/`
  - Result: Pure clean experience, zero popup, legitimate login proceeds smoothly.
- **Step 2 (The Phishing Trap)**:
  - Visit `http://novabank-kyc-verify.test:8080/` (lure: "KYC expires in 24 hours")
  - Result: Instant red full-page overlay flags danger (Score: 100).
  - LLM Explanation arrives asynchronously:
    1. *Brand mismatch on a newly registered lookalike domain.*
    2. *Password form posts credentials to an external unauthorized endpoint.*
    3. *Page uses urgent language demanding immediate account verification.*
  - User is protected by clicking "Go Back to Safety".

---

## Slide 4: Real-Time Security Operations Dashboard
- Live streaming event feed via `GET /events`.
- Projector-ready status monitors:
  - Total Pages Scanned
  - Threats Flagged
  - Safe Sites Passed
- Security teams or home users can inspect technical indicators with one click.

---

## Slide 5: System Architecture & Privacy First
```
[ Browser / Chrome Extension ]
      | (URL, Title, Form Actions, Link Ratios - NEVER TYPED PASSWORDS)
      v
[ FastAPI Backend / Scoring Engine ]
      |-- Heuristic Signals (Lookalike, RDAP age, Threat Feeds, Mismatch) -> < 1s
      |-- SQLite Scan History & Events Logger
      v
[ LLM Explain Engine (Gemini / Claude) ] -> Plain English 3 reasons + advice
```
- **Strict Privacy Rule**: No password or input text values are ever read or transmitted. Only input element names and page structure are inspected.

---

## Slide 6: Accuracy & Benchmark Numbers (eval.py)
- Evaluated on 30 target websites (20 legitimate high-traffic portals + 10 realistic phishing attacks):
  - **Zero False Positives** on legitimate services via curated brand recognition & allowlists.
  - High recall on lookalike domains, unencrypted login actions, and urgency triggers.
  - Reproducible benchmark via single command: `python demo/eval.py`.

---

## Slide 7: What's Next (Roadmap)
1. **Perceptual Favicon / Logo Matching**: Computer vision comparison against known brand marks.
2. **Multilingual Explanations**: Localized warnings in Hindi, Spanish, and regional languages.
3. **Gmail / Email Pre-Click Inspection**: Scanning links inside webmail before redirection occurs.
4. **Community Threat Feed Contribution**: Anonymized submission of verified zero-day lures.

---

## 🎙️ 3-Minute Demo Script (For Pitch Day)

- **[0:00 - 0:20] Hook**: 
  *"How many of you or your family members have received an SMS saying 'Your KYC will expire in 24 hours, click here to avoid account freeze'? Most people panic and click. Today, we're stopping that scam before a password is typed."*
- **[0:20 - 0:50] Legitimate Site**: 
  *"Here is our legitimate demo bank, Nova Bank. When a user visits the real page, PhishLens stays completely quiet. Security shouldn't slow down real life."*
- **[0:50 - 1:50] The Phishing Trap**: 
  *"Now watch what happens when the user clicks the phishing link: `novabank-kyc-verify.test`. In under 1 second, the entire page is blocked by a red warning overlay. And notice this: instead of cryptic technical errors, our AI explains in plain English: 'The site mimics Nova Bank but sends your password to an external collection server'."*
- **[1:50 - 2:30] Live Dashboard & Architecture**: 
  *"On our live monitor, the scan event has already arrived with full signal breakdown. Best of all: not a single keystroke typed by the user was ever sent to our servers."*
- **[2:30 - 3:00] Wrap-up & Q&A**: 
  *"PhishLens delivers instant heuristic protection with human-understandable AI explainability. Thank you, and we're ready for your questions!"*
