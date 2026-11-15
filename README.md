# PhishLens - AI-Powered Phishing Detection Extension

PhishLens is a lightweight Chrome extension that intercepts phishing attacks before users submit credentials. It pairs sub-second heuristic rule evaluation with an asynchronous LLM explanation engine to show clear, plain-English security warnings on login pages.

---

## 🌐 Live Public Links (Anyone Can Use Now!)

* **Live Intelligence Dashboard:** [https://adityabhaker21-star.github.io/PhishLens/](https://adityabhaker21-star.github.io/PhishLens/)
* **Public Backend API & Docs:** [https://dating-referral-concentrate-essay.trycloudflare.com/docs](https://dating-referral-concentrate-essay.trycloudflare.com/docs)
* **Direct Extension Download:** [Download `PhishLens-Extension.zip`](https://github.com/adityabhaker21-star/PhishLens/raw/main/PhishLens-Extension.zip)

### How Anyone Can Install the Extension in 3 Steps:
1. Download [**`PhishLens-Extension.zip`**](https://github.com/adityabhaker21-star/PhishLens/raw/main/PhishLens-Extension.zip) and extract it to a folder.
2. In Google Chrome, navigate to `chrome://extensions/` and switch on **Developer mode** (top right).
3. Click **Load unpacked** and select the extracted folder.
*(The extension connects automatically to our live cloud detection API!)*

---

## 👥 PhishLens Team
- **Aditya Bhaker** ([@adityabhaker21-star](https://github.com/adityabhaker21-star)) — Chrome Extension Architecture & Warning UI (Person A)
- **Aditya Rai** ([@AdityaRai67-beep](https://github.com/AdityaRai67-beep)) — Detection Engine, Scoring Signals & Backend API (Person B)
- **Suhani Agrawal** ([@suhaniagrawal21](https://github.com/suhaniagrawal21)) — AI Explanation Engine & Evaluation Benchmark (Person C)

---

## ⚡ Quickstart Setup (In Order)

### 1. Update Hosts File (Admin Required)
Map the demo domains to localhost so you can run realistic bank demo pages offline without modifying real domains:

**Windows (PowerShell as Administrator):**
```powershell
Add-Content -Path C:\Windows\System32\drivers\etc\hosts -Value "`n127.0.0.1 novabank.test novabank-kyc-verify.test collect.test borderline.test"
```
*(On macOS / Linux: add to `/etc/hosts`)*

---

### 2. Configure Environment (`.env`)
Copy the example environment configuration and ensure your API key is set:
```bash
cp .env.example .env
```
In `.env`:
```ini
GEMINI_API_KEY=your_gemini_api_key_here
GEMINI_MODEL=gemini-flash-lite-latest
```

---

### 3. Start the Demo Server (Port 8080)
In a terminal:
```bash
python demo/serve.py
```
This serves:
- `http://novabank.test:8080/` (Legitimate Bank Login — Safe)
- `http://novabank-kyc-verify.test:8080/` (Urgent KYC Phishing Clone — Danger)
- `http://borderline.test:8080/` (Generic Sign-in — Suspicious)
- `http://collect.test:8080/submit` (Blocked submission sink — "Demo only")

---

### 4. Start the Backend API (Port 8000)
In a second terminal:
```bash
cd backend
uvicorn app:app --reload --port 8000
```
API Docs: `http://localhost:8000/docs`

---

### 5. Open the Live Dashboard
Open `demo/dashboard.html` in any browser or serve it. It connects to `http://localhost:8000/events` and updates live as pages are scanned.

---

### 6. Load Chrome Extension
1. Open Chrome and navigate to `chrome://extensions`.
2. Toggle on **Developer mode** in the top right.
3. Click **Load unpacked** and select the `/extension` folder.
4. Visit `http://novabank-kyc-verify.test:8080/` to watch the warning trigger

---

## 🧪 Evaluation Script
Run the automated evaluation benchmark across 20 real login pages and 10 phishing URLs :
```bash
python demo/eval.py
```

---

## 🔒 Privacy & Architecture
- **Zero Keylogging**: The extension inspects only DOM input field names and page structure, never values typed by the user.
- **Sub-Second Defense**: Heuristics execute in < 1s to immediately display the overlay/banner.
- **AI Explainability**: Asynchronous LLM reasoning explains *why* the page was flagged without delaying warning presentation.

## Review fixes and validation

The current fixes, tests, and deployment limitations are documented in [REVIEW.md](REVIEW.md).
A green "Safe" result means no configured indicators exceeded the threshold; it is not a safety guarantee.
Backend outages now appear as **Not checked**, and report totals represent submissions rather than unique people.

Install backend dependencies before running the quickstart:

```sh
python -m pip install -r backend/req.txt
```

After editing extension source, rebuild its downloadable package:

```sh
python scripts/package_extension.py
```

Run the regression checks with Python and Node 20 or later:

```sh
python -m unittest discover -s tests -p 'test_*.py' -v
python backend/test_suite.py
node tests/extension_regressions.cjs
```
