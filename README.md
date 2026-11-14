# PhishLens - AI-Powered Phishing Detection Extension

PhishLens is a lightweight Chrome extension that intercepts phishing attacks before users submit credentials. It pairs sub-second heuristic rule evaluation with an asynchronous LLM explanation engine to show clear, plain-English security warnings on login pages.

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
4. Visit `http://novabank-kyc-verify.test:8080/` to watch the warning trigger live!

---

## 🧪 Evaluation Script
Run the automated evaluation benchmark across 20 real login pages and 10 phishing URLs:
```bash
python demo/eval.py
```

---

## 🔒 Privacy & Architecture
- **Zero Keylogging**: The extension inspects only DOM input field names and page structure, never values typed by the user.
- **Sub-Second Defense**: Heuristics execute in < 1s to immediately display the overlay/banner.
- **AI Explainability**: Asynchronous LLM reasoning explains *why* the page was flagged without delaying warning presentation.
