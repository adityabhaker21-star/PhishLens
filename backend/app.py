"""
PhishLens Backend API
FastAPI backend for real-time phishing detection, threat analysis, community reporting, and event logging.
"""

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from uuid import uuid4
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from signals import (
    signal_threat_feed,
    signal_brand_mismatch,
    signal_lookalike_domain,
    signal_form_action_mismatch,
    signal_insecure_or_ip,
    signal_new_domain,
    signal_urgency_language,
    signal_url_shape,
)
from database import (
    init_db,
    save_scan,
    get_scan,
    get_recent_scans,
    record_report,
    get_reports_count,
)

# Initialize database schema on startup
init_db()

app = FastAPI(
    title="PhishLens Backend",
    version="1.1.0",
    description="Real-time Phishing Detection & Community Reporting Engine for PhishLens",
)

# Enable CORS for Chrome Extension and Dashboard communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def home():
    """Health check endpoint."""
    return {
        "status": "online",
        "service": "PhishLens Detection & Reporting Engine",
        "version": "1.1.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/analyze")
def analyze(payload: dict):
    """
    Main detection endpoint called by Chrome Extension (Person A).
    Accepts page URL, title, visible text, and optional forms.
    Returns composite score (0-100), verdict (safe/suspicious/danger), breakdown signals,
    AND reports_count for that page!
    """
    # 1. Extract inputs from payload
    website_url = payload.get("url", "").strip()
    if not website_url:
        website_url = payload.get("website", "").strip() or "unknown"

    title = payload.get("title", "")
    text_snippet = payload.get("text_snippet", "")
    website_text = f"{title} {text_snippet}".strip()

    forms = payload.get("forms", [])

    signals: List[Dict[str, Any]] = []

    # 2. Priority 1: Threat Feed Hit (Instant 100 points if known malicious)
    threat_sig = signal_threat_feed(website_url)
    if threat_sig:
        signals.append(threat_sig)

    # 3. Domain & Brand Signals
    brand_sig = signal_brand_mismatch(website_url, website_text)
    if brand_sig:
        signals.append(brand_sig)

    lookalike_sig = signal_lookalike_domain(website_url)
    if lookalike_sig:
        signals.append(lookalike_sig)

    # 4. Form Action & Protocol Signals
    form_sig = signal_form_action_mismatch(website_url, forms)
    if form_sig:
        signals.append(form_sig)

    insecure_sig = signal_insecure_or_ip(website_url)
    if insecure_sig:
        signals.append(insecure_sig)

    # 5. Infrastructure & Heuristic Signals
    new_domain_sig = signal_new_domain(website_url)
    if new_domain_sig:
        signals.append(new_domain_sig)

    urgency_sig = signal_urgency_language(website_text)
    if urgency_sig:
        signals.append(urgency_sig)

    url_shape_sig = signal_url_shape(website_url)
    if url_shape_sig:
        signals.append(url_shape_sig)

    # 6. Calculate total score and cap at 100
    raw_score = sum(s["points"] for s in signals)
    score = min(raw_score, 100)

    # 7. Determine final verdict based on build plan thresholds
    # 0–29: safe | 30–59: suspicious | 60–100: danger
    if score >= 60:
        verdict = "danger"
    elif score >= 30:
        verdict = "suspicious"
    else:
        verdict = "safe"

    # 8. Fetch community reports count for this URL
    reports_count = get_reports_count(website_url)

    # 9. Create scan record
    scan_id = str(uuid4())
    created_at = datetime.now(timezone.utc).isoformat()

    result = {
        "scan_id": scan_id,
        "website": website_url,
        "score": score,
        "verdict": verdict,
        "signals": signals,
        "reports_count": reports_count,
        "created_at": created_at,
    }

    # 10. Persist to SQLite database
    save_scan(result)

    return result


# ============================================================================
# COMMUNITY REPORTING ENDPOINTS
# ============================================================================
@app.post("/report")
def report_phishing_url(payload: dict):
    """
    Called when a user clicks the 'Report Phishing' button.
    Increments community report counter for this specific URL and domain in SQLite.
    Returns the new updated report count.
    """
    url = payload.get("url", "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="Missing required 'url' parameter.")

    new_count = record_report(url)

    return {
        "status": "success",
        "url": url,
        "reports_count": new_count,
        "message": f"Website successfully reported! Total community reports: {new_count}",
    }


@app.get("/report")
def get_url_reports(url: str = Query(..., description="Target website URL to check reports")):
    """
    Get current community report count for a website.
    """
    count = get_reports_count(url)
    return {
        "url": url,
        "reports_count": count,
    }


def _generate_explanation(scan: Dict[str, Any]) -> Dict[str, Any]:
    """Generates structured reasoning and safety advice based on triggered signals."""
    signals = scan.get("signals", [])
    verdict = scan.get("verdict", "safe")
    reports_count = scan.get("reports_count", 0)
    reasons = []

    # Mention community reports if any user has reported it
    if reports_count > 0:
        reasons.append(f"Community Warning: {reports_count} user(s) have flagged this page as suspicious/phishing.")

    for sig in signals:
        sig_id = sig.get("id")
        detail = sig.get("detail", "")

        if sig_id == "threat_feed_hit":
            reasons.append(f"Confirmed Threat: {detail}")
        elif sig_id == "brand_mismatch":
            reasons.append(f"Brand Impersonation: {detail}")
        elif sig_id == "lookalike_domain":
            reasons.append(f"Typosquatting: {detail}")
        elif sig_id == "form_action_mismatch":
            reasons.append(f"Insecure Form Action: {detail}")
        elif sig_id == "new_domain":
            reasons.append(f"Newly Created Domain: {detail}")
        elif sig_id == "insecure_or_ip":
            reasons.append(f"Unencrypted Connection: {detail}")
        elif sig_id == "urgency_language":
            reasons.append(f"Psychological Urgency: {detail}")
        elif sig_id == "url_shape":
            reasons.append(f"Suspicious URL Structure: {detail}")

    if not reasons:
        reasons.append("No active phishing patterns or known threats detected for this domain.")

    if verdict == "danger":
        advice = "CRITICAL: Do NOT enter passwords, OTPs, or personal data. Leave this page immediately."
        confidence = 0.95
    elif verdict == "suspicious":
        advice = "WARNING: Proceed with caution. Verify the domain name in the address bar before logging in."
        confidence = 0.80
    else:
        advice = "Page appears legitimate. Always check for a valid SSL padlock before entering credentials."
        confidence = 0.90

    return {
        "scan_id": scan.get("scan_id"),
        "website": scan.get("website"),
        "verdict": verdict,
        "score": scan.get("score"),
        "reports_count": reports_count,
        "confidence": confidence,
        "reasons": reasons,
        "advice": advice,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/explain/{scan_id}")
@app.post("/explain/{scan_id}")
def explain_scan(scan_id: str):
    """
    Detailed explanation endpoint for AI / Person C dashboard.
    Supports both GET and POST requests.
    """
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan ID '{scan_id}' not found in database.")

    return _generate_explanation(scan)


@app.get("/events")
def events(limit: int = Query(default=50, ge=1, le=500)):
    """
    Returns recent scans list from SQLite database for Person C's dashboard.
    Includes the 'reports_count' column for every scan!
    """
    scans = get_recent_scans(limit=limit)
    return {
        "count": len(scans),
        "events": scans,
    }


@app.get("/threat-feed")
def get_threat_feed_info():
    """Inspect active threat feed status."""
    import json
    from pathlib import Path

    feed_path = Path(__file__).parent / "threat_feed.json"
    if not feed_path.exists():
        return {"loaded": False, "count": 0}

    with open(feed_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    return {
        "loaded": True,
        "updated_at": data.get("updated_at"),
        "domains_count": len(data.get("domains", [])),
        "urls_count": len(data.get("urls", [])),
    }


@app.get("/preview-button", response_class=HTMLResponse)
def preview_report_button():
    """
    Exact Visual Match to the user's Chrome Extension Warning Modal!
    Features:
    - Identical modal layout (Red accent, icon, score meter, key detection signals)
    - Seamlessly integrated Community Report Bar with live incrementing button!
    """
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>PhishLens - Warning Modal Preview</title>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
        <style>
            * { box-sizing: border-box; }
            body {
                font-family: 'Inter', -apple-system, sans-serif;
                background: linear-gradient(135deg, #1e293b, #0f172a);
                margin: 0;
                padding: 30px 16px;
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
            }

            /* The Exact Modal Container from Screenshot */
            .modal-card {
                background: #ffffff;
                width: 100%;
                max-width: 520px;
                border-radius: 18px;
                overflow: hidden;
                box-shadow: 0 25px 60px -15px rgba(0, 0, 0, 0.65);
                position: relative;
            }

            /* Red Top Accent Bar */
            .top-bar {
                height: 5px;
                background: #e11d48;
                width: 100%;
            }

            .modal-content {
                padding: 24px 28px 24px 28px;
            }

            /* Header Section */
            .header-row {
                display: flex;
                align-items: flex-start;
                gap: 14px;
                margin-bottom: 14px;
            }

            .warning-icon-box {
                width: 44px;
                height: 44px;
                background: #fee2e2;
                border-radius: 12px;
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 22px;
                flex-shrink: 0;
            }

            .title-area h2 {
                margin: 0;
                color: #b91c1c;
                font-size: 20px;
                font-weight: 800;
                letter-spacing: -0.3px;
            }

            .site-url {
                color: #64748b;
                font-size: 13px;
                margin-top: 3px;
                font-weight: 500;
            }

            /* Score Bar Row */
            .score-row {
                display: flex;
                align-items: center;
                gap: 12px;
                margin-bottom: 20px;
                padding-left: 58px;
            }

            .score-text {
                font-size: 13px;
                font-weight: 700;
                color: #991b1b;
                white-space: nowrap;
            }

            .score-track {
                flex-grow: 1;
                height: 7px;
                background: #fee2e2;
                border-radius: 10px;
                overflow: hidden;
            }

            .score-fill {
                height: 100%;
                width: 60%;
                background: #e11d48;
                border-radius: 10px;
            }

            /* Section Label */
            .section-label {
                font-size: 11px;
                font-weight: 700;
                color: #64748b;
                text-transform: uppercase;
                letter-spacing: 0.6px;
                margin-bottom: 8px;
            }

            /* Signal Pill Items */
            .signals-list {
                display: flex;
                flex-direction: column;
                gap: 8px;
                margin-bottom: 16px;
            }

            .signal-item {
                background: #f8fafc;
                border: 1px solid #f1f5f9;
                border-left: 3px solid #e11d48;
                border-radius: 8px;
                padding: 10px 14px;
                font-size: 12.5px;
                color: #334155;
                line-height: 1.45;
            }

            .signal-item span.bullet {
                color: #e11d48;
                font-weight: bold;
                margin-right: 4px;
            }

            /* Warning Advice Box */
            .advice-box {
                background: #f8fafc;
                border: 1px solid #e2e8f0;
                border-radius: 10px;
                padding: 12px 14px;
                font-size: 12px;
                color: #475569;
                line-height: 1.4;
                margin-bottom: 16px;
            }

            .advice-box strong {
                color: #0f172a;
                font-weight: 700;
                display: block;
                margin-bottom: 4px;
            }

            /* ======================================================== */
            /* ⭐ THE NEW COMMUNITY REPORT BAR & BUTTON (PERFECT FIT)  */
            /* ======================================================== */
            .community-report-strip {
                background: #fef2f2;
                border: 1px solid #fecaca;
                border-radius: 10px;
                padding: 10px 14px;
                display: flex;
                align-items: center;
                justify-content: space-between;
                margin-bottom: 14px;
            }

            .community-label {
                display: flex;
                align-items: center;
                gap: 8px;
                font-size: 13px;
                font-weight: 600;
                color: #991b1b;
            }

            .community-badge-count {
                background: #ef4444;
                color: white;
                font-size: 11px;
                font-weight: 800;
                padding: 2px 7px;
                border-radius: 12px;
            }

            .btn-report-community {
                background: #ffffff;
                color: #dc2626;
                border: 1.5px solid #fca5a5;
                border-radius: 8px;
                padding: 6px 14px;
                font-size: 12px;
                font-weight: 700;
                cursor: pointer;
                display: inline-flex;
                align-items: center;
                gap: 5px;
                transition: all 0.15s ease;
            }

            .btn-report-community:hover {
                background: #dc2626;
                color: #ffffff;
                border-color: #dc2626;
            }

            .btn-report-community:disabled {
                opacity: 0.6;
                cursor: not-allowed;
            }

            /* Primary Go Back Button */
            .btn-go-back {
                width: 100%;
                background: #e11d48;
                color: white;
                border: none;
                border-radius: 10px;
                padding: 13px 20px;
                font-size: 14px;
                font-weight: 700;
                cursor: pointer;
                display: flex;
                align-items: center;
                justify-content: center;
                gap: 8px;
                box-shadow: 0 4px 12px rgba(225, 29, 72, 0.35);
                transition: background 0.15s;
            }

            .btn-go-back:hover {
                background: #be123c;
            }

            /* Secondary Link */
            .link-continue {
                display: block;
                text-align: center;
                margin-top: 10px;
                color: #64748b;
                font-size: 12px;
                text-decoration: underline;
                cursor: pointer;
            }
        </style>
    </head>
    <body>

        <!-- The Modal from User Screenshot -->
        <div class="modal-card">
            <div class="top-bar"></div>
            
            <div class="modal-content">
                <!-- Header -->
                <div class="header-row">
                    <div class="warning-icon-box">⚠️</div>
                    <div class="title-area">
                        <h2>Phishing Threat Detected</h2>
                        <div class="site-url" id="target-site">exam-setu.dtu.ac.in</div>
                    </div>
                </div>

                <!-- Score Progress Bar -->
                <div class="score-row">
                    <span class="score-text">Score: 60 / 100</span>
                    <div class="score-track">
                        <div class="score-fill"></div>
                    </div>
                </div>

                <!-- Key Detection Signals -->
                <div class="section-label">Key Detection Signals</div>
                <div class="signals-list">
                    <div class="signal-item">
                        <span class="bullet">•</span> Page claims to represent Google but is hosted on unauthorized domain 'exam-setu.dtu.ac.in'
                    </div>
                    <div class="signal-item">
                        <span class="bullet">•</span> Domain 'exam-setu.dtu.ac.in' is a close visual lookalike to official State Bank of India domain 'sbi.co.in'
                    </div>
                    <div class="signal-item">
                        <span class="bullet">•</span> Excessive subdomains (4 levels)
                    </div>
                </div>

                <!-- Advisory Box -->
                <div class="advice-box">
                    <strong>Do not enter your password or sensitive personal data on this page.</strong>
                    • Page claims to represent Google but is hosted on unauthorized domain 'exam-setu.dtu.ac.in'<br>
                    • Domain 'exam-setu.dtu.ac.in' is a close visual lookalike to official SBI domain 'sbi.co.in'
                </div>

                <!-- ======================================================== -->
                <!-- ⭐ THE EXACT REPORT BUTTON & COUNT (PERFECTLY INTEGRATED) -->
                <!-- ======================================================== -->
                <div class="community-report-strip">
                    <div class="community-label">
                        <span>🚩 Community Reports:</span>
                        <span class="community-badge-count" id="badge-count">0</span>
                    </div>
                    <button class="btn-report-community" id="btn-report" onclick="submitCommunityReport()">
                        <span>🚩</span> Report as Phishing
                    </button>
                </div>

                <!-- Go Back to Safety Button (From Screenshot) -->
                <button class="btn-go-back" onclick="alert('Navigating back to safe page!')">
                    <span>←</span> Go back to safety (Recommended)
                </button>

                <div class="link-continue" onclick="alert('Proceeding at your own risk')">
                    I understand the risk, continue anyway
                </div>
            </div>
        </div>

        <script>
            const siteUrl = "http://exam-setu.dtu.ac.in";

            async function loadCurrentReports() {
                try {
                    const res = await fetch(`/report?url=${encodeURIComponent(siteUrl)}`);
                    const data = await res.json();
                    document.getElementById("badge-count").innerText = `${data.reports_count} users`;
                } catch (e) {
                    console.error("Could not fetch reports count", e);
                }
            }

            async function submitCommunityReport() {
                const btn = document.getElementById("btn-report");
                btn.disabled = true;
                btn.innerText = "Reporting...";

                try {
                    const res = await fetch("/report", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ url: siteUrl })
                    });
                    const data = await res.json();
                    
                    // Increment and show success right on the button & badge!
                    document.getElementById("badge-count").innerText = `${data.reports_count} users`;
                    btn.innerHTML = `<span>✅</span> Reported!`;
                    btn.style.borderColor = "#10b981";
                    btn.style.color = "#10b981";
                } catch (e) {
                    alert("Error submitting report");
                    btn.disabled = false;
                    btn.innerHTML = `<span>🚩</span> Report as Phishing`;
                }
            }

            // Load live count on load
            loadCurrentReports();
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)
