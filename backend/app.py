"""
PhishLens Backend API
FastAPI backend for real-time phishing detection, threat analysis, and event logging.
"""

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
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
from database import init_db, save_scan, get_scan, get_recent_scans

# Initialize database schema on startup
init_db()

app = FastAPI(
    title="PhishLens Backend",
    version="1.0.0",
    description="Real-time Phishing Detection Engine API for PhishLens Chrome Extension",
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
        "service": "PhishLens Detection Engine",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/analyze")
def analyze(payload: dict):
    """
    Main detection endpoint called by Chrome Extension (Person A).
    Accepts page URL, title, visible text, and optional forms.
    Returns composite score (0-100), verdict (safe/suspicious/danger), and breakdown signals.
    """
    # 1. Extract inputs from payload
    website_url = payload.get("url", "").strip()
    if not website_url:
        website_url = "unknown"

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

    # 8. Create scan record
    scan_id = str(uuid4())
    created_at = datetime.now(timezone.utc).isoformat()

    result = {
        "scan_id": scan_id,
        "website": website_url,
        "score": score,
        "verdict": verdict,
        "signals": signals,
        "created_at": created_at,
    }

    # 9. Persist to SQLite database
    save_scan(result)

    return result


def _generate_explanation(scan: Dict[str, Any]) -> Dict[str, Any]:
    """Generates structured reasoning and safety advice based on triggered signals."""
    signals = scan.get("signals", [])
    verdict = scan.get("verdict", "safe")
    reasons = []

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
    Fetches the scan from SQLite and generates contextual reasons and safety advice.
    """
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan ID '{scan_id}' not found in database.")

    return _generate_explanation(scan)


@app.get("/events")
def events(limit: int = Query(default=50, ge=1, le=500)):
    """
    Returns recent scans list from SQLite database for Person C's dashboard.
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
