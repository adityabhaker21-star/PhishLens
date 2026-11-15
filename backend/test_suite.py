"""
Automated Test Suite for PhishLens Backend Signals & Database
Run this file to verify all detection signals and SQLite functionality.
"""

import sys
from pathlib import Path

# Add backend directory to sys.path
BASE_DIR = Path(__file__).parent
sys.path.insert(0, str(BASE_DIR))

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


def run_tests():
    print("=" * 65)
    print("           PHISHLENS BACKEND - TEST SUITE")
    print("=" * 65)
    passed = 0
    total = 0

    # Test 1: Threat Feed Hit (100 points)
    total += 1
    tf_hit = signal_threat_feed("http://malicious-phish-bank.com/login.php")
    if tf_hit and tf_hit["points"] == 100:
        print("[PASS] Signal 1: Threat Feed Hit (100 pts)")
        passed += 1
    else:
        print(f"[FAIL] Signal 1: Threat Feed Hit -> {tf_hit}")

    # Test 2: Brand Mismatch (30 points)
    total += 1
    bm_hit = signal_brand_mismatch(
        "http://novabank-fake-login.xyz",
        "Welcome to Nova Bank. Please login to your account."
    )
    if bm_hit and bm_hit["points"] == 30:
        print("[PASS] Signal 2: Brand Mismatch (30 pts)")
        passed += 1
    else:
        print(f"[FAIL] Signal 2: Brand Mismatch -> {bm_hit}")

    # Test 3: Lookalike Domain / Typosquatting (25 points)
    total += 1
    la_hit = signal_lookalike_domain("https://novabnak.test/login")
    if la_hit and la_hit["points"] == 25:
        print("[PASS] Signal 3: Lookalike Domain (25 pts)")
        passed += 1
    else:
        print(f"[FAIL] Signal 3: Lookalike Domain -> {la_hit}")

    # Test 4: Form Action Mismatch (20 points)
    total += 1
    fa_hit = signal_form_action_mismatch(
        "https://novabank.test/login",
        [{"action": "http://evil-data-stealer.xyz/harvest", "method": "POST"}]
    )
    if fa_hit and fa_hit["points"] == 20:
        print("[PASS] Signal 4: Form Action Mismatch (20 pts)")
        passed += 1
    else:
        print(f"[FAIL] Signal 4: Form Action Mismatch -> {fa_hit}")

    # Test 5: Insecure HTTP (15 points)
    total += 1
    insec_hit = signal_insecure_or_ip("http://example-test.com")
    if insec_hit and insec_hit["points"] == 15:
        print("[PASS] Signal 5: Insecure HTTP (15 pts)")
        passed += 1
    else:
        print(f"[FAIL] Signal 5: Insecure HTTP -> {insec_hit}")

    # Test 6: New Domain (15 points)
    total += 1
    new_dom_hit = signal_new_domain("http://novabank-kyc-verify.xyz/login")
    if new_dom_hit and new_dom_hit["points"] == 15:
        print("[PASS] Signal 6: New Domain Age (15 pts)")
        passed += 1
    else:
        print(f"[FAIL] Signal 6: New Domain Age -> {new_dom_hit}")

    # Test 7: Urgency Language (10 points)
    total += 1
    urg_hit = signal_urgency_language("Your account will be suspended. Verify KYC immediately.")
    if urg_hit and urg_hit["points"] == 10:
        print("[PASS] Signal 7: Urgency Language (10 pts)")
        passed += 1
    else:
        print(f"[FAIL] Signal 7: Urgency Language -> {urg_hit}")

    # Test 8: Suspicious URL Shape (10 points)
    total += 1
    shape_hit = signal_url_shape("http://user@portal.account.login.security.novabank.xyz/verify")
    if shape_hit and shape_hit["points"] >= 5:
        print(f"[PASS] Signal 8: Suspicious URL Shape ({shape_hit['points']} pts)")
        passed += 1
    else:
        print(f"[FAIL] Signal 8: Suspicious URL Shape -> {shape_hit}")

    # Test 9: Legitimate Site (0 points / No false positives)
    total += 1
    legit_bm = signal_brand_mismatch("https://novabank.test/dashboard", "Welcome to Nova Bank.")
    legit_tf = signal_threat_feed("https://novabank.test/dashboard")
    legit_insec = signal_insecure_or_ip("https://novabank.test/dashboard")
    if legit_bm is None and legit_tf is None and legit_insec is None:
        print("[PASS] Test 9: Legitimate Domain Returns Zero False Positives")
        passed += 1
    else:
        print(f"[FAIL] Test 9: False positive on legitimate domain")

    # Test 10: SQLite Database Persistence
    total += 1
    init_db()
    test_scan = {
        "scan_id": "test-uuid-12345",
        "website": "http://novabank-kyc-verify.xyz",
        "score": 85,
        "verdict": "danger",
        "signals": [
            {"id": "brand_mismatch", "points": 30, "detail": "Test impersonation"}
        ],
        "created_at": "2026-11-14T12:00:00Z"
    }
    save_scan(test_scan)
    retrieved = get_scan("test-uuid-12345")
    recent = get_recent_scans(limit=10)

    if retrieved and retrieved["scan_id"] == "test-uuid-12345" and len(recent) > 0:
        print("[PASS] Test 10: SQLite Scans Table Save & Retrieval")
        passed += 1
    else:
        print(f"[FAIL] Test 10: SQLite Database Failed")

    # Test 11: Community Reporting (Report Button Feature)
    total += 1
    report_test_url = "http://test-phish-counter.xyz/login"
    initial_count = get_reports_count(report_test_url)
    updated_count = record_report(report_test_url)
    verified_count = get_reports_count(report_test_url)

    if updated_count == initial_count + 1 and verified_count == updated_count:
        print(f"[PASS] Test 11: Community Report Feature (Incremented to {verified_count})")
        passed += 1
    else:
        print(f"[FAIL] Test 11: Community Report Failed")

    print("=" * 65)
    print(f"RESULTS: {passed}/{total} Tests Passed ({100 * passed / total:.1f}%)")
    print("=" * 65)
    return passed == total


if __name__ == "__main__":
    import tempfile
    import database
    with tempfile.TemporaryDirectory() as temp_dir:
        database.DB_PATH = Path(temp_dir) / "tests.db"
        sys.exit(0 if run_tests() else 1)
