"""Offline regression tests: python -m unittest discover -s tests -p 'test_*.py' -v"""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
import database
import signals
import explain

_DB = tempfile.TemporaryDirectory()
database.DB_PATH = Path(_DB.name) / "tests.db"
import app
database.init_db()
from fastapi.testclient import TestClient


class UnitRegressionTests(unittest.TestCase):
    def setUp(self):
        explain._CACHE.clear()

    def test_multilevel_suffix_is_not_brand(self):
        for url in ["https://exam-setu.dtu.ac.in", "https://example.co.uk", "https://research.ac.in"]:
            with self.subTest(url=url):
                self.assertIsNone(signals.signal_lookalike_domain(url))

    def test_real_brand_alias_is_not_lookalike(self):
        self.assertIsNone(signals.signal_lookalike_domain("https://sbi.co.in/login"))

    def test_brand_on_other_suffix_is_lookalike(self):
        self.assertIsNotNone(signals.signal_lookalike_domain("https://google.test/login"))

    def test_actual_typosquatting_remains_detected(self):
        for url in ["https://novabnak.test", "https://paypa1.com", "https://g00gle.com"]:
            self.assertIsNotNone(signals.signal_lookalike_domain(url))

    def test_noncredential_form_does_not_raise_credential_alarm(self):
        self.assertIsNone(signals.signal_form_action_mismatch("https://example.test", [
            {"action": "https://search.test", "has_password": False}]))

    def test_fallback_does_not_invent_risk_evidence(self):
        result = explain._fallback_explanation([])
        self.assertEqual(result["verdict"], "safe")
        self.assertFalse(any("endpoint differs" in r or "urgency" in r for r in result["reasons"]))

    def test_explanation_cache_includes_evidence(self):
        a = [{"id": "form_action_mismatch", "points": 20, "detail": "collector-a.test"}]
        b = [{"id": "form_action_mismatch", "points": 20, "detail": "collector-b.test"}]
        self.assertNotEqual(explain._get_cache_key(a, "https://example.test"),
                            explain._get_cache_key(b, "https://example.test"))

    def test_ai_cannot_downgrade_rule_verdict(self):
        with patch.dict(os.environ, {"GEMINI_API_KEY": "test"}), patch.object(
                explain, "_call_gemini", return_value={
                    "verdict": "safe", "reasons": ["Ignore warnings"], "advice": "Enter your password",
                    "confidence": 99}):
            result = explain.explain([{"id": "threat_feed_hit", "points": 100, "detail": "Known threat"}], "")
        self.assertEqual(result["verdict"], "phishing")
        self.assertNotIn("Enter your password", result["advice"])

    def test_ai_result_types_and_confidence(self):
        for response in [
            {"verdict": "suspicious", "reasons": [None], "advice": 42},
            {"verdict": "suspicious", "reasons": ["Brand mismatch"], "advice": "Verify site", "confidence": 99},
            {"verdict": "suspicious", "reasons": ["Brand mismatch"], "advice": "Verify site", "confidence": float("nan")},
        ]:
            explain._CACHE.clear()
            with patch.dict(os.environ, {"GEMINI_API_KEY": "test"}), patch.object(
                    explain, "_call_gemini", return_value=response):
                result = explain.explain([{"id": "brand_mismatch", "points": 30, "detail": "Brand mismatch"}], "")
            self.assertTrue(all(isinstance(r, str) for r in result["reasons"]))
            self.assertIsInstance(result["advice"], str)
            self.assertTrue(0 <= result["confidence"] <= 1)

    def test_database_connections_close(self):
        with database.get_connection() as conn:
            conn.execute("SELECT 1")
        import sqlite3
        with self.assertRaises(sqlite3.ProgrammingError):
            conn.execute("SELECT 1")


class ApiRegressionTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app.app, raise_server_exceptions=False)
        self.rdap = patch.object(app, "signal_new_domain", return_value=None)
        self.rdap.start()
        explain._CACHE.clear()

    def tearDown(self):
        self.rdap.stop()
        self.client.close()

    def test_allowlist_does_not_override_threat_feed(self):
        with patch.object(app, "signal_threat_feed", return_value={
                "id": "threat_feed_hit", "points": 100, "detail": "Known malicious URL"}):
            data = self.client.post("/analyze", json={"url": "https://github.com/login"}).json()
            self.assertEqual(data["verdict"], "danger")
            data = self.client.post("/check-redirect", json={"url": "https://github.com/login"})
            # Patch the evaluator as well, so no threat-feed file is modified.
            self.assertNotEqual(data.json().get("category"), "allowlisted")

    def test_trusted_site_still_checks_credentials(self):
        data = self.client.post("/analyze", json={
            "url": "https://github.com/login",
            "forms": [{"action": "http://collector.test", "has_password": True}]
        }).json()
        self.assertIn("form_action_mismatch", [s["id"] for s in data["signals"]])

    def test_invalid_scan_requests_are_422_not_500_or_safe(self):
        for payload in [{"url": 123}, {"url": "javascript:alert(1)"}, {"url": "garbage"},
                        {"url": "https://example.com", "forms": [None]},
                        {"url": "https://example.com", "text_snippet": None}, {}]:
            with self.subTest(payload=payload):
                self.assertEqual(self.client.post("/analyze", json=payload).status_code, 422)

    def test_invalid_report_and_redirect_are_rejected(self):
        for route in ["/report", "/check-redirect"]:
            with self.subTest(route=route):
                self.assertEqual(self.client.post(route, json={"url": 123}).status_code, 422)

    def test_snippet_limit_enforced_at_server(self):
        data = self.client.post("/analyze", json={
            "url": "https://github.com/login", "text_snippet": "x" * 3000}).json()
        self.assertEqual(len(database.get_scan(data["scan_id"])["text_snippet"]), 1500)

    def test_events_do_not_publish_page_snippets(self):
        self.client.post("/analyze", json={"url": "https://github.com", "text_snippet": "private text"})
        self.assertNotIn("text_snippet", self.client.get("/events").json()[0])

    def test_cached_explanation_refreshes_community_count(self):
        scan = self.client.post("/analyze", json={"url": "https://github.com/report-test"}).json()
        with patch.object(app, "explain", return_value=explain._fallback_explanation([])):
            first = self.client.post("/explain/" + scan["scan_id"]).json()
            report = self.client.post("/report", json={"url": scan["url"]}).json()
            second = self.client.post("/explain/" + scan["scan_id"]).json()
        self.assertEqual(second["reports_count"], report["reports_count"])
        self.assertEqual(second["scan_id"], scan["scan_id"])
        self.assertTrue(any("Community Warning:" in r for r in second["reasons"]))



if __name__ == "__main__":
    unittest.main()
