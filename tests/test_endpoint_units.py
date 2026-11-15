"""Endpoint-function tests for environments where socket-based TestClient cannot run."""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from pydantic import ValidationError
from fastapi import HTTPException

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
import database
_TEMP = tempfile.TemporaryDirectory()
database.DB_PATH = Path(_TEMP.name) / "endpoints.db"
import app
database.init_db()


class EndpointTests(unittest.TestCase):
    def test_reject_malformed_scan_inputs(self):
        for value in [{"url": 123}, {"url": "garbage"}, {"url": "javascript:alert(1)"},
                      {"url": "https://example.test", "forms": [None]}, {}]:
            with self.subTest(value=value), self.assertRaises(ValidationError):
                app.AnalyzeRequest.model_validate(value)

    def test_legacy_url_and_server_snippet_limit(self):
        request = app.AnalyzeRequest.model_validate({
            "website": "https://github.com/login", "text_snippet": "x" * 3000})
        data = app.analyze(request)
        self.assertEqual(data["score"], 0)
        self.assertEqual(len(database.get_scan(data["scan_id"])["text_snippet"]), 1500)

    def test_trusted_domain_threat_is_not_bypassed(self):
        with patch.object(app, "signal_threat_feed", return_value={
            "id": "threat_feed_hit", "points": 100, "detail": "Confirmed threat"
        }):
            data = app.analyze(app.AnalyzeRequest(url="https://github.com/login"))
        self.assertEqual(data["verdict"], "danger")

    def test_trusted_domain_insecure_form_is_checked(self):
        request = app.AnalyzeRequest(url="https://github.com/login",
                                    forms=[{"action": "http://collector.test"}])
        data = app.analyze(request)
        self.assertTrue(any(s["id"] == "form_action_mismatch" for s in data["signals"]))

    def test_reports_refresh_cached_explanation(self):
        scan = app.analyze(app.AnalyzeRequest(url="https://github.com/report-units"))
        with patch.object(app, "explain", return_value={
            "verdict": "safe", "reasons": ["No signals"], "advice": "Verify site", "confidence": 0.75}):
            app.explain_scan(scan["scan_id"])
            report = app.report_phishing_url(app.ReportRequest(url=scan["url"]))
            second = app.explain_scan(scan["scan_id"])
        self.assertEqual(second["reports_count"], report["reports_count"])
        self.assertEqual(second["scan_id"], scan["scan_id"])
        self.assertTrue(any("Community Warning:" in r for r in second["reasons"]))

    def test_redirect_validation_and_threat_precedence(self):
        for value in [123, "javascript:alert(1)", "https://example.test:bad"]:
            with self.subTest(value=value), self.assertRaises(HTTPException) as caught:
                app.check_redirect(url=value, opener=None, payload=None)
            self.assertEqual(caught.exception.status_code, 422)
        with patch.object(app, "_is_allowlisted", return_value=True):
            result = app.check_redirect(url="https://malicious-phish-bank.com", opener=None, payload=None)
        self.assertTrue(result["blocked"])

    def test_events_omit_page_text(self):
        app.analyze(app.AnalyzeRequest(url="https://github.com", text_snippet="private page text"))
        self.assertTrue(all("text_snippet" not in scan for scan in app.events(limit=50)))

    def test_demo_detection_is_not_weakened(self):
        import json
        sample = Path(__file__).resolve().parents[1] / "backend/samples/fake_payload.json"
        with patch.object(app, "signal_new_domain", return_value=None):
            result = app.analyze(app.AnalyzeRequest.model_validate(json.loads(sample.read_text())))
        self.assertEqual(result["verdict"], "danger")


if __name__ == "__main__":
    unittest.main()
