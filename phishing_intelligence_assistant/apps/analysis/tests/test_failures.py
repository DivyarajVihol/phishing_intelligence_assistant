"""Failure scenario and resiliency tests (Phase 16)."""
import json
from unittest.mock import patch

from django.test import TestCase, override_settings
import requests

from apps.analysis.models import Investigation
from apps.ml_engine.predict import ModelUnavailable
from apps.threat_intel.service import clear_cache


class TestFailureScenariosAndResiliency(TestCase):
    """End-to-end tests for network failures, missing artifacts, and invalid input."""

    def setUp(self) -> None:
        """Clear threat intel in-memory cache before each test."""
        clear_cache()

    @patch("apps.threat_intel.phishtank.requests.post")
    @patch("apps.threat_intel.urlhaus.requests.post")
    def test_intel_timeouts_and_errors(self, mock_uh_post, mock_pt_post) -> None:
        """Assert timeouts in threat intel render Unavailable badges without 500."""
        mock_pt_post.side_effect = requests.exceptions.Timeout("PhishTank timed out")
        mock_uh_post.side_effect = requests.exceptions.Timeout("URLhaus timed out")

        response = self.client.post("/", {"url": "https://timeout-test.org/login"}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "analysis/result.html")

        html = response.content.decode()
        self.assertIn("Unavailable", html)

        inv = response.context["investigation"]
        self.assertIn(inv.overall_level, ("inconclusive", "low_observed", "medium", "high"))
        for lk in inv.threat_lookups.all():
            self.assertEqual(lk.query_status, "unavailable")

        # Verify HTML and JSON reports render successfully
        rep_resp = self.client.get(f"/report/{inv.id}/")
        self.assertEqual(rep_resp.status_code, 200)
        json_resp = self.client.get(f"/report/{inv.id}/json/")
        self.assertEqual(json_resp.status_code, 200)
        self.assertEqual(json.loads(json_resp.content.decode())["report_id"], inv.id)

    @patch("apps.analysis.services.predict")
    def test_ml_model_file_missing(self, mock_predict) -> None:
        """Assert missing ML artifacts show Unavailable without crashing analysis."""
        mock_predict.side_effect = ModelUnavailable("Model artifact not found")

        response = self.client.post("/", {"url": "https://no-model-test.org/check"}, follow=True)
        self.assertEqual(response.status_code, 200)

        inv = response.context["investigation"]
        self.assertIsNotNone(inv.id)
        self.assertEqual(inv.ml_predictions.count(), 0)

        html = response.content.decode()
        self.assertIn("Machine learning prediction is not available", html)
        self.assertIn("Unavailable", html)

    @patch("apps.analysis.services.predict")
    @patch("apps.threat_intel.phishtank.requests.post")
    @patch("apps.threat_intel.urlhaus.requests.post")
    def test_both_intel_and_model_down(self, mock_uh, mock_pt, mock_ml) -> None:
        """Assert page renders cleanly when all intel and ML services fail simultaneously."""
        mock_pt.side_effect = requests.exceptions.RequestException("PT failure")
        mock_uh.side_effect = requests.exceptions.RequestException("UH failure")
        mock_ml.side_effect = ModelUnavailable("Model missing")

        response = self.client.post("/", {"url": "https://all-down-test.org/auth"}, follow=True)
        self.assertEqual(response.status_code, 200)

        inv = response.context["investigation"]
        self.assertIsNotNone(inv.id)
        self.assertTemplateUsed(response, "analysis/result.html")

    def test_malformed_inputs_rejected(self) -> None:
        """Assert invalid, malformed, or hostile input schemes are blocked at the form."""
        bad_inputs = [
            "",
            "   ",
            "https://example.com/" + "a" * 2100,
            "ftp://example.com/file",
            "not a valid url with spaces",
            "javascript:alert(1)",
            "data:text/html,test",
            "https://" + "h" * 2100 + ".org/auth",
        ]
        for bad in bad_inputs:
            with self.subTest(url=bad[:25]):
                count_before = Investigation.objects.count()
                resp = self.client.post("/", {"url": bad})
                self.assertEqual(resp.status_code, 200)
                self.assertTemplateUsed(resp, "analysis/submit.html")
                self.assertTrue(resp.context["form"].errors)
                self.assertEqual(Investigation.objects.count(), count_before)

    @override_settings(URLHAUS_AUTH_KEY="")
    def test_missing_urlhaus_key_not_configured(self) -> None:
        """Assert missing URLhaus key is marked not configured, never no match."""
        response = self.client.post("/", {"url": "https://no-key-test.com/path"}, follow=True)
        self.assertEqual(response.status_code, 200)

        html = response.content.decode()
        self.assertIn("Not configured", html)

        inv = response.context["investigation"]
        uh = inv.threat_lookups.filter(source="urlhaus").first()
        self.assertIsNotNone(uh)
        self.assertEqual(uh.query_status, "not_configured")
        self.assertNotEqual(uh.query_status, "no_match")

    def test_prohibited_words_never_appear(self) -> None:
        """Assert prohibited terminology ('Safe', 'Confirmed malicious') is never rendered."""
        inv = Investigation.objects.create(
            submitted_url="https://audit-clean.com/home",
            overall_level="low_observed",
            score=10,
            status="completed",
        )
        for endpoint in (f"/result/{inv.id}/", "/history/", "/dashboard/", f"/report/{inv.id}/"):
            with self.subTest(endpoint=endpoint):
                resp = self.client.get(endpoint)
                self.assertEqual(resp.status_code, 200)
                html = resp.content.decode()
                self.assertNotRegex(html, r"\bSafe\b")
                self.assertNotIn("Confirmed malicious", html)
