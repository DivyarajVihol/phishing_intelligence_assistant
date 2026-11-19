"""Unit and security tests for analysis views and templates."""
import re
from unittest.mock import MagicMock, patch

from django.test import TestCase

from apps.analysis.models import (
    FindingRecord,
    Investigation,
    MLPredictionRecord,
    ParsedURLRecord,
    ThreatIntelLookupRecord,
)
from apps.analysis.services import analyse_url
from apps.core.types import ThreatLookup
from apps.url_analyzer.defang import defang_url

LIMITATION_NOTICE = (
    "These results are indicators for investigation. They do not independently establish that a "
    "website is malicious or safe. A missing threat-feed record does not mean a URL is safe."
)


class TestAnalysisViews(TestCase):
    """Test suite for submit and result pages, including NEVER-OPEN security checks."""

    def _mock_no_match(self, parsed: object, settings: object) -> list[ThreatLookup]:
        return [
            ThreatLookup(source="phishtank", status="no_match"),
            ThreatLookup(source="urlhaus", status="no_match"),
        ]

    def test_get_submit_page_returns_200(self) -> None:
        """Assert GET request on '/' renders the submission page with 200."""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "analysis/submit.html")
        self.assertContains(response, "PhishTank and URLhaus")

    @patch("apps.threat_intel.service.query_sources")
    def test_valid_post_redirects_to_result(self, mock_query: MagicMock) -> None:
        """Assert valid POST submission creates investigation and redirects to /result/<id>/."""
        mock_query.side_effect = self._mock_no_match
        response = self.client.post("/", {"url": "https://example.com/login"})

        self.assertEqual(response.status_code, 302)
        location = response["Location"]
        self.assertTrue(location.startswith("/result/"))

        investigation_id = int(location.strip("/").split("/")[-1])
        self.assertTrue(Investigation.objects.filter(id=investigation_id).exists())

    def test_invalid_input_shows_message_and_saves_nothing(self) -> None:
        """Assert invalid URL shows error message and does not persist records."""
        response = self.client.post("/", {"url": "ftp://unsupported.com"})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Unsupported scheme")
        self.assertEqual(Investigation.objects.count(), 0)

    @patch("apps.threat_intel.service.query_sources")
    def test_result_page_contains_evidence_sections_and_unavailable(
        self, mock_query: MagicMock
    ) -> None:
        """Assert result page contains all required sections including unavailable checks."""
        mock_query.return_value = [
            ThreatLookup(source="phishtank", status="unavailable", error="Timeout"),
            ThreatLookup(source="urlhaus", status="no_match"),
        ]
        investigation = analyse_url("https://example.com/test")

        response = self.client.get(f"/result/{investigation.id}/")
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "analysis/result.html")

        # Section 1: Assessment
        self.assertContains(response, "Overall Assessment")
        self.assertContains(response, "Points Breakdown")
        self.assertContains(response, "Based on")

        # Section 2: Threat Intelligence
        self.assertContains(response, "Threat Intelligence")
        self.assertContains(response, "phishtank")

        # Section 3: Local Findings
        self.assertContains(response, "Local URL and Obfuscation Findings")

        # Section 4: Machine Learning
        self.assertContains(response, "Machine Learning Prediction")

        # Section 6: Unavailable checks
        self.assertContains(response, "Unavailable / Not Completed Checks")

        # Section 7: Parsed components
        self.assertContains(response, "Parsed URL Components")

        # Section 8: Limitation notice
        self.assertContains(response, LIMITATION_NOTICE)

    @patch("apps.threat_intel.service.query_sources")
    def test_result_threat_intel_no_match_with_record_id_and_ml_labels(
        self, mock_query: MagicMock
    ) -> None:
        """Assert record ID on no_match shows clarification text and ML labels are formatted."""
        mock_query.return_value = [
            ThreatLookup(source="phishtank", status="no_match", record_id="99999"),
            ThreatLookup(source="urlhaus", status="no_match"),
        ]
        investigation = analyse_url("https://example.com/test")

        response = self.client.get(f"/result/{investigation.id}/")
        self.assertEqual(response.status_code, 200)
        html = response.content.decode()

        # Record ID on no_match plain text
        self.assertIn("<code>99999</code>", html)
        self.assertIn("Reported to this source but not confirmed as phishing", html)
        self.assertNotIn('href="99999"', html)

        # ML label and note
        self.assertIn("Not phishing-like", html)
        self.assertIn(
            "This model only looks at the domain name, so it can miss phishing hosted on shared platforms. It is a supporting signal only.",
            html,
        )
        self.assertNotIn(">benign<", html)

    def test_result_page_ml_phishing_like_label(self) -> None:
        """Assert ML predicted_class phishing_like displays as Phishing-like."""
        inv = Investigation.objects.create(
            submitted_url="https://phish.target.com",
            status="completed",
            overall_level="high",
            score=80,
            summary="High risk.",
        )
        ParsedURLRecord.objects.create(
            investigation=inv,
            original="https://phish.target.com",
            normalized="https://phish.target.com/",
            scheme="https",
            hostname="phish.target.com",
            registered_domain="target.com",
        )
        MLPredictionRecord.objects.create(
            investigation=inv,
            model_name="domain-lr",
            model_version="1.0.0",
            score=0.95,
            threshold=0.62,
            predicted_class="phishing_like",
        )
        response = self.client.get(f"/result/{inv.id}/")
        self.assertEqual(response.status_code, 200)
        html = response.content.decode()
        self.assertIn("Phishing-like", html)
        self.assertNotIn(">phishing_like<", html)

    def test_inconclusive_shows_no_score(self) -> None:
        """Assert inconclusive investigation with score None hides score line."""
        investigation = Investigation.objects.create(
            submitted_url="https://unknown-site.xyz",
            status="completed",
            overall_level="inconclusive",
            score=None,
            summary="Inconclusive: Insufficient check coverage.",
        )
        ParsedURLRecord.objects.create(
            investigation=investigation,
            original="https://unknown-site.xyz",
            normalized="https://unknown-site.xyz/",
            scheme="https",
            hostname="unknown-site.xyz",
            registered_domain="unknown-site.xyz",
        )
        FindingRecord.objects.create(
            investigation=investigation,
            check_name="lexical.check",
            category="heuristic",
            status="unavailable",
            severity="info",
            explanation="Module unavailable",
        )

        response = self.client.get(f"/result/{investigation.id}/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Inconclusive")
        self.assertNotContains(response, " / 100")
        self.assertNotContains(response, "higher means more suspicious")

    def test_no_open_check_at_every_risk_level(self) -> None:
        """Assert NEVER-OPEN rules: no href/iframe/img/action pointing to submitted URL."""
        test_levels = [
            ("high", 85),
            ("medium", 45),
            ("low_observed", 10),
            ("inconclusive", None),
        ]
        raw_url = "https://hostile-phish-target.example.com/login?token=abc"
        defanged = defang_url(raw_url)

        for level, score in test_levels:
            with self.subTest(level=level):
                inv = Investigation.objects.create(
                    submitted_url=raw_url,
                    status="completed",
                    overall_level=level,
                    score=score,
                    summary=f"Analysis summary for {level}.",
                )
                ParsedURLRecord.objects.create(
                    investigation=inv,
                    original=raw_url,
                    normalized="https://hostile-phish-target.example.com/login?token=abc",
                    scheme="https",
                    hostname="hostile-phish-target.example.com",
                    registered_domain="example.com",
                    path="/login",
                    query="token=abc",
                )
                FindingRecord.objects.create(
                    investigation=inv,
                    check_name="lexical.test",
                    category="heuristic",
                    status="flagged" if level == "high" else "clear",
                    severity="high" if level == "high" else "info",
                    explanation="Sample check",
                )

                response = self.client.get(f"/result/{inv.id}/")
                self.assertEqual(response.status_code, 200)
                html = response.content.decode()

                # Defanged URL must appear
                self.assertIn(defanged, html)

                # Raw submitted URL string must NOT appear anywhere in the HTML
                self.assertNotIn(raw_url, html)

                # Assert no clickable links, iframe, img, or form action pointing to submitted host
                for tag in ("a", "iframe", "img", "form"):
                    attr = "src" if tag in ("iframe", "img") else ("href" if tag == "a" else "action")
                    matches = re.findall(rf'<{tag}[^>]*{attr}=["\']([^"\']+)["\']', html, re.IGNORECASE)
                    for target in matches:
                        self.assertNotIn("hostile-phish-target.example.com", target)
                        self.assertNotIn("hxxp", target)

    def test_xss_url_is_escaped(self) -> None:
        """Assert malicious script tags in submitted URLs are HTML-escaped."""
        xss_url = "http://example.com/search?q=<script>alert('xss')</script>"
        inv = Investigation.objects.create(
            submitted_url=xss_url,
            status="completed",
            overall_level="medium",
            score=30,
            summary="Medium risk.",
        )
        ParsedURLRecord.objects.create(
            investigation=inv,
            original=xss_url,
            normalized="http://example.com/search?q=%3Cscript%3Ealert('xss')%3C/script%3E",
            scheme="http",
            hostname="example.com",
            registered_domain="example.com",
        )

        response = self.client.get(f"/result/{inv.id}/")
        self.assertEqual(response.status_code, 200)
        html = response.content.decode()
        self.assertNotIn("<script>alert('xss')</script>", html)
        self.assertIn("&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;", html)

    def test_word_safe_never_appears_in_result_page(self) -> None:
        """Assert word 'safe' never appears outside of the verbatim limitation notice."""
        levels = ["high", "medium", "low_observed", "inconclusive"]
        for level in levels:
            inv = Investigation.objects.create(
                submitted_url="https://clean-site.org",
                status="completed",
                overall_level=level,
                score=10 if level != "inconclusive" else None,
                summary=f"Assessment result for {level}.",
            )
            ParsedURLRecord.objects.create(
                investigation=inv,
                original="https://clean-site.org",
                normalized="https://clean-site.org/",
                scheme="https",
                hostname="clean-site.org",
                registered_domain="clean-site.org",
            )
            FindingRecord.objects.create(
                investigation=inv,
                check_name="lexical.length",
                category="heuristic",
                status="clear",
                severity="info",
                explanation="Length within acceptable bounds.",
            )

            response = self.client.get(f"/result/{inv.id}/")
            self.assertEqual(response.status_code, 200)
            html = response.content.decode()

            # Ensure 'safe' is never used as badge, status, or level
            self.assertNotIn("badge--safe", html)
            self.assertNotIn("status: safe", html.lower())
            self.assertNotIn("verdict: safe", html.lower())

            # Remove all occurrences of the verbatim limitation notice from HTML
            # and verify the word 'safe' does not appear anywhere else
            notice_pattern = re.compile(re.escape(LIMITATION_NOTICE), re.IGNORECASE)
            html_without_notice = notice_pattern.sub("", html)
            self.assertNotIn("safe", html_without_notice.lower())
