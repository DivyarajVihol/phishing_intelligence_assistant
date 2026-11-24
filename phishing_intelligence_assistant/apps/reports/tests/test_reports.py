"""Unit and security tests for reports generation and JSON export (Phase 15)."""
import json
import re
from datetime import datetime, timezone as dt_timezone

from django.test import TestCase
from django.utils import timezone

from apps.analysis.models import (
    FindingRecord,
    Investigation,
    MLPredictionRecord,
    ParsedURLRecord,
    ThreatIntelLookupRecord,
)
from apps.reports.builder import LIMITATION_NOTICE, SUGGESTED_NEXT_STEPS, build_report
from apps.url_analyzer.defang import defang_url


class TestReports(TestCase):
    """Test suite for HTML and JSON investigation reports."""

    def _create_investigation(
        self,
        url: str = "https://hostile-bank.example.com/login?token=abc",
        level: str = "high",
        score: int | None = 85,
        status: str = "completed",
    ) -> Investigation:
        """Create sample investigation with all relations."""
        inv = Investigation.objects.create(
            submitted_url=url,
            overall_level=level,
            score=score,
            status=status,
            summary=f"Assessment result for {level}.",
        )
        ParsedURLRecord.objects.create(
            investigation=inv,
            original=url,
            normalized=url,
            scheme="https",
            hostname="hostile-bank.example.com",
            registered_domain="example.com",
            subdomain="hostile-bank",
            suffix="com",
            path="/login",
            query="token=abc",
            is_ip_host=False,
        )
        ThreatIntelLookupRecord.objects.create(
            investigation=inv,
            source="phishtank",
            matched=True,
            query_status="match",
            source_record_id="pt-12345",
            queried_at=timezone.now(),
        )
        ThreatIntelLookupRecord.objects.create(
            investigation=inv,
            source="urlhaus",
            matched=False,
            query_status="no_match",
            source_record_id=None,
            queried_at=timezone.now(),
        )
        MLPredictionRecord.objects.create(
            investigation=inv,
            model_name="logistic_regression",
            model_version="model-v1",
            predicted_class="phishing_like",
            score=0.885,
            threshold=0.62,
        )
        FindingRecord.objects.create(
            investigation=inv,
            check_name="lexical.length",
            category="heuristic",
            status="flagged",
            severity="medium",
            explanation="URL is unusually long.",
        )
        FindingRecord.objects.create(
            investigation=inv,
            check_name="dns.rdap",
            category="enrichment",
            status="flagged",
            severity="low",
            explanation="Recently registered domain.",
        )
        FindingRecord.objects.create(
            investigation=inv,
            check_name="redirect.hops",
            category="enrichment",
            status="unavailable",
            severity="info",
            explanation="Redirect check disabled by configuration.",
        )
        return inv

    def test_builder_constructs_complete_report_dict(self) -> None:
        """Assert builder generates all required keys and structures."""
        inv = self._create_investigation()
        report = build_report(inv)

        self.assertEqual(report["report_id"], inv.id)
        self.assertEqual(report["title"], f"Investigation Report #{inv.id}")
        self.assertEqual(report["submitted_url_defanged"], defang_url(inv.submitted_url))
        self.assertEqual(report["submitted_url_raw"], inv.submitted_url)
        self.assertIn("T", report["generated_at"])  # ISO 8601
        self.assertEqual(report["assessment"]["level"], "high")
        self.assertGreater(len(report["local_findings"]), 0)
        self.assertGreater(len(report["enrichment_findings"]), 0)
        self.assertEqual(len(report["threat_intel"]), 2)
        self.assertIsNotNone(report["ml_prediction"])
        self.assertEqual(report["limitations"], LIMITATION_NOTICE)
        self.assertEqual(report["suggested_next_steps"], SUGGESTED_NEXT_STEPS)

    def test_html_report_contains_every_section(self) -> None:
        """Assert HTML report renders title, metadata, URL, assessment, intel, ML, next steps, and notice."""
        inv = self._create_investigation()
        response = self.client.get(f"/report/{inv.id}/")
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "reports/report.html")
        html = response.content.decode()

        self.assertIn(f"Investigation Report #{inv.id}", html)
        self.assertIn("Overall Assessment", html)
        self.assertIn("High risk", html)
        self.assertIn("Threat Intelligence Lookups", html)
        self.assertIn("PhishTank", html)
        self.assertIn("URLhaus", html)
        self.assertIn("malware intelligence matches", html)
        self.assertIn("Machine Learning Prediction", html)
        self.assertIn("logistic_regression", html)
        self.assertIn("Suggested Next Steps", html)
        self.assertIn(LIMITATION_NOTICE, html)
        self.assertIn("Print report", html)
        self.assertIn("Download JSON", html)

    def test_json_report_download_headers_and_content(self) -> None:
        """Assert JSON route serves download attachment with expected schema."""
        inv = self._create_investigation()
        response = self.client.get(f"/report/{inv.id}/json/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/json")
        self.assertEqual(
            response["Content-Disposition"], f'attachment; filename="report_{inv.id}.json"'
        )

        data = json.loads(response.content.decode("utf-8"))
        self.assertEqual(data["report_id"], inv.id)
        self.assertEqual(data["submitted_url_raw"], inv.submitted_url)
        self.assertEqual(data["submitted_url_defanged"], defang_url(inv.submitted_url))
        self.assertIn("generated_at", data)
        self.assertIn("parsed_components", data)
        self.assertIn("threat_intel", data)
        self.assertIn("ml_prediction", data)

        # Assert no secrets, detail links, or private feeds in JSON
        json_str = response.content.decode("utf-8")
        self.assertNotIn("detail", data["threat_intel"][0])
        self.assertNotIn("api_key", json_str.lower())
        self.assertNotIn("auth_key", json_str.lower())
        self.assertNotIn("secret", json_str.lower())

    def test_unknown_report_id_returns_404(self) -> None:
        """Assert requesting unknown ID returns 404 for both HTML and JSON."""
        resp_html = self.client.get("/report/999999/")
        self.assertEqual(resp_html.status_code, 404)

        resp_json = self.client.get("/report/999999/json/")
        self.assertEqual(resp_json.status_code, 404)

    def test_inconclusive_analysis_shows_no_score(self) -> None:
        """Assert inconclusive analysis hides score in both HTML and JSON."""
        inv = self._create_investigation(level="inconclusive", score=None)
        resp_html = self.client.get(f"/report/{inv.id}/")
        self.assertEqual(resp_html.status_code, 200)
        html = resp_html.content.decode()
        self.assertIn("Inconclusive", html)
        self.assertNotContains(resp_html, " / 100")

        resp_json = self.client.get(f"/report/{inv.id}/json/")
        data = json.loads(resp_json.content.decode("utf-8"))
        self.assertIsNone(data["assessment"]["score"])
        self.assertFalse(data["assessment"]["show_score"])

    def test_no_open_check_at_every_risk_level(self) -> None:
        """Assert NEVER-OPEN rule: raw URL never in HTML, no href to submitted data, neither Safe nor Confirmed malicious."""
        levels = [("high", 90), ("medium", 50), ("low_observed", 15), ("inconclusive", None)]
        raw_urls = [
            "https://hostile-bank1.xyz/auth?user=victim1",
            "https://hostile-bank2.xyz/auth?user=victim2",
            "https://hostile-bank3.xyz/auth?user=victim3",
            "https://hostile-bank4.xyz/auth?user=victim4",
        ]

        for (lvl, sc), raw in zip(levels, raw_urls):
            inv = self._create_investigation(url=raw, level=lvl, score=sc)
            response = self.client.get(f"/report/{inv.id}/")
            self.assertEqual(response.status_code, 200)
            html = response.content.decode()

            # Word "Safe" and "Confirmed malicious" must never appear
            self.assertNotRegex(
                re.sub(re.escape(LIMITATION_NOTICE), "", html), r"\bSafe\b"
            )
            self.assertNotIn("Confirmed malicious", html)

            # Defanged URL must appear, raw must not appear
            self.assertIn(defang_url(raw), html)
            self.assertNotIn(raw, html)

            # No links, iframes, images, or forms pointing to target host
            for tag in ("a", "iframe", "img", "form"):
                attr = "src" if tag in ("iframe", "img") else ("href" if tag == "a" else "action")
                matches = re.findall(rf'<{tag}[^>]*{attr}=["\']([^"\']+)["\']', html, re.IGNORECASE)
                for target in matches:
                    self.assertNotIn("hostile-bank", target)
                    self.assertNotIn("hxxp", target)

    def test_xss_url_is_escaped_in_html(self) -> None:
        """Assert malicious script tag in URL is escaped in HTML report."""
        xss_url = "https://example.com/test?q=<script>alert('xss')</script>"
        inv = self._create_investigation(url=xss_url)
        response = self.client.get(f"/report/{inv.id}/")
        self.assertEqual(response.status_code, 200)
        html = response.content.decode()

        self.assertNotIn("<script>alert('xss')</script>", html)
        self.assertIn("&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;", html)

    def test_dates_formatted_in_html_and_iso_in_json(self) -> None:
        """Assert dates in HTML use dd-Mon-yyyy while JSON retains ISO 8601 timestamps."""
        inv = self._create_investigation()
        # Set fixed timestamp: 2026-11-24 15:22 UTC
        fixed_dt = datetime(2026, 11, 24, 15, 22, tzinfo=dt_timezone.utc)
        Investigation.objects.filter(id=inv.id).update(submitted_at=fixed_dt)
        ThreatIntelLookupRecord.objects.filter(investigation=inv).update(queried_at=fixed_dt)

        resp_html = self.client.get(f"/report/{inv.id}/")
        html = resp_html.content.decode()
        self.assertIn("24-Nov-2026 03:22 PM", html)

        resp_json = self.client.get(f"/report/{inv.id}/json/")
        data = json.loads(resp_json.content.decode("utf-8"))
        self.assertIn("2026-11-24T15:22:00+00:00", data["submitted_at"])
        self.assertIn("2026-11-24T15:22:00+00:00", data["threat_intel"][0]["queried_at"])
