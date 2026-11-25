"""Unit and security tests for PDF investigation report downloads."""
import json
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.analysis.models import (
    FindingRecord,
    Investigation,
    MLPredictionRecord,
    ParsedURLRecord,
    ThreatIntelLookupRecord,
)
from apps.reports.builder import build_report
from apps.reports.pdf_sections import extract_report_text_lines


def _create_investigation(
    url: str = "https://phish-test.xyz/login?a=1&b=2",
    level: str = "high",
    score: int | None = 85,
) -> Investigation:
    """Create a complete Investigation fixture with related records."""
    inv = Investigation.objects.create(
        submitted_url=url, overall_level=level, score=score,
        summary="Test summary.", status="completed", model_version="v2",
    )
    ParsedURLRecord.objects.create(
        investigation=inv, original=url, normalized=url, scheme="https",
        scheme_assumed=False, hostname="phish-test.xyz", subdomain="",
        registered_domain="phish-test.xyz", suffix="xyz", port=None,
        userinfo="", path="/login", query="a=1&b=2", fragment="", is_ip_host=False,
    )
    FindingRecord.objects.create(
        investigation=inv, check_name="lexical.keywords", category="heuristic",
        status="flagged", severity="medium", explanation="Keyword 'login' found.",
        evidence={}, source="lexical",
    )
    ThreatIntelLookupRecord.objects.create(
        investigation=inv, source="phishtank", queried_at=timezone.now(),
        query_status="no_match", matched=False, source_record_id="",
    )
    MLPredictionRecord.objects.create(
        investigation=inv, model_name="logistic_regression", model_version="v2",
        predicted_class="phishing_like", score=0.91, threshold=0.7771,
    )
    return inv


class TestPdfReport(TestCase):
    """Test suite for PDF report generation, security, and UI links."""

    def test_pdf_download_headers_and_magic_bytes(self) -> None:
        """Assert GET /report/<id>/pdf/ returns 200 PDF starting with %PDF and ending with %%EOF."""
        inv = _create_investigation()
        resp = self.client.get(reverse("report_pdf", args=[inv.id]))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp["Content-Type"], "application/pdf")
        self.assertEqual(resp["Content-Disposition"], f'attachment; filename="investigation-report-{inv.id}.pdf"')
        self.assertTrue(resp.content.startswith(b"%PDF"))
        self.assertTrue(resp.content.rstrip().endswith(b"%%EOF"))

    def test_pdf_unknown_id_returns_404(self) -> None:
        """Assert unknown investigation ID returns 404."""
        resp = self.client.get("/report/999999/pdf/")
        self.assertEqual(resp.status_code, 404)

    def test_pdf_contains_no_links_uri_or_js(self) -> None:
        """Assert generated PDF bytes contain no /URI, /Link, or /JS objects."""
        inv = _create_investigation()
        resp = self.client.get(reverse("report_pdf", args=[inv.id]))
        for forbidden in (b"/URI", b"/Link", b"/JS"):
            self.assertNotIn(forbidden, resp.content)

    def test_pdf_escapes_script_and_ampersand_in_url(self) -> None:
        """Assert URL containing <script> and & builds without markup errors."""
        inv = _create_investigation(url="https://evil-xss.com/<script>alert(1)</script>&x=1")
        resp = self.client.get(reverse("report_pdf", args=[inv.id]))
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.content.startswith(b"%PDF"))

    def test_inconclusive_pdf_omits_score(self) -> None:
        """Assert Inconclusive report builds cleanly and omits numeric score line."""
        inv = _create_investigation(level="inconclusive", score=None)
        report = build_report(inv)
        lines = "\n".join(extract_report_text_lines(report))
        self.assertIn("Inconclusive", lines)
        self.assertNotIn("higher means more suspicious", lines)
        resp = self.client.get(reverse("report_pdf", args=[inv.id]))
        self.assertEqual(resp.status_code, 200)

    def test_raw_url_not_in_extracted_pdf_text_lines(self) -> None:
        """Assert raw submitted URL is absent from pure PDF text lines (defanged only)."""
        raw_url = "https://secret-phish.example.com/login?token=abc&x=1"
        inv = _create_investigation(url=raw_url)
        report = build_report(inv)
        joined = "\n".join(extract_report_text_lines(report))
        self.assertNotIn(raw_url, joined)
        self.assertIn(report["submitted_url_defanged"], joined)

    def test_result_page_has_download_pdf_and_no_view_report(self) -> None:
        """Assert result page links to Download PDF and not View report, and JSON still works."""
        inv = _create_investigation()
        res_html = self.client.get(reverse("result", args=[inv.id])).content.decode()
        self.assertIn("Download PDF", res_html)
        self.assertIn(reverse("report_pdf", args=[inv.id]), res_html)
        self.assertNotIn("View report", res_html)
        json_resp = self.client.get(reverse("report_json", args=[inv.id]))
        self.assertEqual(json_resp.status_code, 200)
        self.assertEqual(json.loads(json_resp.content.decode())["report_id"], inv.id)
