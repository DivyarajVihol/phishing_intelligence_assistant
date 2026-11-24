"""Unit and security tests for dashboard metrics visualization (Phase 14)."""
from datetime import timedelta
import re

from django.test import TestCase
from django.utils import timezone

from apps.analysis.models import (
    FindingRecord,
    Investigation,
    MLPredictionRecord,
    ParsedURLRecord,
    ThreatIntelLookupRecord,
)
from apps.dashboard.metrics import get_dashboard_metrics
from apps.url_analyzer.defang import defang_url


class TestDashboardMetricsAndSecurity(TestCase):
    """Test suite for metrics calculation, dashboard view, and NEVER-OPEN security."""

    def _create_sample_data(self) -> None:
        """Create structured known investigation records for metric validation."""
        today = timezone.localdate()

        # Inv 1: High risk, phishtank match, ML phishing_like
        inv1 = Investigation.objects.create(
            submitted_url="https://hostile-bank.com/login",
            overall_level="high",
            score=95,
            status="completed",
        )
        ParsedURLRecord.objects.create(
            investigation=inv1,
            original="https://hostile-bank.com/login",
            normalized="https://hostile-bank.com/login",
            scheme="https",
            hostname="hostile-bank.com",
            registered_domain="hostile-bank.com",
            suffix="com",
        )
        ThreatIntelLookupRecord.objects.create(
            investigation=inv1, source="phishtank", matched=True, query_status="match"
        )
        ThreatIntelLookupRecord.objects.create(
            investigation=inv1, source="urlhaus", matched=False, query_status="no_match"
        )
        MLPredictionRecord.objects.create(
            investigation=inv1,
            model_name="baseline",
            model_version="v1",
            predicted_class="phishing_like",
            score=0.92,
            threshold=0.62,
        )
        FindingRecord.objects.create(
            investigation=inv1,
            check_name="lexical.length",
            category="heuristic",
            status="flagged",
            severity="high",
        )
        FindingRecord.objects.create(
            investigation=inv1,
            check_name="intel.phishtank",
            category="intel",
            status="flagged",
            severity="high",
        )

        # Inv 2: Medium risk, URLhaus match, ML benign, 2 days ago
        inv2 = Investigation.objects.create(
            submitted_url="https://malware-drop.org/payload.exe",
            overall_level="medium",
            score=45,
            status="completed",
        )
        Investigation.objects.filter(id=inv2.id).update(
            submitted_at=timezone.now() - timedelta(days=2)
        )
        ParsedURLRecord.objects.create(
            investigation=inv2,
            original="https://malware-drop.org/payload.exe",
            normalized="https://malware-drop.org/payload.exe",
            scheme="https",
            hostname="malware-drop.org",
            registered_domain="malware-drop.org",
            suffix="org",
        )
        ThreatIntelLookupRecord.objects.create(
            investigation=inv2, source="phishtank", matched=False, query_status="no_match"
        )
        ThreatIntelLookupRecord.objects.create(
            investigation=inv2, source="urlhaus", matched=True, query_status="match"
        )
        MLPredictionRecord.objects.create(
            investigation=inv2,
            model_name="baseline",
            model_version="v1",
            predicted_class="benign",
            score=0.15,
            threshold=0.62,
        )
        FindingRecord.objects.create(
            investigation=inv2,
            check_name="lexical.length",
            category="heuristic",
            status="clear",
            severity="info",
        )
        FindingRecord.objects.create(
            investigation=inv2,
            check_name="obfuscation.encoding",
            category="heuristic",
            status="flagged",
            severity="medium",
        )

        # Inv 3: Low observed risk, no matches, ML unavailable
        inv3 = Investigation.objects.create(
            submitted_url="https://portal.net/index",
            overall_level="low_observed",
            score=10,
            status="completed",
        )
        ParsedURLRecord.objects.create(
            investigation=inv3,
            original="https://portal.net/index",
            normalized="https://portal.net/index",
            scheme="https",
            hostname="portal.net",
            registered_domain="portal.net",
            suffix="net",
        )
        ThreatIntelLookupRecord.objects.create(
            investigation=inv3, source="phishtank", matched=False, query_status="no_match"
        )
        ThreatIntelLookupRecord.objects.create(
            investigation=inv3, source="urlhaus", matched=False, query_status="no_match"
        )
        FindingRecord.objects.create(
            investigation=inv3,
            check_name="ml.prediction",
            category="ml",
            status="unavailable",
            severity="info",
        )

        # Inv 4: Inconclusive risk, check not run
        inv4 = Investigation.objects.create(
            submitted_url="https://portal.net/other",
            overall_level="inconclusive",
            score=None,
            status="completed",
        )
        ParsedURLRecord.objects.create(
            investigation=inv4,
            original="https://portal.net/other",
            normalized="https://portal.net/other",
            scheme="https",
            hostname="portal.net",
            registered_domain="portal.net",
            suffix="net",
        )
        FindingRecord.objects.create(
            investigation=inv4,
            check_name="dns.lookup",
            category="enrichment",
            status="not_run",
            severity="info",
        )

    def test_dashboard_empty_state(self) -> None:
        """Assert empty state renders cleanly when 0 investigations exist."""
        response = self.client.get("/dashboard/")
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "dashboard/dashboard.html")
        self.assertContains(response, "No investigations found")
        self.assertContains(
            response,
            "These figures describe the investigations stored in this tool. "
            "They are not a measure of how common phishing is in the real world.",
        )
        self.assertNotContains(response, "<progress")

    def test_metrics_calculation_and_counts(self) -> None:
        """Assert each metric calculates exact numbers correctly from database."""
        self._create_sample_data()
        metrics = get_dashboard_metrics()

        # 1. Total analyses
        self.assertEqual(metrics["total_analyses"], 4)

        # 2. Risk distribution
        risk_map = {item["key"]: item["count"] for item in metrics["risk_distribution"]}
        self.assertEqual(risk_map["high"], 1)
        self.assertEqual(risk_map["medium"], 1)
        self.assertEqual(risk_map["low_observed"], 1)
        self.assertEqual(risk_map["inconclusive"], 1)

        # 3. PhishTank and URLhaus counted separately
        self.assertEqual(metrics["threat_intel"]["phishtank"]["count"], 1)
        self.assertEqual(metrics["threat_intel"]["urlhaus"]["count"], 1)

        # 4. Activity over time (30 entries, today and 2 days ago recorded)
        activity = metrics["activity_over_time"]
        self.assertEqual(len(activity), 30)
        today_iso = timezone.localdate().isoformat()
        two_days_ago_iso = (timezone.localdate() - timedelta(days=2)).isoformat()
        day_map = {d["date"]: d["count"] for d in activity}
        self.assertEqual(day_map.get(today_iso), 3)
        self.assertEqual(day_map.get(two_days_ago_iso), 1)

        # 5. Top domains and top TLDs
        top_domains = {d["registered_domain"]: d["count"] for d in metrics["top_domains"]}
        self.assertEqual(top_domains["portal.net"], 2)
        self.assertEqual(top_domains["hostile-bank.com"], 1)
        top_tlds = {t["suffix"]: t["count"] for t in metrics["top_tlds"]}
        self.assertEqual(top_tlds["net"], 2)
        self.assertEqual(top_tlds["com"], 1)
        self.assertEqual(top_tlds["org"], 1)

        # 6. Check availability per group
        avail = {item["group"]: item for item in metrics["check_availability"]}
        self.assertEqual(avail["lexical"]["flagged"], 1)
        self.assertEqual(avail["lexical"]["clear"], 1)
        self.assertEqual(avail["obfuscation"]["flagged"], 1)
        self.assertEqual(avail["ml"]["unavailable"], 1)
        self.assertEqual(avail["dns"]["not_run"], 1)

        # 7. ML prediction distribution
        ml_map = {m["key"]: m["count"] for m in metrics["ml_distribution"]}
        self.assertEqual(ml_map["phishing_like"], 1)
        self.assertEqual(ml_map["benign"], 1)
        self.assertEqual(ml_map["unavailable"], 2)

    def test_dashboard_view_renders_200_and_progress_bars(self) -> None:
        """Assert dashboard template renders with tables, progress bars, and labels."""
        self._create_sample_data()
        response = self.client.get("/dashboard/")
        self.assertEqual(response.status_code, 200)
        html = response.content.decode()

        self.assertIn("Investigation Dashboard", html)
        self.assertIn("Malware intelligence matches", html)
        self.assertNotIn("URLhaus phishing", html)
        self.assertIn("<progress", html)
        self.assertIn("portal[.]net", html)

    def test_no_open_check_and_defanged_domains(self) -> None:
        """Assert NEVER-OPEN rules: no href pointing to submitted data, domains defanged."""
        self._create_sample_data()
        response = self.client.get("/dashboard/")
        html = response.content.decode()

        # Word "Safe" or "Confirmed malicious" must never appear
        self.assertNotRegex(html, r"\bSafe\b")
        self.assertNotIn("Confirmed malicious", html)

        # Raw hostile domain must not appear bare, only defanged
        self.assertIn("hostile-bank[.]com", html)
        self.assertNotIn(">hostile-bank.com<", html)

        # No links, iframes, images or forms targeting submitted domain
        for tag in ("a", "iframe", "img", "form"):
            attr = "src" if tag in ("iframe", "img") else ("href" if tag == "a" else "action")
            matches = re.findall(rf'<{tag}[^>]*{attr}=["\']([^"\']+)["\']', html, re.IGNORECASE)
            for target in matches:
                self.assertNotIn("hostile-bank.com", target)
                self.assertNotIn("hxxp", target)

    def test_xss_in_domain_is_escaped(self) -> None:
        """Assert malicious script tag in registered domain is HTML-escaped."""
        inv = Investigation.objects.create(
            submitted_url="https://xss-domain.org",
            overall_level="high",
            score=90,
        )
        ParsedURLRecord.objects.create(
            investigation=inv,
            original="https://xss-domain.org",
            normalized="https://xss-domain.org",
            scheme="https",
            hostname="xss-domain.org",
            registered_domain="<script>alert('xss')</script>.com",
            suffix="com",
        )
        response = self.client.get("/dashboard/")
        self.assertEqual(response.status_code, 200)
        html = response.content.decode()

        self.assertNotIn("<script>alert('xss')</script>", html)
        self.assertIn("&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;", html)
