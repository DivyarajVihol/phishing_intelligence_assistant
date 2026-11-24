"""Unit and security tests for investigation history, search, and filters (Phase 11)."""
from datetime import timedelta
import re

from django.test import TestCase
from django.utils import timezone

from apps.analysis.models import (
    Investigation,
    MLPredictionRecord,
    ParsedURLRecord,
    ThreatIntelLookupRecord,
)
from apps.url_analyzer.defang import defang_url


class TestHistoryViewAndFilters(TestCase):
    """Test suite for history list view, filters, search, pagination, and NEVER-OPEN security."""

    def _create_investigation(
        self,
        url: str = "https://example.com/login",
        level: str = "high",
        score: int | None = 85,
        status: str = "completed",
        domain: str = "example.com",
        hostname: str = "example.com",
        phishtank_match: bool = False,
        urlhaus_match: bool = False,
        ml_class: str | None = None,
        days_ago: int = 0,
    ) -> Investigation:
        """Helper to create complete investigation with relations for testing."""
        inv = Investigation.objects.create(
            submitted_url=url,
            status=status,
            overall_level=level,
            score=score,
            summary=f"Summary for {level}",
        )
        if days_ago > 0:
            target_time = timezone.now() - timedelta(days=days_ago)
            Investigation.objects.filter(id=inv.id).update(submitted_at=target_time)
            inv.refresh_from_db()

        ParsedURLRecord.objects.create(
            investigation=inv,
            original=url,
            normalized=url,
            scheme="https",
            hostname=hostname,
            registered_domain=domain,
        )
        ThreatIntelLookupRecord.objects.create(
            investigation=inv,
            source="phishtank",
            matched=phishtank_match,
            query_status="match" if phishtank_match else "no_match",
        )
        ThreatIntelLookupRecord.objects.create(
            investigation=inv,
            source="urlhaus",
            matched=urlhaus_match,
            query_status="match" if urlhaus_match else "no_match",
        )
        if ml_class:
            MLPredictionRecord.objects.create(
                investigation=inv,
                model_name="test_model",
                model_version="v1",
                predicted_class=ml_class,
                score=0.9 if ml_class == "phishing_like" else 0.1,
                threshold=0.62,
            )
        return inv

    def test_history_empty_state(self) -> None:
        """Assert empty state message appears when no investigations match."""
        response = self.client.get("/history/")
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "analysis/history.html")
        self.assertContains(response, "No investigations match the selected filters.")
        self.assertNotContains(response, "<table")

    def test_list_shows_saved_analyses_newest_first(self) -> None:
        """Assert investigations are displayed in newest-first order."""
        inv_old = self._create_investigation(
            url="https://older-site.org/index", days_ago=2
        )
        inv_new = self._create_investigation(
            url="https://newer-site.org/index", days_ago=0
        )

        response = self.client.get("/history/")
        self.assertEqual(response.status_code, 200)
        items = list(response.context["items"])
        self.assertEqual(len(items), 2)
        self.assertEqual(items[0]["id"], inv_new.id)
        self.assertEqual(items[1]["id"], inv_old.id)

    def test_search_by_url_and_domain(self) -> None:
        """Assert search query narrows results by submitted URL or registered domain."""
        self._create_investigation(url="https://target-portal.com/login", domain="target-portal.com")
        self._create_investigation(url="https://random-service.net/user", domain="random-service.net")

        # Search by URL substring
        resp_url = self.client.get("/history/", {"q": "target-portal"})
        self.assertEqual(len(resp_url.context["items"]), 1)
        self.assertEqual(resp_url.context["items"][0]["submitted_url"], "https://target-portal.com/login")

        # Search by domain
        resp_domain = self.client.get("/history/", {"q": "random-service.net"})
        self.assertEqual(len(resp_domain.context["items"]), 1)
        self.assertEqual(resp_domain.context["items"][0]["submitted_url"], "https://random-service.net/user")

        # Search with no match
        resp_nomatch = self.client.get("/history/", {"q": "nonexistent"})
        self.assertEqual(len(resp_nomatch.context["items"]), 0)
        self.assertContains(resp_nomatch, "No investigations match the selected filters.")

    def test_filter_by_date_range(self) -> None:
        """Assert date range filters correctly by date_from and date_to."""
        today = timezone.localdate()
        inv_today = self._create_investigation(url="https://today.org", days_ago=0)
        self._create_investigation(url="https://old.org", days_ago=5)

        # Filter today only
        response = self.client.get("/history/", {"date_from": today.isoformat(), "date_to": today.isoformat()})
        self.assertEqual(len(response.context["items"]), 1)
        self.assertEqual(response.context["items"][0]["id"], inv_today.id)

    def test_filter_by_risk_level(self) -> None:
        """Assert risk level filter restricts records to the selected level."""
        inv_high = self._create_investigation(url="https://high.com", level="high", score=90)
        self._create_investigation(url="https://med.com", level="medium", score=40)
        self._create_investigation(url="https://low.com", level="low_observed", score=10)
        self._create_investigation(url="https://inconc.com", level="inconclusive", score=None)

        resp = self.client.get("/history/", {"risk_level": "high"})
        self.assertEqual(len(resp.context["items"]), 1)
        self.assertEqual(resp.context["items"][0]["id"], inv_high.id)

        resp_inconc = self.client.get("/history/", {"risk_level": "inconclusive"})
        self.assertEqual(len(resp_inconc.context["items"]), 1)
        self.assertEqual(resp_inconc.context["items"][0]["level_label"], "Inconclusive")

    def test_filter_by_phishtank_match(self) -> None:
        """Assert phishtank filter isolates records with PhishTank match."""
        inv_match = self._create_investigation(url="https://phish1.com", phishtank_match=True)
        inv_nomatch = self._create_investigation(url="https://clean1.com", phishtank_match=False)

        resp_match = self.client.get("/history/", {"phishtank": "match"})
        self.assertEqual(len(resp_match.context["items"]), 1)
        self.assertEqual(resp_match.context["items"][0]["id"], inv_match.id)

        resp_nomatch = self.client.get("/history/", {"phishtank": "no_match"})
        self.assertEqual(len(resp_nomatch.context["items"]), 1)
        self.assertEqual(resp_nomatch.context["items"][0]["id"], inv_nomatch.id)

    def test_filter_by_urlhaus_match(self) -> None:
        """Assert urlhaus filter isolates records with URLhaus match."""
        inv_match = self._create_investigation(url="https://malware1.com", urlhaus_match=True)
        inv_nomatch = self._create_investigation(url="https://clean2.com", urlhaus_match=False)

        resp_match = self.client.get("/history/", {"urlhaus": "match"})
        self.assertEqual(len(resp_match.context["items"]), 1)
        self.assertEqual(resp_match.context["items"][0]["id"], inv_match.id)

        resp_nomatch = self.client.get("/history/", {"urlhaus": "no_match"})
        self.assertEqual(len(resp_nomatch.context["items"]), 1)
        self.assertEqual(resp_nomatch.context["items"][0]["id"], inv_nomatch.id)

    def test_filter_by_status(self) -> None:
        """Assert status filter isolates completed or failed investigations."""
        inv_completed = self._create_investigation(url="https://comp.org", status="completed")
        inv_failed = self._create_investigation(url="https://fail.org", status="failed")

        resp = self.client.get("/history/", {"status": "failed"})
        self.assertEqual(len(resp.context["items"]), 1)
        self.assertEqual(resp.context["items"][0]["id"], inv_failed.id)

        resp_comp = self.client.get("/history/", {"status": "completed"})
        self.assertEqual(len(resp_comp.context["items"]), 1)
        self.assertEqual(resp_comp.context["items"][0]["id"], inv_completed.id)

    def test_filter_by_ml_result(self) -> None:
        """Assert ml_result filter isolates phishing-like vs not phishing-like."""
        inv_phish = self._create_investigation(url="https://phish-ml.org", ml_class="phishing_like")
        inv_benign = self._create_investigation(url="https://benign-ml.org", ml_class="benign")

        resp_phish = self.client.get("/history/", {"ml_result": "phishing_like"})
        self.assertEqual(len(resp_phish.context["items"]), 1)
        self.assertEqual(resp_phish.context["items"][0]["id"], inv_phish.id)

        resp_benign = self.client.get("/history/", {"ml_result": "benign"})
        self.assertEqual(len(resp_benign.context["items"]), 1)
        self.assertEqual(resp_benign.context["items"][0]["id"], inv_benign.id)

    def test_pagination_gives_25_per_page_and_keeps_filters(self) -> None:
        """Assert pagination yields 25 items per page and page links preserve filter params."""
        for i in range(30):
            self._create_investigation(url=f"https://example{i}.org", level="high", score=80)

        # Page 1
        resp_p1 = self.client.get("/history/", {"risk_level": "high"})
        self.assertEqual(resp_p1.status_code, 200)
        self.assertEqual(len(resp_p1.context["items"]), 25)
        self.assertEqual(resp_p1.context["page_obj"].paginator.count, 30)
        self.assertEqual(resp_p1.context["page_obj"].paginator.num_pages, 2)

        # Check next page link in HTML retains risk_level=high
        html_p1 = resp_p1.content.decode()
        self.assertIn("page=2", html_p1)
        self.assertIn("risk_level=high", html_p1)

        # Page 2
        resp_p2 = self.client.get("/history/", {"risk_level": "high", "page": "2"})
        self.assertEqual(resp_p2.status_code, 200)
        self.assertEqual(len(resp_p2.context["items"]), 5)
        html_p2 = resp_p2.content.decode()
        self.assertIn("page=1", html_p2)
        self.assertIn("risk_level=high", html_p2)

    def test_table_columns_and_inconclusive_score_blank(self) -> None:
        """Assert table renders all columns, Inconclusive score is blank, and View details uses reverse."""
        inv = self._create_investigation(
            url="https://inconc-test.com",
            level="inconclusive",
            score=45,
            phishtank_match=True,
            ml_class="phishing_like",
        )
        response = self.client.get("/history/")
        self.assertEqual(response.status_code, 200)
        html = response.content.decode()

        self.assertIn("Inconclusive", html)
        self.assertIn("PhishTank", html)
        self.assertIn("Phishing-like", html)
        self.assertIn(f"/result/{inv.id}/", html)
        self.assertIn("View details", html)

        # Inconclusive score must be blank (not displaying 45)
        item = response.context["items"][0]
        self.assertFalse(item["show_score"])
        self.assertIsNone(item["score"])

    def test_no_open_check_at_every_risk_level(self) -> None:
        """Assert NEVER-OPEN rule: raw URL never appears, no href points to submitted URL, defanged in <code>."""
        levels = [("high", 90), ("medium", 50), ("low_observed", 15), ("inconclusive", None)]
        raw_urls = [
            "https://hostile-bank-login1.xyz/auth?user=victim1",
            "https://hostile-bank-login2.xyz/auth?user=victim2",
            "https://hostile-bank-login3.xyz/auth?user=victim3",
            "https://hostile-bank-login4.xyz/auth?user=victim4",
        ]

        for (lvl, sc), raw in zip(levels, raw_urls):
            self._create_investigation(url=raw, level=lvl, score=sc)

        response = self.client.get("/history/")
        self.assertEqual(response.status_code, 200)
        html = response.content.decode()

        # Word "Safe" must never appear
        self.assertNotRegex(html, r"\bSafe\b")

        for raw in raw_urls:
            defanged = defang_url(raw)
            # Defanged URL must appear
            self.assertIn(defanged, html)
            # Raw submitted URL string must NOT appear
            self.assertNotIn(raw, html)

        # Assert no clickable links, iframe, img, or action target pointing to submitted host
        for tag in ("a", "iframe", "img", "form"):
            attr = "src" if tag in ("iframe", "img") else ("href" if tag == "a" else "action")
            matches = re.findall(rf'<{tag}[^>]*{attr}=["\']([^"\']+)["\']', html, re.IGNORECASE)
            for target in matches:
                self.assertNotIn("hostile-bank-login", target)
                self.assertNotIn("hxxp", target)

    def test_xss_url_is_escaped(self) -> None:
        """Assert URL containing <script> tags is safely HTML-escaped."""
        xss_url = "https://example.com/login?q=<script>alert('xss')</script>"
        self._create_investigation(url=xss_url)

        response = self.client.get("/history/")
        self.assertEqual(response.status_code, 200)
        html = response.content.decode()

        self.assertNotIn("<script>alert('xss')</script>", html)
        self.assertIn("&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;", html)
