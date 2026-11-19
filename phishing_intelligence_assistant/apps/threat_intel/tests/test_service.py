"""Unit tests for threat intelligence service and findings conversion."""
from datetime import datetime, timezone
import unittest
from unittest.mock import MagicMock, patch

from apps.core.types import ThreatLookup
from apps.threat_intel import service
from apps.url_analyzer.parser import parse_url


class TestThreatIntelService(unittest.TestCase):
    """Test suite for threat intelligence orchestration and caching."""

    def setUp(self) -> None:
        service.clear_cache()
        self.parsed = parse_url("https://suspicious-test.xyz/path")
        self.secret_key = "TOP_SECRET_AUTH_KEY_123"
        self.settings = {
            "ENABLE_PHISHTANK": True,
            "PHISHTANK_APP_KEY": self.secret_key,
            "PHISHTANK_USER_AGENT": "test-agent",
            "ENABLE_URLHAUS": True,
            "URLHAUS_AUTH_KEY": self.secret_key,
            "EXTERNAL_TIMEOUT_SECONDS": 5,
            "LOOKUP_CACHE_TTL_SECONDS": 3600,
        }

    @patch("requests.post")
    def test_query_sources_cache_hit(self, mock_post: MagicMock) -> None:
        """Assert cached lookups do not trigger repeated network requests."""
        resp = MagicMock()
        resp.status_code = 200
        resp.json.side_effect = [
            {"results": {"in_database": False, "verified": False}},  # PhishTank
            {"query_status": "no_results"},  # URLhaus
        ]
        mock_post.return_value = resp

        # First query triggers 2 requests (PhishTank and URLhaus)
        first_lookups = service.query_sources(self.parsed, self.settings)
        self.assertEqual(len(first_lookups), 2)
        self.assertEqual(mock_post.call_count, 2)

        # Second query should hit cache and make 0 additional requests
        second_lookups = service.query_sources(self.parsed, self.settings)
        self.assertEqual(len(second_lookups), 2)
        self.assertEqual(mock_post.call_count, 2)
        self.assertEqual(first_lookups[0].status, second_lookups[0].status)
        self.assertEqual(first_lookups[1].status, second_lookups[1].status)

    @patch("requests.post")
    def test_unavailable_results_are_never_cached(self, mock_post: MagicMock) -> None:
        """Assert unavailable lookup results are never stored in cache."""
        resp = MagicMock()
        resp.status_code = 500  # Will cause unavailable status
        mock_post.return_value = resp

        first_lookups = service.query_sources(self.parsed, self.settings)
        self.assertEqual(len(first_lookups), 2)
        self.assertTrue(all(l.status == "unavailable" for l in first_lookups))
        self.assertEqual(mock_post.call_count, 2)

        # Second query must not hit cache and call post again
        second_lookups = service.query_sources(self.parsed, self.settings)
        self.assertEqual(len(second_lookups), 2)
        self.assertEqual(mock_post.call_count, 4)

    def test_to_findings_mappings(self) -> None:
        """Assert to_findings maps statuses and severities correctly."""
        now = datetime.now(timezone.utc)
        lookups = [
            ThreatLookup(source="phishtank", status="match", record_id="111", detail={"id": 111}, queried_at=now),
            ThreatLookup(source="urlhaus", status="no_match", record_id=None, detail={}, queried_at=now),
            ThreatLookup(source="phishtank", status="unavailable", error="Request timed out", queried_at=now),
            ThreatLookup(source="urlhaus", status="not_configured", queried_at=now),
        ]
        findings = service.to_findings(lookups)
        self.assertEqual(len(findings), 4)

        # Match -> flagged / high
        self.assertEqual(findings[0].check_name, "intel.phishtank")
        self.assertEqual(findings[0].category, "intel")
        self.assertEqual(findings[0].status, "flagged")
        self.assertEqual(findings[0].severity, "high")
        self.assertEqual(findings[0].evidence["record_id"], "111")
        self.assertEqual(
            findings[0].explanation,
            "URL matched entry in phishtank threat intelligence lookup.",
        )

        # No match -> clear / info with exact required text
        self.assertEqual(findings[1].check_name, "intel.urlhaus")
        self.assertEqual(findings[1].category, "intel")
        self.assertEqual(findings[1].status, "clear")
        self.assertEqual(findings[1].severity, "info")
        self.assertEqual(
            findings[1].explanation,
            "No match found in this source at the time of lookup.",
        )

        # Unavailable -> unavailable
        self.assertEqual(findings[2].check_name, "intel.phishtank")
        self.assertEqual(findings[2].status, "unavailable")
        self.assertEqual(findings[2].severity, "info")

        # Not configured -> not_run
        self.assertEqual(findings[3].check_name, "intel.urlhaus")
        self.assertEqual(findings[3].status, "not_run")
        self.assertEqual(findings[3].severity, "info")

    def test_banned_words_and_key_leakage_in_findings(self) -> None:
        """Assert findings never contain words 'safe' or 'clean' and never leak secrets."""
        now = datetime.now(timezone.utc)
        lookups = [
            ThreatLookup(source="phishtank", status="match", record_id="999", detail={"k": "v"}, queried_at=now),
            ThreatLookup(source="urlhaus", status="no_match", detail={}, queried_at=now),
            ThreatLookup(source="phishtank", status="unavailable", error="Timeout", queried_at=now),
            ThreatLookup(source="urlhaus", status="not_configured", queried_at=now),
        ]
        findings = service.to_findings(lookups)
        for f in findings:
            representation = f"{f.check_name} {f.explanation} {f.evidence} {f.status} {f.severity}".lower()
            self.assertNotIn("safe", representation)
            self.assertNotIn("clean", representation)
            self.assertNotIn("confirmed malicious", representation)
            self.assertNotIn(self.secret_key.lower(), representation)
