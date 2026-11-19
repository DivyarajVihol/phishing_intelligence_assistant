"""Unit and integration tests for analysis orchestrator service."""
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
from apps.ml_engine.predict import ModelUnavailable
from apps.url_analyzer.parser import InvalidURLError


class SmokeTest(TestCase):
    """Smoke test ensuring base routing and template rendering work."""

    def test_root_url_returns_200(self) -> None:
        """Assert placeholder root URL returns HTTP 200."""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)


class TestAnalysisService(TestCase):
    """Test suite for URL analysis orchestrator and database persistence."""

    def _mock_no_match_lookups(self, parsed: object, settings: object) -> list[ThreatLookup]:
        return [
            ThreatLookup(source="phishtank", status="no_match"),
            ThreatLookup(source="urlhaus", status="no_match"),
        ]

    @patch("apps.threat_intel.service.query_sources")
    def test_full_success_saves_everything(self, mock_query: MagicMock) -> None:
        """Assert full analysis pipeline successfully saves all related database records."""
        mock_query.side_effect = self._mock_no_match_lookups
        raw_url = "https://example.com/test-path?param=1"

        investigation = analyse_url(raw_url)

        self.assertEqual(Investigation.objects.count(), 1)
        self.assertEqual(investigation.submitted_url, raw_url)
        self.assertIn(investigation.overall_level, ("high", "medium", "low_observed", "inconclusive"))

        # Check ParsedURLRecord
        self.assertEqual(ParsedURLRecord.objects.count(), 1)
        parsed_record = ParsedURLRecord.objects.first()
        self.assertIsNotNone(parsed_record)
        self.assertEqual(parsed_record.hostname, "example.com")
        self.assertEqual(parsed_record.registered_domain, "example.com")
        self.assertEqual(parsed_record.path, "/test-path")

        # Check FindingRecords
        self.assertGreater(FindingRecord.objects.filter(investigation=investigation).count(), 0)

        # Check ThreatIntelLookupRecords
        self.assertEqual(ThreatIntelLookupRecord.objects.filter(investigation=investigation).count(), 2)

        # Check MLPredictionRecord
        self.assertEqual(MLPredictionRecord.objects.filter(investigation=investigation).count(), 1)
        ml_rec = MLPredictionRecord.objects.first()
        self.assertIsNotNone(ml_rec)
        self.assertIn(ml_rec.predicted_class, ("phishing_like", "benign"))

    @patch("apps.threat_intel.service.query_sources")
    def test_intel_unavailable_gives_inconclusive(self, mock_query: MagicMock) -> None:
        """Assert unavailable intelligence lookups downgrade benign URL to Inconclusive."""
        mock_query.return_value = [
            ThreatLookup(source="phishtank", status="unavailable", error="Request timed out"),
            ThreatLookup(source="urlhaus", status="unavailable", error="Connection failed"),
        ]
        investigation = analyse_url("https://example.com")

        self.assertEqual(investigation.overall_level, "inconclusive")
        self.assertEqual(
            ThreatIntelLookupRecord.objects.filter(investigation=investigation, query_status="unavailable").count(),
            2,
        )

    @patch("apps.analysis.services.predict")
    @patch("apps.threat_intel.service.query_sources")
    def test_model_missing_still_saves_with_unavailable_finding(
        self, mock_query: MagicMock, mock_predict: MagicMock
    ) -> None:
        """Assert model failure records unavailable finding and completes investigation."""
        mock_query.side_effect = self._mock_no_match_lookups
        mock_predict.side_effect = ModelUnavailable("Model artifact not found")

        investigation = analyse_url("https://example.com")

        self.assertEqual(Investigation.objects.count(), 1)
        self.assertEqual(MLPredictionRecord.objects.filter(investigation=investigation).count(), 0)
        self.assertTrue(
            FindingRecord.objects.filter(
                investigation=investigation, check_name="ml.prediction", status="unavailable"
            ).exists()
        )

    def test_invalid_url_raises_and_saves_nothing(self) -> None:
        """Assert invalid URL raises InvalidURLError and persists no records."""
        with self.assertRaises(InvalidURLError):
            analyse_url("ftp://unsupported-scheme.com")

        self.assertEqual(Investigation.objects.count(), 0)
        self.assertEqual(FindingRecord.objects.count(), 0)
        self.assertEqual(ParsedURLRecord.objects.count(), 0)

    @patch("apps.analysis.services.check_lexical")
    @patch("apps.threat_intel.service.query_sources")
    def test_lexical_failure_becomes_unavailable_finding(
        self, mock_query: MagicMock, mock_lexical: MagicMock
    ) -> None:
        """Assert failure in lexical module becomes unavailable finding without stopping analysis."""
        mock_query.side_effect = self._mock_no_match_lookups
        mock_lexical.side_effect = RuntimeError("Lexical check crashed")

        investigation = analyse_url("https://example.com")

        self.assertEqual(Investigation.objects.count(), 1)
        self.assertTrue(
            FindingRecord.objects.filter(
                investigation=investigation, check_name="lexical.error", status="unavailable"
            ).exists()
        )
        # Ensure other checks still executed
        self.assertTrue(
            FindingRecord.objects.filter(
                investigation=investigation, check_name="ml.prediction"
            ).exists()
        )
        self.assertEqual(ThreatIntelLookupRecord.objects.filter(investigation=investigation).count(), 2)
