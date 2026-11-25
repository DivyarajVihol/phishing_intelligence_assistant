"""Test isolation checks ensuring tests never make real outbound network calls."""
from unittest.mock import patch

from django.conf import settings
from django.test import TestCase

from apps.analysis.models import Investigation
from apps.analysis.services import analyse_url
from apps.core.types import ThreatLookup


class TestNetworkIsolation(TestCase):
    """Verify optional network flags are off in tests and analyse_url stays offline."""

    def test_optional_network_flags_disabled_during_tests(self) -> None:
        """Assert ENABLE_DNS_RDAP and ENABLE_REDIRECT_CHECK are forced False in test runs."""
        self.assertFalse(settings.ENABLE_DNS_RDAP)
        self.assertFalse(settings.ENABLE_REDIRECT_CHECK)

    @patch("apps.threat_intel.service.query_sources")
    @patch("requests.Session.request", side_effect=AssertionError("network used in tests"))
    @patch("socket.getaddrinfo", side_effect=AssertionError("network used in tests"))
    def test_analyse_url_makes_no_network_calls(
        self, mock_getaddrinfo, mock_request, mock_query_sources
    ) -> None:
        """Assert analyse_url completes without touching socket or HTTP when intel is mocked."""
        mock_query_sources.return_value = [
            ThreatLookup(source="phishtank", status="no_match"),
            ThreatLookup(source="urlhaus", status="no_match"),
        ]
        inv = analyse_url("https://example.com/check")
        self.assertEqual(Investigation.objects.count(), 1)
        self.assertIsNotNone(inv.id)
        mock_getaddrinfo.assert_not_called()
        mock_request.assert_not_called()
