"""Unit tests for DNS and RDAP domain enrichment checks (all network mocked)."""
import json
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import dns.exception
import dns.resolver

from apps.core.types import ParsedURL
from apps.url_analyzer.domain_checks import check_dns, check_rdap
from apps.url_analyzer.parser import parse_url


def _make_rdap_response(status_code: int = 200, payload: dict | None = None, location: str = "") -> MagicMock:
    """Create a mocked requests.Response for RDAP tests."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.headers = {"location": location} if location else {}
    raw = json.dumps(payload or {}).encode("utf-8")
    resp.iter_content.return_value = [raw]
    resp.raise_for_status.return_value = None
    return resp


class TestDomainChecks(unittest.TestCase):
    """Test suite for check_dns and check_rdap with mocked network."""

    @patch("apps.url_analyzer.domain_checks.dns.resolver.Resolver")
    def test_dns_no_records_is_low(self, mock_resolver_cls: MagicMock) -> None:
        """Assert missing A and AAAA records return low-severity flagged finding."""
        inst = mock_resolver_cls.return_value
        inst.resolve.side_effect = dns.resolver.NoAnswer()
        findings = check_dns(parse_url("https://example.com"))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].check_name, "dns.records")
        self.assertEqual(findings[0].status, "flagged")
        self.assertEqual(findings[0].severity, "low")

    @patch("apps.url_analyzer.domain_checks.dns.resolver.Resolver")
    def test_dns_missing_mx_alone_is_info_clear(self, mock_resolver_cls: MagicMock) -> None:
        """Assert missing MX alone with valid A record returns clear info finding."""
        inst = mock_resolver_cls.return_value

        def _resolve(domain: str, rtype: str) -> list:
            if rtype in ("A", "NS"):
                return [MagicMock()]
            raise dns.resolver.NoAnswer()

        inst.resolve.side_effect = _resolve
        findings = check_dns(parse_url("https://example.com"))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, "clear")
        self.assertEqual(findings[0].severity, "info")

    @patch("apps.url_analyzer.domain_checks.dns.resolver.Resolver")
    def test_dns_timeout_is_unavailable(self, mock_resolver_cls: MagicMock) -> None:
        """Assert DNS timeout returns unavailable finding."""
        mock_resolver_cls.return_value.resolve.side_effect = dns.exception.Timeout()
        findings = check_dns(parse_url("https://example.com"))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, "unavailable")

    @patch("apps.url_analyzer.domain_checks.requests.get")
    def test_rdap_young_domain_is_high(self, mock_get: MagicMock) -> None:
        """Assert domain registered < 7 days ago returns high-severity finding."""
        created = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
        mock_get.return_value = _make_rdap_response(payload={"events": [{"eventAction": "registration", "eventDate": created}]})
        findings = check_rdap(parse_url("https://new-phish.com"))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].check_name, "rdap.domain_age")
        self.assertEqual(findings[0].status, "flagged")
        self.assertEqual(findings[0].severity, "high")

    @patch("apps.url_analyzer.domain_checks.requests.get")
    def test_rdap_old_domain_is_clear(self, mock_get: MagicMock) -> None:
        """Assert domain registered >= 90 days ago returns clear finding."""
        created = (datetime.now(timezone.utc) - timedelta(days=365)).isoformat()
        mock_get.return_value = _make_rdap_response(payload={"events": [{"eventAction": "registration", "eventDate": created}]})
        findings = check_rdap(parse_url("https://old-site.com"))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, "clear")

    @patch("apps.url_analyzer.domain_checks.requests.get")
    def test_rdap_hidden_date_is_unavailable(self, mock_get: MagicMock) -> None:
        """Assert missing RDAP registration date returns unavailable finding."""
        mock_get.return_value = _make_rdap_response(payload={"events": []})
        findings = check_rdap(parse_url("https://hidden-date.com"))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, "unavailable")

    @patch("apps.url_analyzer.domain_checks.requests.get")
    @patch("apps.url_analyzer.domain_checks.dns.resolver.Resolver")
    def test_invalid_domain_rejected_before_any_request(self, mock_resolver: MagicMock, mock_get: MagicMock) -> None:
        """Assert invalid domain string is rejected before making DNS or RDAP calls."""
        bad = ParsedURL(
            original="http://bad_domain!com", normalized="http://bad_domain!com/", scheme="http",
            scheme_assumed=False, hostname="bad_domain!com", subdomain="", registered_domain="bad_domain!com",
            suffix="", port=None, userinfo="", path="/", query="", fragment="", is_ip_host=False,
        )
        self.assertEqual(check_dns(bad)[0].status, "unavailable")
        self.assertEqual(check_rdap(bad)[0].status, "unavailable")
        mock_resolver.assert_not_called()
        mock_get.assert_not_called()

    @patch("apps.url_analyzer.domain_checks.requests.get")
    def test_rdap_non_https_redirect_refused(self, mock_get: MagicMock) -> None:
        """Assert RDAP redirect to non-HTTPS URL is refused and returns unavailable."""
        mock_get.return_value = _make_rdap_response(status_code=302, location="http://insecure.rdap.example/domain/a.com")
        findings = check_rdap(parse_url("https://example.com"))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, "unavailable")
        self.assertEqual(mock_get.call_count, 1)
