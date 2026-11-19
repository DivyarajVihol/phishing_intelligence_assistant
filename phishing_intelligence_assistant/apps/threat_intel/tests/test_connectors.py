"""Unit tests for PhishTank and URLhaus connectors."""
import unittest
from unittest.mock import MagicMock, patch

import requests

from apps.threat_intel import phishtank, urlhaus
from apps.url_analyzer.parser import parse_url


class TestPhishTankConnector(unittest.TestCase):
    """Test suite for PhishTank lookup connector."""

    def setUp(self) -> None:
        self.parsed = parse_url("http://example.com/login")
        self.secret_key = "PHISHTANK_SECRET_KEY_9999"
        self.settings = {
            "ENABLE_PHISHTANK": True,
            "PHISHTANK_APP_KEY": self.secret_key,
            "PHISHTANK_USER_AGENT": "test-agent/1.0",
            "EXTERNAL_TIMEOUT_SECONDS": 3,
        }

    @patch("requests.post")
    def test_lookup_match_when_in_db_and_verified(self, mock_post: MagicMock) -> None:
        """Assert match when in_database and verified are both True."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "results": {"in_database": True, "verified": True, "phish_id": 12345}
        }
        mock_post.return_value = mock_resp

        result = phishtank.lookup(self.parsed, self.settings)
        self.assertEqual(result.source, "phishtank")
        self.assertEqual(result.status, "match")
        self.assertEqual(result.record_id, "12345")
        self.assertTrue(mock_post.called)
        call_kwargs = mock_post.call_args[1]
        self.assertEqual(call_kwargs["data"]["url"], self.parsed.normalized)
        self.assertEqual(call_kwargs["data"]["app_key"], self.secret_key)
        self.assertEqual(call_kwargs["headers"]["User-Agent"], "test-agent/1.0")

    @patch("requests.post")
    def test_lookup_no_match_when_not_in_db_or_unverified(self, mock_post: MagicMock) -> None:
        """Assert no_match when in_database is False or unverified."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "results": {"in_database": True, "verified": False, "phish_id": 999}
        }
        mock_post.return_value = mock_resp

        result = phishtank.lookup(self.parsed, self.settings)
        self.assertEqual(result.status, "no_match")

    @patch("requests.post")
    def test_lookup_timeout_returns_unavailable(self, mock_post: MagicMock) -> None:
        """Assert timeout results in unavailable status with short error."""
        mock_post.side_effect = requests.exceptions.Timeout("Connection timed out")

        result = phishtank.lookup(self.parsed, self.settings)
        self.assertEqual(result.status, "unavailable")
        self.assertEqual(result.error, "Request timed out")
        self.assertNotIn(self.secret_key, str(result.error))

    @patch("requests.post")
    def test_lookup_rate_limited_429_and_509(self, mock_post: MagicMock) -> None:
        """Assert HTTP 429 and 509 return unavailable rate-limited status."""
        for code in (429, 509):
            mock_resp = MagicMock()
            mock_resp.status_code = code
            mock_post.return_value = mock_resp

            result = phishtank.lookup(self.parsed, self.settings)
            self.assertEqual(result.status, "unavailable")
            self.assertIn(f"Rate limited (HTTP {code})", result.error or "")

    @patch("requests.post")
    def test_lookup_http_error_returns_unavailable(self, mock_post: MagicMock) -> None:
        """Assert non-200 HTTP response returns unavailable status."""
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_post.return_value = mock_resp

        result = phishtank.lookup(self.parsed, self.settings)
        self.assertEqual(result.status, "unavailable")
        self.assertEqual(result.error, "HTTP 500 error")

    @patch("requests.post")
    def test_lookup_malformed_json_returns_unavailable(self, mock_post: MagicMock) -> None:
        """Assert malformed JSON returns unavailable status."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.side_effect = ValueError("Invalid JSON")
        mock_post.return_value = mock_resp

        result = phishtank.lookup(self.parsed, self.settings)
        self.assertEqual(result.status, "unavailable")
        self.assertEqual(result.error, "Invalid JSON response")

    @patch("requests.post")
    def test_lookup_disabled_returns_not_configured(self, mock_post: MagicMock) -> None:
        """Assert disabled connector returns not_configured without network call."""
        disabled_settings = dict(self.settings, ENABLE_PHISHTANK=False)
        result = phishtank.lookup(self.parsed, disabled_settings)
        self.assertEqual(result.status, "not_configured")
        mock_post.assert_not_called()

    @patch("requests.post")
    def test_key_never_in_text(self, mock_post: MagicMock) -> None:
        """Assert API key never leaks in result strings or errors."""
        mock_post.side_effect = requests.exceptions.RequestException("boom")
        result = phishtank.lookup(self.parsed, self.settings)
        self.assertNotIn(self.secret_key, result.error or "")
        self.assertNotIn(self.secret_key, str(result.detail))
        self.assertNotIn(self.secret_key, str(result))


class TestURLhausConnector(unittest.TestCase):
    """Test suite for URLhaus lookup connector."""

    def setUp(self) -> None:
        self.parsed = parse_url("https://malware-drop.xyz/test")
        self.secret_key = "URLHAUS_SECRET_KEY_7777"
        self.settings = {
            "ENABLE_URLHAUS": True,
            "URLHAUS_AUTH_KEY": self.secret_key,
            "EXTERNAL_TIMEOUT_SECONDS": 4,
        }

    @patch("requests.post")
    def test_lookup_match_when_query_status_ok(self, mock_post: MagicMock) -> None:
        """Assert match when query_status is ok."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "query_status": "ok",
            "id": 8888,
            "threat": "malware_download",
        }
        mock_post.return_value = mock_resp

        result = urlhaus.lookup(self.parsed, self.settings)
        self.assertEqual(result.source, "urlhaus")
        self.assertEqual(result.status, "match")
        self.assertEqual(result.record_id, "8888")
        call_kwargs = mock_post.call_args[1]
        self.assertEqual(call_kwargs["data"]["url"], self.parsed.normalized)
        self.assertEqual(call_kwargs["headers"]["Auth-Key"], self.secret_key)

    @patch("requests.post")
    def test_lookup_no_match_when_query_status_no_results(self, mock_post: MagicMock) -> None:
        """Assert no_match when query_status is no_results."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"query_status": "no_results"}
        mock_post.return_value = mock_resp

        result = urlhaus.lookup(self.parsed, self.settings)
        self.assertEqual(result.status, "no_match")

    @patch("requests.post")
    def test_lookup_invalid_key_returns_unavailable(self, mock_post: MagicMock) -> None:
        """Assert invalid_key response returns unavailable."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"query_status": "invalid_key"}
        mock_post.return_value = mock_resp

        result = urlhaus.lookup(self.parsed, self.settings)
        self.assertEqual(result.status, "unavailable")
        self.assertEqual(result.error, "Invalid API key")

    @patch("requests.post")
    def test_lookup_timeout_returns_unavailable(self, mock_post: MagicMock) -> None:
        """Assert timeout returns unavailable."""
        mock_post.side_effect = requests.exceptions.Timeout("Timeout")
        result = urlhaus.lookup(self.parsed, self.settings)
        self.assertEqual(result.status, "unavailable")
        self.assertEqual(result.error, "Request timed out")

    @patch("requests.post")
    def test_lookup_rate_limited_and_http_errors(self, mock_post: MagicMock) -> None:
        """Assert 429 and 500 status codes return unavailable."""
        for code, expected_err in [(429, "Rate limited (HTTP 429)"), (500, "HTTP 500 error")]:
            mock_resp = MagicMock()
            mock_resp.status_code = code
            mock_post.return_value = mock_resp

            result = urlhaus.lookup(self.parsed, self.settings)
            self.assertEqual(result.status, "unavailable")
            self.assertEqual(result.error, expected_err)

    @patch("requests.post")
    def test_lookup_empty_key_returns_not_configured(self, mock_post: MagicMock) -> None:
        """Assert empty key returns not_configured without network request."""
        settings = dict(self.settings, URLHAUS_AUTH_KEY="")
        result = urlhaus.lookup(self.parsed, settings)
        self.assertEqual(result.status, "not_configured")
        mock_post.assert_not_called()

    @patch("requests.post")
    def test_lookup_disabled_returns_not_configured(self, mock_post: MagicMock) -> None:
        """Assert disabled connector returns not_configured."""
        settings = dict(self.settings, ENABLE_URLHAUS=False)
        result = urlhaus.lookup(self.parsed, settings)
        self.assertEqual(result.status, "not_configured")
        mock_post.assert_not_called()

    @patch("requests.post")
    def test_key_never_in_text(self, mock_post: MagicMock) -> None:
        """Assert URLhaus key never leaks in result strings or errors."""
        mock_post.side_effect = requests.exceptions.RequestException("network error")
        result = urlhaus.lookup(self.parsed, self.settings)
        self.assertNotIn(self.secret_key, result.error or "")
        self.assertNotIn(self.secret_key, str(result.detail))
        self.assertNotIn(self.secret_key, str(result))
