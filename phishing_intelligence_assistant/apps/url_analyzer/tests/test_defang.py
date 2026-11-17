"""Unit tests for URL defanging."""
import unittest

from apps.url_analyzer.defang import defang_url


class TestURLDefang(unittest.TestCase):
    """Test suite for URL defanging across schemes, components, and formats."""

    def test_https_defanging(self) -> None:
        """Assert https scheme becomes hxxps and host dots are bracketed."""
        result = defang_url("https://example.com/login")
        self.assertEqual(result, "hxxps://example[.]com/login")
        self.assertFalse(result.lower().startswith("http"))

    def test_http_defanging(self) -> None:
        """Assert http scheme becomes hxxp and host dots are bracketed."""
        result = defang_url("http://example.com")
        self.assertEqual(result, "hxxp://example[.]com")
        self.assertFalse(result.lower().startswith("http"))

    def test_ip_host_defanging(self) -> None:
        """Assert IPv4 addresses have each octet dot bracketed."""
        result = defang_url("http://192.168.1.1/admin")
        self.assertEqual(result, "hxxp://192[.]168[.]1[.]1/admin")
        self.assertFalse(result.lower().startswith("http"))

    def test_userinfo_defanging(self) -> None:
        """Assert userinfo dots remain unchanged while host dots are bracketed."""
        result = defang_url("https://trusted-site.com@fake-login.net/")
        self.assertEqual(result, "hxxps://trusted-site.com@fake-login[.]net/")
        self.assertFalse(result.lower().startswith("http"))

    def test_idn_defanging(self) -> None:
        """Assert IDN hostnames have dots bracketed properly."""
        result = defang_url("https://радио.рф/news")
        self.assertEqual(result, "hxxps://радио[.]рф/news")
        self.assertFalse(result.lower().startswith("http"))

    def test_no_scheme_defanging(self) -> None:
        """Assert URLs without scheme defang host while preserving path dots."""
        result = defang_url("example.com/foo.bar")
        self.assertEqual(result, "example[.]com/foo.bar")
        self.assertFalse(result.lower().startswith("http"))

    def test_never_starts_with_http(self) -> None:
        """Assert URLs starting with 'http' in domain or path never begin with http."""
        urls_to_test = [
            "http://example.com",
            "https://example.com",
            "http.phish.com",
            "httplogin.net/verify",
            "HTTP://EXAMPLE.ORG",
        ]
        for url in urls_to_test:
            defanged = defang_url(url)
            self.assertFalse(
                defanged.lower().startswith("http"),
                f"Defanged URL '{defanged}' must not start with 'http'",
            )
