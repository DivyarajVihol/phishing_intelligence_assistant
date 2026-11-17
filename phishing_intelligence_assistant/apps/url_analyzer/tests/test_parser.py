"""Unit tests for URL parser and validator."""
import unittest

from apps.url_analyzer.parser import InvalidURLError, parse_url


class TestURLParser(unittest.TestCase):
    """Test suite for URL parsing, validation, and normalization."""

    def test_empty_url_raises_error(self) -> None:
        """Assert empty string raises InvalidURLError."""
        with self.assertRaises(InvalidURLError):
            parse_url("")

    def test_whitespace_raises_error(self) -> None:
        """Assert whitespace in URL raises InvalidURLError."""
        with self.assertRaises(InvalidURLError):
            parse_url("   ")
        with self.assertRaises(InvalidURLError):
            parse_url("https://example .com")
        with self.assertRaises(InvalidURLError):
            parse_url("https://example.com/path with space")
        with self.assertRaises(InvalidURLError):
            parse_url("\nhttp://example.com")

    def test_too_long_raises_error(self) -> None:
        """Assert URL exceeding max length raises InvalidURLError."""
        long_url = "https://example.com/" + ("a" * 2050)
        with self.assertRaises(InvalidURLError):
            parse_url(long_url, max_len=2048)

    def test_ftp_scheme_raises_error(self) -> None:
        """Assert ftp scheme raises InvalidURLError."""
        with self.assertRaises(InvalidURLError):
            parse_url("ftp://example.com/file.txt")

    def test_no_scheme_assumes_http(self) -> None:
        """Assert URLs without scheme assume http:// and set scheme_assumed."""
        parsed = parse_url("example.com/login")
        self.assertEqual(parsed.scheme, "http")
        self.assertTrue(parsed.scheme_assumed)
        self.assertEqual(parsed.original, "example.com/login")
        self.assertEqual(parsed.hostname, "example.com")
        self.assertEqual(parsed.registered_domain, "example.com")

    def test_port_parsing(self) -> None:
        """Assert custom and standard ports are correctly captured."""
        parsed = parse_url("http://example.com:8080/app")
        self.assertEqual(parsed.port, 8080)
        self.assertIn(":8080", parsed.normalized)

        parsed_std = parse_url("https://example.com:443/app")
        self.assertEqual(parsed_std.port, 443)
        self.assertNotIn(":443", parsed_std.normalized)

    def test_query_and_fragment_parsing(self) -> None:
        """Assert query parameters and fragments are preserved."""
        parsed = parse_url("https://example.com/search?q=phish&sort=desc#results")
        self.assertEqual(parsed.query, "q=phish&sort=desc")
        self.assertEqual(parsed.fragment, "results")
        self.assertIn("?q=phish&sort=desc", parsed.normalized)
        self.assertIn("#results", parsed.normalized)

    def test_ip_host_detection(self) -> None:
        """Assert IPv4 and IPv6 hosts are detected with is_ip_host=True."""
        parsed_v4 = parse_url("http://192.168.1.1/dashboard")
        self.assertTrue(parsed_v4.is_ip_host)
        self.assertEqual(parsed_v4.hostname, "192.168.1.1")
        self.assertEqual(parsed_v4.registered_domain, "192.168.1.1")
        self.assertEqual(parsed_v4.subdomain, "")
        self.assertEqual(parsed_v4.suffix, "")

        parsed_v6 = parse_url("http://[2001:db8::1]:8080/index")
        self.assertTrue(parsed_v6.is_ip_host)
        self.assertEqual(parsed_v6.port, 8080)

    def test_unusual_subdomains(self) -> None:
        """Assert deeply nested subdomains are correctly separated."""
        parsed = parse_url("https://a.b.c.d.e.example.com/portal")
        self.assertEqual(parsed.subdomain, "a.b.c.d.e")
        self.assertEqual(parsed.registered_domain, "example.com")
        self.assertEqual(parsed.suffix, "com")

    def test_idn_and_punycode_handling(self) -> None:
        """Assert IDN unicode and punycode representations are handled safely."""
        parsed_idn = parse_url("http://радио.рф/stream")
        self.assertEqual(parsed_idn.hostname, "радио.рф")
        self.assertIn("xn--80aimyg.xn--p1ai", parsed_idn.normalized)

        parsed_puny = parse_url("http://xn--80aimyg.xn--p1ai/stream")
        self.assertEqual(parsed_puny.hostname, "xn--80aimyg.xn--p1ai")
        self.assertIn("xn--80aimyg.xn--p1ai", parsed_puny.normalized)

    def test_known_answer_subdomain_brand_mimic(self) -> None:
        """Assert paypal.com.example-login.com registered_domain is example-login.com."""
        url = "https://paypal.com.example-login.com/verify"
        parsed = parse_url(url)
        self.assertEqual(parsed.registered_domain, "example-login.com")
        self.assertEqual(parsed.subdomain, "paypal.com")
        self.assertEqual(parsed.suffix, "com")
        self.assertEqual(parsed.path, "/verify")

    def test_known_answer_userinfo_obfuscation(self) -> None:
        """Assert trusted-site.com@fake-login.net userinfo is trusted-site.com."""
        url = "https://trusted-site.com@fake-login.net/"
        parsed = parse_url(url)
        self.assertEqual(parsed.hostname, "fake-login.net")
        self.assertEqual(parsed.userinfo, "trusted-site.com")
        self.assertEqual(parsed.registered_domain, "fake-login.net")

    def test_unlisted_suffix_fallback_to_two_labels(self) -> None:
        """Assert hostnames with unknown suffixes fall back to last two labels."""
        parsed = parse_url("http://sub.domain.corp/internal")
        self.assertEqual(parsed.suffix, "")
        self.assertEqual(parsed.registered_domain, "domain.corp")
        self.assertEqual(parsed.subdomain, "sub")
