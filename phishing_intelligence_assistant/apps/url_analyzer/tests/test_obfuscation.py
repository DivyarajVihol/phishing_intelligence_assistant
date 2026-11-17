"""Unit tests for URL obfuscation heuristics."""
import unittest

from apps.url_analyzer.obfuscation import check_obfuscation
from apps.url_analyzer.parser import parse_url


class TestObfuscationChecks(unittest.TestCase):
    """Test suite for URL obfuscation, homograph, and deception checks."""

    def test_clean_url_produces_no_findings(self) -> None:
        """Assert a clean standard URL produces zero obfuscation findings."""
        clean_url = "https://docs.python.org/3/"
        parsed = parse_url(clean_url)
        findings = check_obfuscation(parsed)
        self.assertEqual(len(findings), 0)

    def test_known_answer_brand_in_subdomain(self) -> None:
        """Assert paypal.com.example-login.com triggers brand mismatch with high severity."""
        url = "https://paypal.com.example-login.com/verify"
        parsed = parse_url(url)
        findings = check_obfuscation(parsed)
        matching = [f for f in findings if f.check_name == "obfuscation.brand_mismatch"]
        self.assertEqual(len(matching), 1)
        self.assertEqual(matching[0].severity, "high")
        self.assertIn("warning, not proof", matching[0].explanation)

    def test_known_answer_userinfo_deception(self) -> None:
        """Assert trusted-site.com@fake-login.net triggers userinfo deception with high severity."""
        url = "https://trusted-site.com@fake-login.net/"
        parsed = parse_url(url)
        findings = check_obfuscation(parsed)
        matching = [f for f in findings if f.check_name == "obfuscation.userinfo_deception"]
        self.assertEqual(len(matching), 1)
        self.assertEqual(matching[0].severity, "high")
        self.assertIn("warning, not proof", matching[0].explanation)

    def test_percent_encoding_in_path(self) -> None:
        """Assert percent-encoding in path triggers finding with low severity."""
        url = "https://example.com/login%20page"
        parsed = parse_url(url)
        findings = check_obfuscation(parsed)
        matching = [f for f in findings if f.check_name == "obfuscation.percent_encoding"]
        self.assertEqual(len(matching), 1)
        self.assertEqual(matching[0].severity, "low")
        self.assertIn("warning, not proof", matching[0].explanation)

    def test_percent_encoding_in_host(self) -> None:
        """Assert percent-encoding in host triggers finding with medium severity."""
        url = "http://example%2ecom/login"
        parsed = parse_url(url)
        findings = check_obfuscation(parsed)
        matching = [f for f in findings if f.check_name == "obfuscation.percent_encoding"]
        self.assertEqual(len(matching), 1)
        self.assertEqual(matching[0].severity, "medium")
        self.assertIn("warning, not proof", matching[0].explanation)

    def test_repeated_separators(self) -> None:
        """Assert '//' in path or '--' in host triggers repeated separators with low severity."""
        path_url = "https://example.com//admin//settings"
        parsed_path = parse_url(path_url)
        findings_path = check_obfuscation(parsed_path)
        matching_path = [f for f in findings_path if f.check_name == "obfuscation.repeated_separators"]
        self.assertEqual(len(matching_path), 1)
        self.assertEqual(matching_path[0].severity, "low")
        self.assertIn("warning, not proof", matching_path[0].explanation)

        host_url = "https://secure--login.example.com/"
        parsed_host = parse_url(host_url)
        findings_host = check_obfuscation(parsed_host)
        matching_host = [f for f in findings_host if f.check_name == "obfuscation.repeated_separators"]
        self.assertEqual(len(matching_host), 1)
        self.assertEqual(matching_host[0].severity, "low")

    def test_non_ascii_and_punycode_host(self) -> None:
        """Assert unicode and punycode hostnames trigger non-ascii check with medium severity."""
        unicode_url = "http://радио.рф/stream"
        parsed_u = parse_url(unicode_url)
        findings_u = check_obfuscation(parsed_u)
        matching_u = [f for f in findings_u if f.check_name == "obfuscation.non_ascii_punycode"]
        self.assertEqual(len(matching_u), 1)
        self.assertEqual(matching_u[0].severity, "medium")
        self.assertIn("warning, not proof", matching_u[0].explanation)

        puny_url = "http://xn--80aimyg.xn--p1ai/stream"
        parsed_p = parse_url(puny_url)
        findings_p = check_obfuscation(parsed_p)
        matching_p = [f for f in findings_p if f.check_name == "obfuscation.non_ascii_punycode"]
        self.assertEqual(len(matching_p), 1)
        self.assertEqual(matching_p[0].severity, "medium")

    def test_excessive_subdomains(self) -> None:
        """Assert excessive subdomain depth triggers finding with low severity."""
        deep_url = "https://a.b.c.d.example.com/portal"
        parsed = parse_url(deep_url)
        findings = check_obfuscation(parsed)
        matching = [f for f in findings if f.check_name == "obfuscation.excessive_subdomains"]
        self.assertEqual(len(matching), 1)
        self.assertEqual(matching[0].severity, "low")
        self.assertIn("warning, not proof", matching[0].explanation)

    def test_brand_in_path_mismatch(self) -> None:
        """Assert brand token in path with unrelated registered domain triggers high severity."""
        url = "https://phish-site.net/apple/id/signin"
        parsed = parse_url(url)
        findings = check_obfuscation(parsed)
        matching = [f for f in findings if f.check_name == "obfuscation.brand_mismatch"]
        self.assertEqual(len(matching), 1)
        self.assertEqual(matching[0].severity, "high")
        self.assertIn("warning, not proof", matching[0].explanation)
