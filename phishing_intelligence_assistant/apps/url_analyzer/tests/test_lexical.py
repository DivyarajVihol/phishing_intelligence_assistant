"""Unit tests for lexical heuristic checks."""
import unittest

from apps.url_analyzer.lexical import check_lexical
from apps.url_analyzer.parser import parse_url


class TestLexicalChecks(unittest.TestCase):
    """Test suite for lexical heuristics."""

    def test_clean_url_produces_no_warnings(self) -> None:
        """Assert a standard clean HTTPS URL produces zero flagged findings."""
        clean_url = "https://example.com/about"
        parsed = parse_url(clean_url)
        findings = check_lexical(parsed)
        self.assertEqual(len(findings), 0)

    def test_long_url_fires_rule(self) -> None:
        """Assert URLs exceeding max length threshold trigger lexical.url_length."""
        long_url = "https://example.com/" + ("path/" * 25)
        parsed = parse_url(long_url)
        findings = check_lexical(parsed)
        matching = [f for f in findings if f.check_name == "lexical.url_length"]
        self.assertEqual(len(matching), 1)
        finding = matching[0]
        self.assertEqual(finding.severity, "low")
        self.assertIn("warning, not proof", finding.explanation)

    def test_many_subdomains_fires_rule(self) -> None:
        """Assert excessive subdomain depth triggers lexical.subdomain_count."""
        deep_sub_url = "https://a.b.c.d.example.com/portal"
        parsed = parse_url(deep_sub_url)
        findings = check_lexical(parsed)
        matching = [f for f in findings if f.check_name == "lexical.subdomain_count"]
        self.assertEqual(len(matching), 1)
        finding = matching[0]
        self.assertEqual(finding.severity, "medium")
        self.assertIn("warning, not proof", finding.explanation)

    def test_ip_host_fires_rule(self) -> None:
        """Assert IP address hostnames trigger lexical.ip_host."""
        ip_url = "https://192.168.1.1/admin"
        parsed = parse_url(ip_url)
        findings = check_lexical(parsed)
        matching = [f for f in findings if f.check_name == "lexical.ip_host"]
        self.assertEqual(len(matching), 1)
        finding = matching[0]
        self.assertEqual(finding.severity, "medium")
        self.assertIn("warning, not proof", finding.explanation)

    def test_suspicious_keywords_fire_rule(self) -> None:
        """Assert presence of sensitive keywords triggers lexical.suspicious_keywords."""
        keyword_url = "https://example.com/banking/login/verify"
        parsed = parse_url(keyword_url)
        findings = check_lexical(parsed)
        matching = [f for f in findings if f.check_name == "lexical.suspicious_keywords"]
        self.assertEqual(len(matching), 1)
        finding = matching[0]
        self.assertEqual(finding.severity, "medium")
        self.assertIn("warning, not proof", finding.explanation)

    def test_at_symbol_fires_rule(self) -> None:
        """Assert '@' userinfo separator triggers lexical.at_symbol."""
        at_url = "https://trusted-site.com@fake-login.net/"
        parsed = parse_url(at_url)
        findings = check_lexical(parsed)
        matching = [f for f in findings if f.check_name == "lexical.at_symbol"]
        self.assertEqual(len(matching), 1)
        finding = matching[0]
        self.assertEqual(finding.severity, "medium")
        self.assertIn("warning, not proof", finding.explanation)

    def test_http_scheme_fires_info_severity_only(self) -> None:
        """Assert non-HTTPS scheme triggers lexical.https_scheme with info severity."""
        http_url = "http://example.com/about"
        parsed = parse_url(http_url)
        findings = check_lexical(parsed)
        matching = [f for f in findings if f.check_name == "lexical.https_scheme"]
        self.assertEqual(len(matching), 1)
        finding = matching[0]
        self.assertEqual(finding.severity, "info")
        self.assertIn("warning, not proof", finding.explanation)
