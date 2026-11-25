"""Unit tests for registered-domain brand similarity checks."""
import unittest

from apps.url_analyzer.brand import check_brand_similarity
from apps.url_analyzer.parser import parse_url


class TestBrandSimilarity(unittest.TestCase):
    """Test suite for check_brand_similarity."""

    def test_lookalike_substitutions_are_high(self) -> None:
        """Assert exact look-alike substitutions (paypa1, g00gle, micr0soft) are high severity."""
        for url in ("https://paypa1.com/login", "https://g00gle.com/", "https://micr0soft.com/"):
            findings = check_brand_similarity(parse_url(url))
            self.assertEqual(len(findings), 1, url)
            self.assertEqual(findings[0].check_name, "brand.similarity")
            self.assertEqual(findings[0].status, "flagged")
            self.assertEqual(findings[0].severity, "high", url)
            self.assertIn("warning, not proof", findings[0].explanation.lower())

    def test_exact_brand_domains_produce_no_finding(self) -> None:
        """Assert exact brand domains paypal.com and sbi.co.in produce no findings."""
        self.assertEqual(check_brand_similarity(parse_url("https://www.paypal.com/")), [])
        self.assertEqual(check_brand_similarity(parse_url("https://www.sbi.co.in/")), [])

    def test_same_label_different_suffix_is_medium(self) -> None:
        """Assert same brand label with different suffix (paypal.xyz) is medium severity."""
        findings = check_brand_similarity(parse_url("https://paypal.xyz/verify"))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "medium")

    def test_edit_distance_one_by_label_length(self) -> None:
        """Assert distance 1 is medium for >=7-char labels (microsft.com) and low for 5-6-char labels."""
        med = check_brand_similarity(parse_url("https://microsft.com/"))
        self.assertEqual(len(med), 1)
        self.assertEqual(med[0].severity, "medium")
        for url in ("https://kodak.com/", "https://apply.com/", "https://paypay.ne.jp/"):
            low = check_brand_similarity(parse_url(url))
            self.assertEqual(len(low), 1, url)
            self.assertEqual(low[0].severity, "low", url)

    def test_short_distance_two_and_unrelated_produce_no_finding(self) -> None:
        """Assert short edit-distance-2 domain (maple.com) and unrelated domain produce no findings."""
        self.assertEqual(check_brand_similarity(parse_url("https://maple.com/")), [])
        self.assertEqual(check_brand_similarity(parse_url("https://example-garden-shop.org/")), [])
