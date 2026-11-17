"""Unit tests for URL feature extraction."""
import math
import unittest

from apps.url_analyzer.features import FEATURE_NAMES, extract_features
from apps.url_analyzer.parser import parse_url


class TestFeatureExtraction(unittest.TestCase):
    """Test suite for numerical feature extraction."""

    def test_hand_checked_url_features(self) -> None:
        """Verify each feature value matches expected hand-checked values."""
        # URL: https://paypal.com.example-login.com/verify?id=123#sec
        # length: 57
        # host: paypal.com.example-login.com (len 28)
        # registered_domain: example-login.com (len 17)
        # dots: 3 (paypal.com, example-login.com)
        # dot_ratio: 3 / 57
        # hyphens: 1 (example-login)
        # hyphen_ratio: 1 / 57
        # digits: 3 (1, 2, 3)
        # digit_ratio: 3 / 57
        # subdomains: paypal.com -> 2 labels
        # is_ip_host: 0.0
        # has_https: 1.0
        # path_depth: 1 (/verify)
        # path_length: 7 (/verify)
        # query_length: 6 (id=123)
        # query_param_count: 1
        # at_count: 0.0
        # percent_count: 0.0
        # tokens: 'login', 'verify' -> 2
        # non_ascii_or_punycode: 0.0
        url = "https://paypal.com.example-login.com/verify?id=123#sec"
        parsed = parse_url(url)
        features = extract_features(parsed)

        self.assertEqual(features["url_length"], 54.0)
        self.assertEqual(features["host_length"], 28.0)
        self.assertEqual(features["registered_domain_length"], 17.0)
        self.assertEqual(features["dot_count"], 3.0)
        self.assertAlmostEqual(features["dot_ratio"], 3.0 / 54.0, places=4)
        self.assertEqual(features["hyphen_count"], 1.0)
        self.assertAlmostEqual(features["hyphen_ratio"], 1.0 / 54.0, places=4)
        self.assertEqual(features["digit_count"], 3.0)
        self.assertAlmostEqual(features["digit_ratio"], 3.0 / 54.0, places=4)
        self.assertEqual(features["subdomain_count"], 2.0)
        self.assertEqual(features["is_ip_host"], 0.0)
        self.assertEqual(features["has_https"], 1.0)
        self.assertEqual(features["path_depth"], 1.0)
        self.assertEqual(features["path_length"], 7.0)
        self.assertEqual(features["query_length"], 6.0)
        self.assertEqual(features["query_param_count"], 1.0)
        self.assertEqual(features["at_count"], 0.0)
        self.assertEqual(features["percent_count"], 0.0)
        self.assertEqual(features["suspicious_token_count"], 2.0)
        self.assertEqual(features["non_ascii_or_punycode"], 0.0)
        self.assertGreater(features["hostname_entropy"], 2.5)

    def test_feature_determinism(self) -> None:
        """Assert identical features are produced across repeated invocations."""
        parsed = parse_url("https://secure-login.bank.example.com/update")
        run1 = extract_features(parsed)
        run2 = extract_features(parsed)
        self.assertEqual(run1, run2)

    def test_no_nan_values(self) -> None:
        """Assert no features result in NaN or infinite values across edge cases."""
        urls = [
            "http://192.168.0.1",
            "https://example.com/",
            "http://a.b.c.d.e.f.example.org/path/sub/sub2?a=1&b=2&c=3",
            "https://радио.рф/",
        ]
        for u in urls:
            parsed = parse_url(u)
            features = extract_features(parsed)
            for key, val in features.items():
                self.assertIsInstance(val, float, f"Feature {key} for {u} is not a float")
                self.assertFalse(math.isnan(val), f"Feature {key} for {u} is NaN")
                self.assertFalse(math.isinf(val), f"Feature {key} for {u} is Inf")

    def test_same_ordered_keys_for_every_input(self) -> None:
        """Assert every extracted dict has exactly FEATURE_NAMES keys in order."""
        urls = [
            "http://localhost/test",
            "https://user:pass@example.com:8080/path?q=1#top",
            "http://10.0.0.1/",
        ]
        for u in urls:
            parsed = parse_url(u)
            features = extract_features(parsed)
            self.assertEqual(list(features.keys()), FEATURE_NAMES)
