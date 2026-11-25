"""Unit tests for ML prediction module."""
import json
import tempfile
import unittest

from apps.core.types import Prediction
from apps.ml_engine.predict import (
    _DEFAULT_ARTIFACTS_DIR,
    MODEL_VERSION,
    ModelUnavailable,
    build_row,
    load_model,
    predict,
)
from apps.url_analyzer.features import DOMAIN_FEATURE_NAMES
from apps.url_analyzer.parser import parse_url

_REAL_ARTIFACTS_EXIST = (
    (_DEFAULT_ARTIFACTS_DIR / f"model-{MODEL_VERSION}.joblib").is_file()
    and (_DEFAULT_ARTIFACTS_DIR / f"model-{MODEL_VERSION}.json").is_file()
)


class TestPredict(unittest.TestCase):
    """Test suite for ML prediction and artifact loading."""

    @unittest.skipUnless(_REAL_ARTIFACTS_EXIST, "Real artifacts not found")
    def test_predict_with_real_artifact(self) -> None:
        """Assert predict returns Prediction with valid score and consistent label."""
        parsed = parse_url("https://example.com")
        pred = predict(parsed)

        self.assertIsInstance(pred, Prediction)
        self.assertIsInstance(pred.score, float)
        self.assertGreaterEqual(pred.score, 0.0)
        self.assertLessEqual(pred.score, 1.0)
        expected_label = "phishing_like" if pred.score >= pred.threshold else "benign"
        self.assertEqual(pred.label, expected_label)
        self.assertEqual(pred.model_name, "logistic_regression")
        self.assertEqual(pred.model_version, MODEL_VERSION)

    def test_missing_artifacts_raises_model_unavailable(self) -> None:
        """Assert missing artifacts folder raises ModelUnavailable."""
        parsed = parse_url("https://example.com")
        with tempfile.TemporaryDirectory() as empty_dir:
            with self.assertRaises(ModelUnavailable):
                load_model(empty_dir)
            with self.assertRaises(ModelUnavailable):
                predict(parsed, artifacts_dir=empty_dir)

    def test_build_row_parity(self) -> None:
        """Assert build_row(parse_url(url)) equals [registered domain, lowercase]."""
        test_cases = [
            ("https://Sub.Example.COM/path?arg=1", "example.com"),
            ("http://TEST-domain.co.uk/test", "test-domain.co.uk"),
            ("https://paypal.com.example-login.com/verify", "example-login.com"),
            ("http://my-security-check.xyz/login", "my-security-check.xyz"),
            ("https://google.com", "google.com"),
        ]
        for url, expected_domain in test_cases:
            parsed = parse_url(url)
            self.assertEqual(build_row(parsed), [expected_domain])
            self.assertEqual(build_row(parsed), [parsed.registered_domain.lower()])

    @unittest.skipUnless(_REAL_ARTIFACTS_EXIST, "Real artifacts not found")
    def test_json_feature_names_parity(self) -> None:
        """Assert feature names in model-v2.json equal current DOMAIN_FEATURE_NAMES."""
        _, metadata = load_model()
        self.assertIn("DOMAIN_FEATURE_NAMES", metadata)
        self.assertEqual(metadata["DOMAIN_FEATURE_NAMES"], DOMAIN_FEATURE_NAMES)

    @unittest.skipUnless(_REAL_ARTIFACTS_EXIST, "Real artifacts not found")
    def test_google_com_score_and_threshold_matches_json(self) -> None:
        """Assert google.com scores in (0, 1) and threshold matches model-v2.json."""
        pred = predict(parse_url("https://www.google.com/"))
        self.assertGreater(pred.score, 0.0)
        self.assertLess(pred.score, 1.0)
        meta = json.loads((_DEFAULT_ARTIFACTS_DIR / f"model-{MODEL_VERSION}.json").read_text(encoding="utf-8"))
        self.assertEqual(pred.threshold, float(meta["threshold"]))

    @unittest.skipUnless(_REAL_ARTIFACTS_EXIST, "Real artifacts not found")
    def test_domain_only_predict_gives_same_score(self) -> None:
        """Assert predict produces identical score for same domain with different paths/subdomains."""
        p1 = parse_url("https://www.sub.example.com/a?b=1")
        p2 = parse_url("http://example.com")
        pred1 = predict(p1)
        pred2 = predict(p2)
        self.assertEqual(pred1.score, pred2.score)
        self.assertEqual(pred1.label, pred2.label)

    def test_load_model_caches_in_memory(self) -> None:
        """Assert load_model caches the artifact in memory across multiple calls."""
        if not _REAL_ARTIFACTS_EXIST:
            self.skipTest("Real artifacts not found")
        model1, meta1 = load_model()
        model2, meta2 = load_model()
        self.assertIs(model1, model2)
        self.assertIs(meta1, meta2)
