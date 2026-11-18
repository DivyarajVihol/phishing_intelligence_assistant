"""Unit tests for ML training, domain features, and model evaluation."""
import csv
import json
import math
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

import joblib
import numpy as np

from apps.ml_engine.predict import build_row
from apps.url_analyzer.features import DOMAIN_FEATURE_NAMES, domain_features
from ml.training.evaluate import compute_metrics, find_best_threshold
from ml.training.train import build_models, train_pipeline


class TestTrainAndEvaluate(unittest.TestCase):
    """Test suite for feature extraction, threshold selection, and model training."""

    def test_domain_features_keys_and_no_nan(self) -> None:
        """Assert domain_features returns exact expected keys with no NaN values."""
        test_domains = ["", "google.com", "sub-domain123.co.uk", "paypal-secure99.net"]
        for d in test_domains:
            feats = domain_features(d)
            self.assertEqual(list(feats.keys()), DOMAIN_FEATURE_NAMES)
            for k, val in feats.items():
                self.assertIsInstance(val, float)
                self.assertFalse(math.isnan(val), f"NaN feature {k} for domain '{d}'")

    def test_build_row(self) -> None:
        """Assert build_row extracts lowercased registered domain list."""
        parsed = Mock()
        parsed.registered_domain = "EXamPLE.CO.UK"
        row = build_row(parsed)
        self.assertEqual(row, ["example.co.uk"])

    def test_threshold_selection(self) -> None:
        """Assert threshold selection returns value between 0.0 and 1.0."""
        y_true = [0, 0, 0, 1, 1, 1]
        y_scores = [0.1, 0.2, 0.4, 0.7, 0.8, 0.9]
        thresh, max_f1 = find_best_threshold(y_true, y_scores)
        self.assertGreaterEqual(thresh, 0.0)
        self.assertLessEqual(thresh, 1.0)
        self.assertGreaterEqual(max_f1, 0.0)
        self.assertLessEqual(max_f1, 1.0)

    def test_saved_and_reloaded_pipeline_gives_identical_scores(self) -> None:
        """Assert serialized and deserialized pipeline generates identical predictions."""
        models = build_models()
        pipe = models["logistic_regression"]
        X = ["clean-domain.org", "phish-portal.xyz", "safe-site.com", "fake-bank.net"]
        y = [0, 1, 0, 1]
        pipe.fit(X, y)

        scores_before = pipe.predict_proba(X)[:, 1]
        with tempfile.NamedTemporaryFile(suffix=".joblib", delete=False) as f:
            joblib.dump(pipe, f.name)
            tmp_path = Path(f.name)

        reloaded = joblib.load(tmp_path)
        scores_after = reloaded.predict_proba(X)[:, 1]
        np.testing.assert_allclose(scores_before, scores_after, rtol=1e-6)

        try:
            tmp_path.unlink()
        except OSError:
            pass

    def test_training_end_to_end_on_synthetic_data(self) -> None:
        """Assert end-to-end training and artifact creation on synthetic dataset."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            synthetic_csv = tmp_path / "dataset.csv"
            artifacts_dir = tmp_path / "artifacts"

            with open(synthetic_csv, mode="w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=[
                    "url", "label", "source", "source_id", "collected_at", "registered_domain", "model_text", "split"
                ])
                writer.writeheader()
                for i in range(20):
                    split = "train" if i < 12 else ("validation" if i < 16 else "test")
                    label = 1 if i % 2 == 1 else 0
                    dom = f"site-{i}.xyz" if label == 1 else f"site-{i}.org"
                    writer.writerow({
                        "url": f"https://{dom}", "label": str(label), "source": "test",
                        "source_id": str(i), "collected_at": "", "registered_domain": dom,
                        "model_text": dom, "split": split,
                    })

            chosen_name, thresh = train_pipeline(synthetic_csv, artifacts_dir)
            self.assertIn(chosen_name, {"logistic_regression", "random_forest"})
            self.assertTrue((artifacts_dir / "model-v1.joblib").exists())
            self.assertTrue((artifacts_dir / "model-v1.json").exists())
            self.assertTrue((artifacts_dir / "evaluation.md").exists())

            with open(artifacts_dir / "model-v1.json", mode="r", encoding="utf-8") as f:
                meta = json.load(f)
            self.assertEqual(meta["version"], "v1")
            self.assertEqual(meta["threshold"], thresh)
            self.assertIn("validation", meta["metrics"])
            self.assertIn("test", meta["metrics"])
