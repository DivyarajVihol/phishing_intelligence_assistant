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
from ml.training.evaluate import compute_metrics, find_best_threshold, find_precision_threshold
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

            v1_joblib = artifacts_dir / "model-v1.joblib"
            v1_json = artifacts_dir / "model-v1.json"
            v1_eval = artifacts_dir / "evaluation.md"
            artifacts_dir.mkdir(parents=True, exist_ok=True)
            v1_joblib.write_bytes(b"v1-sentinel")
            v1_json.write_text('{"version":"v1"}', encoding="utf-8")
            v1_eval.write_text("v1-eval", encoding="utf-8")

            chosen_name, thresh = train_pipeline(synthetic_csv, artifacts_dir)
            self.assertIn(chosen_name, {"logistic_regression", "random_forest"})
            self.assertTrue((artifacts_dir / "model-v2.joblib").exists())
            self.assertTrue((artifacts_dir / "model-v2.json").exists())
            self.assertTrue((artifacts_dir / "evaluation-v2.md").exists())
            self.assertEqual(v1_joblib.read_bytes(), b"v1-sentinel")
            self.assertEqual(v1_json.read_text(encoding="utf-8"), '{"version":"v1"}')
            self.assertEqual(v1_eval.read_text(encoding="utf-8"), "v1-eval")

            with open(artifacts_dir / "model-v2.json", mode="r", encoding="utf-8") as f:
                meta = json.load(f)
            self.assertEqual(meta["version"], "v2")
            self.assertEqual(meta["threshold"], thresh)
            self.assertIn("validation", meta["metrics"])
            self.assertIn("test", meta["metrics"])
            self.assertIn("recent_test", meta["metrics"])

    def test_precision_threshold_target_and_fallback(self) -> None:
        """Assert precision-target threshold picks lowest threshold >= target and falls back when unreachable."""
        y_true = [0, 0, 0, 0, 1, 1, 1, 1]
        y_scores = [0.1, 0.2, 0.3, 0.6, 0.7, 0.8, 0.9, 0.95]
        t_hit, reached = find_precision_threshold(y_true, y_scores, target_precision=0.90)
        self.assertTrue(reached)
        self.assertAlmostEqual(t_hit, 0.7)

        y_true_unreach = [0, 0, 0, 1, 1]
        y_scores_unreach = [0.1, 0.8, 0.9, 0.5, 0.7]
        t_fb, reached_fb = find_precision_threshold(y_true_unreach, y_scores_unreach, target_precision=0.90)
        self.assertFalse(reached_fb)
        self.assertGreaterEqual(t_fb, 0.0)
        self.assertLessEqual(t_fb, 1.0)

    def test_v1_files_untouched_when_training_v2(self) -> None:
        """Assert model-v1 artifacts are not modified or deleted during v2 training."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            csv_path, art_dir = tmp_path / "dataset.csv", tmp_path / "artifacts"
            art_dir.mkdir()
            (art_dir / "model-v1.joblib").write_bytes(b"keep-v1")
            (art_dir / "model-v1.json").write_text('{"version":"v1"}', encoding="utf-8")
            (art_dir / "evaluation.md").write_text("keep-v1-eval", encoding="utf-8")
            with open(csv_path, mode="w", encoding="utf-8", newline="") as f:
                w = csv.DictWriter(f, fieldnames=["url", "label", "source", "source_id", "collected_at", "registered_domain", "model_text", "split"])
                w.writeheader()
                for i in range(16):
                    spl = "train" if i < 10 else ("validation" if i < 13 else "test")
                    lbl = i % 2
                    dom = f"d{i}.xyz" if lbl == 1 else f"d{i}.org"
                    w.writerow({"url": f"https://{dom}", "label": str(lbl), "source": "phiusiil", "source_id": str(i), "collected_at": "", "registered_domain": dom, "model_text": dom, "split": spl})
            train_pipeline(csv_path, art_dir)
            self.assertEqual((art_dir / "model-v1.joblib").read_bytes(), b"keep-v1")
            self.assertEqual((art_dir / "model-v1.json").read_text(encoding="utf-8"), '{"version":"v1"}')
            self.assertEqual((art_dir / "evaluation.md").read_text(encoding="utf-8"), "keep-v1-eval")
