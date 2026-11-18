"""Train, compare, evaluate, and save domain-level phishing detection models."""
import csv
import datetime
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import sklearn
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer

from apps.url_analyzer.features import DOMAIN_FEATURE_NAMES, domain_features
from ml.training.evaluate import (
    build_evaluation_markdown,
    compute_metrics,
    compute_tld_breakdown,
    find_best_threshold,
    get_top_errors,
    get_top_ngrams,
)


def extract_domain_features_matrix(domains: list[str]) -> list[list[float]]:
    """Extract ordered numeric feature vectors for domain strings."""
    return [[domain_features(d)[name] for name in DOMAIN_FEATURE_NAMES] for d in domains]


def load_dataset(filepath: Path) -> tuple[dict[str, tuple[list[str], list[int]]], dict[str, Any], str]:
    """Load dataset splits, summarize records, and compute CSV SHA-256 hash."""
    splits: dict[str, tuple[list[str], list[int]]] = {"train": ([], []), "validation": ([], []), "test": ([], [])}
    classes: Counter[int] = Counter()
    hasher = hashlib.sha256()

    with open(filepath, mode="r", encoding="utf-8") as f:
        content = f.read()
        hasher.update(content.encode("utf-8"))

    with open(filepath, mode="r", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            s, lbl = row["split"], int(row["label"])
            if s in splits:
                splits[s][0].append(row["model_text"])
                splits[s][1].append(lbl)
                classes[lbl] += 1

    summary = {
        "total_rows": sum(len(v[0]) for v in splits.values()),
        "rows_per_split": {k: len(v[0]) for k, v in splits.items()},
        "rows_per_class": {"benign": classes[0], "phishing": classes[1]},
        "dataset_csv_sha256": hasher.hexdigest(),
    }
    return splits, summary, hasher.hexdigest()


def build_models() -> dict[str, Pipeline]:
    """Instantiate model pipelines for comparison."""
    return {
        "logistic_regression": Pipeline([
            ("tfidf", TfidfVectorizer(analyzer="char", ngram_range=(2, 5), max_features=100000)),
            ("clf", LogisticRegression(class_weight="balanced", random_state=42, max_iter=1000)),
        ]),
        "random_forest": Pipeline([
            ("feats", FunctionTransformer(extract_domain_features_matrix)),
            ("clf", RandomForestClassifier(
                n_estimators=100, max_depth=20, min_samples_leaf=5, class_weight="balanced",
                random_state=42, n_jobs=1
            )),
        ]),
        "dummy_baseline": Pipeline([("clf", DummyClassifier(strategy="most_frequent"))]),
    }


def fit_and_compare(models: dict[str, Pipeline], splits: dict[str, Any]) -> tuple[str, Pipeline, dict[str, Any]]:
    """Fit candidate models on train split and compare via validation PR-AUC."""
    X_tr, y_tr = splits["train"]
    X_val, y_val = splits["validation"]
    val_metrics: dict[str, Any] = {}

    for name, pipe in models.items():
        print(f"Fitting {name}...")
        pipe.fit(X_tr, y_tr)
        scores = pipe.predict_proba(X_val)[:, 1] if hasattr(pipe, "predict_proba") else [0.0] * len(y_val)
        val_metrics[name] = {"scores": scores, **compute_metrics(y_val, scores, 0.5)}

    chosen = "logistic_regression" if val_metrics["logistic_regression"]["pr_auc"] >= val_metrics["random_forest"]["pr_auc"] else "random_forest"
    print(f"Chosen model: {chosen} (PR-AUC: {val_metrics[chosen]['pr_auc']:.4f})")
    return chosen, models[chosen], val_metrics


def save_artifacts(artifacts_dir: Path, chosen_name: str, chosen_pipe: Pipeline, json_data: dict[str, Any], md_text: str) -> None:
    """Save pipeline, metadata JSON, and markdown report to artifacts directory."""
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    joblib_path = artifacts_dir / "model-v1.joblib"
    joblib.dump(chosen_pipe, joblib_path)
    size_mb = joblib_path.stat().st_size / (1024 * 1024)
    print(f"Saved {chosen_name} artifact ({size_mb:.2f} MB) to {joblib_path}")

    with open(artifacts_dir / "model-v1.json", mode="w", encoding="utf-8") as f:
        json.dump(json_data, f, indent=2)

    with open(artifacts_dir / "evaluation.md", mode="w", encoding="utf-8") as f:
        f.write(md_text)


def train_pipeline(dataset_csv: Path, artifacts_dir: Path) -> tuple[str, float]:
    """Execute end-to-end model training, threshold tuning, and artifact generation."""
    splits, summary, _ = load_dataset(dataset_csv)
    chosen_name, chosen_pipe, all_val = fit_and_compare(build_models(), splits)

    thresh, _ = find_best_threshold(splits["validation"][1], all_val[chosen_name]["scores"])
    v_metrics = compute_metrics(splits["validation"][1], all_val[chosen_name]["scores"], thresh)
    test_scores = chosen_pipe.predict_proba(splits["test"][0])[:, 1]
    t_metrics = compute_metrics(splits["test"][1], test_scores, thresh)

    json_data = {
        "model_name": chosen_name, "version": "v1", "trained_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "python_version": sys.version, "sklearn_version": sklearn.__version__, "numpy_version": np.__version__,
        "DOMAIN_FEATURE_NAMES": DOMAIN_FEATURE_NAMES, "threshold": thresh,
        "input_type": "list of registered-domain strings", "dataset_summary": summary,
        "metrics": {"validation": v_metrics, "test": t_metrics},
    }
    pos_ng, neg_ng = get_top_ngrams(chosen_pipe) if chosen_name == "logistic_regression" else ([], [])
    tld_b = compute_tld_breakdown(splits["test"][0], splits["test"][1], test_scores, thresh)
    fps, fns = get_top_errors(splits["test"][0], splits["test"][1], test_scores, thresh)
    md = build_evaluation_markdown(chosen_name, thresh, all_val, v_metrics, t_metrics, pos_ng, neg_ng, tld_b, fps, fns)

    save_artifacts(artifacts_dir, chosen_name, chosen_pipe, json_data, md)
    return chosen_name, thresh


def main() -> None:
    """CLI entry point for python -m ml.training.train."""
    base = Path(__file__).resolve().parent.parent
    train_pipeline(base / "data" / "processed" / "dataset.csv", base / "artifacts")


if __name__ == "__main__":
    main()
