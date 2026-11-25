"""Train, compare, evaluate, and save domain-level phishing detection models (v2)."""
import csv
import datetime
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Optional

import joblib
import numpy as np
import sklearn
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer

from apps.ml_engine.predict import ModelUnavailable, load_model
from apps.url_analyzer.features import DOMAIN_FEATURE_NAMES, domain_features
from ml.training.evaluate import (
    SANITY_DOMAINS,
    build_evaluation_markdown,
    compute_metrics,
    compute_sanity_rows,
    compute_source_recall,
    compute_tld_breakdown,
    find_precision_threshold,
    get_top_errors,
    get_top_ngrams,
)

TARGET_PRECISION = 0.90
OPTION_TARGETS = (0.80, 0.90, 0.95)


def extract_domain_features_matrix(domains: list[str]) -> list[list[float]]:
    """Extract ordered numeric feature vectors for domain strings."""
    return [[domain_features(d)[name] for name in DOMAIN_FEATURE_NAMES] for d in domains]


def load_dataset(filepath: Path) -> tuple[dict[str, tuple[list[str], list[int]]], list[str], dict[str, Any], dict[str, int]]:
    """Load dataset splits, source breakdown, CSV SHA-256 hash, and prep stats."""
    splits: dict[str, tuple[list[str], list[int]]] = {
        "train": ([], []), "validation": ([], []), "test": ([], []), "recent_test": ([], []),
    }
    test_sources: list[str] = []
    classes: Counter[int] = Counter()
    src_lbl_spl: Counter[tuple[str, int, str]] = Counter()
    content = filepath.read_text(encoding="utf-8")
    csv_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()

    for row in csv.DictReader(content.splitlines()):
        s, lbl, src = row["split"], int(row["label"]), row.get("source", "unknown")
        if s in splits:
            splits[s][0].append(row["model_text"])
            splits[s][1].append(lbl)
            classes[lbl] += 1
            src_lbl_spl[(src, lbl, s)] += 1
            if s == "test":
                test_sources.append(src)

    stats_file = filepath.parent / "prep_stats.json"
    prep_stats = json.loads(stats_file.read_text(encoding="utf-8")) if stats_file.is_file() else {}
    summary = {
        "total_rows": sum(len(v[0]) for v in splits.values()),
        "rows_per_split": {k: len(v[0]) for k, v in splits.items()},
        "rows_per_class": {"benign": classes[0], "phishing": classes[1]},
        "dataset_csv_sha256": csv_hash,
        "counts_by_source_label_split": dict(src_lbl_spl),
    }
    return splits, test_sources, summary, prep_stats


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
                random_state=42, n_jobs=1,
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
    """Save v2 pipeline, metadata JSON, and evaluation markdown without touching v1."""
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    joblib_path = artifacts_dir / "model-v2.joblib"
    joblib.dump(chosen_pipe, joblib_path)
    print(f"Saved {chosen_name} artifact ({joblib_path.stat().st_size / (1024 * 1024):.2f} MB) to {joblib_path}")
    (artifacts_dir / "model-v2.json").write_text(json.dumps(json_data, indent=2), encoding="utf-8")
    (artifacts_dir / "evaluation-v2.md").write_text(md_text, encoding="utf-8")


def _load_v1_safe(v1_dir: Path) -> tuple[Any, dict[str, Any]]:
    """Load v1 model and metadata via predict.load_model, returning (None, {}) if unavailable."""
    try:
        return load_model(v1_dir)
    except ModelUnavailable:
        return None, {}


def _eval_options(
    val_y: list[int], val_s: list[float], test_y: list[int], test_s: list[float],
    rec_y: list[int], rec_s: list[float], sanity_probs: list[float],
) -> list[dict[str, Any]]:
    """Evaluate threshold options across target precisions using validation only."""
    options: list[dict[str, Any]] = []
    for target in OPTION_TARGETS:
        t, reached = find_precision_threshold(val_y, val_s, target)
        vm = compute_metrics(val_y, val_s, t)
        tm = compute_metrics(test_y, test_s, t)
        cm = tm["confusion_matrix"]
        fp, tn = cm[0][1], cm[0][0]
        rec_recall = compute_metrics(rec_y, rec_s, t)["recall"] if rec_y else 0.0
        options.append({
            "target": target, "reached": reached, "threshold": t,
            "val_prec": vm["precision"], "val_rec": vm["recall"],
            "test_prec": tm["precision"], "test_rec": tm["recall"],
            "test_fp": fp, "test_fpr": fp / (fp + tn) if (fp + tn) else 0.0,
            "recent_rec": rec_recall, "sanity_flagged": sum(1 for p in sanity_probs if p >= t),
        })
    return options


def train_pipeline(dataset_csv: Path, artifacts_dir: Path, v1_artifacts_dir: Optional[Path] = None) -> tuple[str, float]:
    """Execute end-to-end v2 model training, precision-threshold tuning, and evaluation."""
    splits, test_sources, summary, prep_stats = load_dataset(dataset_csv)
    chosen_name, chosen_pipe, all_val = fit_and_compare(build_models(), splits)
    val_s, t_s = all_val[chosen_name]["scores"], chosen_pipe.predict_proba(splits["test"][0])[:, 1]
    r_x, r_y = splits["recent_test"]
    r_s = chosen_pipe.predict_proba(r_x)[:, 1] if r_x else []

    thresh, reached = find_precision_threshold(splits["validation"][1], val_s, TARGET_PRECISION)
    v_m = compute_metrics(splits["validation"][1], val_s, thresh)
    t_m = compute_metrics(splits["test"][1], t_s, thresh)
    r_m = compute_metrics(r_y, r_s, thresh) if r_x else {"accuracy": 0.0, "precision": 0.0, "recall": 0.0, "f1": 0.0, "pr_auc": 0.0, "roc_auc": 0.0, "confusion_matrix": [[0, 0], [0, 0]]}

    v1_model, v1_meta = _load_v1_safe(v1_artifacts_dir or artifacts_dir)
    v1_thresh = float(v1_meta.get("threshold", 0.5))
    v1_rec = compute_metrics(r_y, v1_model.predict_proba(r_x)[:, list(v1_model.classes_).index(1)], v1_thresh)["recall"] if (v1_model is not None and r_x) else None
    v2_sanity = compute_sanity_rows(chosen_pipe, thresh)
    options = _eval_options(splits["validation"][1], val_s, splits["test"][1], t_s, r_y, r_s, [r["score"] for r in v2_sanity])

    json_summary = {k: v for k, v in summary.items() if k != "counts_by_source_label_split"}
    json_data = {
        "model_name": chosen_name, "version": "v2", "trained_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "python_version": sys.version, "sklearn_version": sklearn.__version__, "numpy_version": np.__version__,
        "DOMAIN_FEATURE_NAMES": DOMAIN_FEATURE_NAMES, "threshold": thresh,
        "input_type": "list of registered-domain strings", "dataset_summary": json_summary,
        "metrics": {"validation": v_m, "test": t_m, "recent_test": r_m},
    }
    pos_ng, neg_ng = get_top_ngrams(chosen_pipe) if chosen_name == "logistic_regression" else ([], [])
    md = build_evaluation_markdown(
        chosen_name, thresh, reached, all_val, v_m, t_m, r_m, v1_rec, options,
        compute_sanity_rows(v1_model, v1_thresh), v2_sanity, pos_ng, neg_ng,
        compute_tld_breakdown(splits["test"][0], splits["test"][1], t_s, thresh),
        *get_top_errors(splits["test"][0], splits["test"][1], t_s, thresh, top_n=10),
        summary, prep_stats, compute_source_recall(splits["test"][1], t_s, test_sources, thresh),
    )
    print(md)
    save_artifacts(artifacts_dir, chosen_name, chosen_pipe, json_data, md)
    return chosen_name, thresh


def main() -> None:
    """CLI entry point for python -m ml.training.train."""
    base = Path(__file__).resolve().parent.parent
    train_pipeline(base / "data" / "processed" / "dataset.csv", base / "artifacts")


if __name__ == "__main__":
    main()
