"""Prediction module for ML engine (plain Python)."""
import json
from pathlib import Path
from typing import Any, Optional, Union

import joblib

from apps.core.types import ParsedURL, Prediction

MODEL_VERSION = "v2"
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_ARTIFACTS_DIR = _PROJECT_ROOT / "ml" / "artifacts"
_MODEL_CACHE: dict[Path, tuple[Any, dict[str, Any]]] = {}


class ModelUnavailable(Exception):
    """Raised when machine learning model artifacts cannot be loaded."""


def build_row(parsed: ParsedURL) -> list[str]:
    """Extract registered domain text representation for ML model input."""
    return [parsed.registered_domain.lower()]


def load_model(
    artifacts_dir: Optional[Union[str, Path]] = None,
) -> tuple[Any, dict[str, Any]]:
    """Load model pipeline and metadata from artifacts directory, cached in memory."""
    target_dir = Path(artifacts_dir).resolve() if artifacts_dir is not None else _DEFAULT_ARTIFACTS_DIR.resolve()
    if target_dir in _MODEL_CACHE:
        return _MODEL_CACHE[target_dir]

    joblib_path = target_dir / f"model-{MODEL_VERSION}.joblib"
    json_path = target_dir / f"model-{MODEL_VERSION}.json"
    if not joblib_path.is_file() or not json_path.is_file():
        raise ModelUnavailable(f"Artifact files missing in {target_dir}")

    try:
        with open(json_path, mode="r", encoding="utf-8") as f:
            metadata = json.load(f)
        model = joblib.load(joblib_path)
    except Exception as exc:
        raise ModelUnavailable(f"Failed to load artifacts from {target_dir}: {exc}") from exc

    _MODEL_CACHE[target_dir] = (model, metadata)
    return model, metadata


def predict(
    parsed: ParsedURL,
    artifacts_dir: Optional[Union[str, Path]] = None,
) -> Prediction:
    """Predict phishing likelihood from parsed URL using trained model."""
    model, metadata = load_model(artifacts_dir)
    row = build_row(parsed)
    try:
        classes = list(model.classes_)
        class_1_idx = classes.index(1)
        proba = model.predict_proba(row)[0]
        score = float(proba[class_1_idx])
    except Exception as exc:
        raise ModelUnavailable(f"Prediction failed: {exc}") from exc

    threshold = float(metadata.get("threshold", 0.5))
    label = "phishing_like" if score >= threshold else "benign"
    model_name = str(metadata.get("model_name", "logistic_regression"))
    model_version = str(metadata.get("version", metadata.get("model_version", MODEL_VERSION)))

    return Prediction(
        model_name=model_name,
        model_version=model_version,
        label=label,
        score=score,
        threshold=threshold,
    )
