"""Prediction module for ML engine (plain Python)."""
from apps.core.types import ParsedURL


def build_row(parsed: ParsedURL) -> list[str]:
    """Extract registered domain text representation for ML model input."""
    return [parsed.registered_domain.lower()]
