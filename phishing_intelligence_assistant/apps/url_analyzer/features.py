"""Numerical feature extraction for ML model and URL analysis (plain Python)."""
import math
from collections import Counter

from apps.core.types import ParsedURL
from apps.url_analyzer.constants import SUSPICIOUS_TOKENS

FEATURE_NAMES: list[str] = [
    "url_length",
    "host_length",
    "registered_domain_length",
    "dot_count",
    "dot_ratio",
    "hyphen_count",
    "hyphen_ratio",
    "digit_count",
    "digit_ratio",
    "special_char_count",
    "special_char_ratio",
    "subdomain_count",
    "is_ip_host",
    "has_https",
    "path_depth",
    "path_length",
    "query_length",
    "query_param_count",
    "at_count",
    "percent_count",
    "suspicious_token_count",
    "non_ascii_or_punycode",
    "hostname_entropy",
]


def _calculate_hostname_entropy(hostname: str) -> float:
    """Calculate Shannon entropy for hostname character distribution."""
    if not hostname:
        return 0.0
    length = len(hostname)
    counts = Counter(hostname)
    return float(-sum((c / length) * math.log2(c / length) for c in counts.values()))


def _extract_char_stats(raw: str) -> tuple[float, float, float, float, float, float, float, float]:
    """Compute counts and ratios for dots, hyphens, digits, and special characters."""
    total_len = max(len(raw), 1)
    dots = float(raw.count("."))
    hyphens = float(raw.count("-"))
    digits = float(sum(1 for c in raw if c.isdigit()))
    specials = float(sum(1 for c in raw if not c.isalnum()))
    return (
        dots,
        dots / total_len,
        hyphens,
        hyphens / total_len,
        digits,
        digits / total_len,
        specials,
        specials / total_len,
    )


def extract_features(parsed: ParsedURL) -> dict[str, float]:
    """Extract numeric feature dictionary aligned with FEATURE_NAMES."""
    raw = parsed.original
    dots, dot_r, hyphs, hyph_r, digits, digit_r, specials, special_r = _extract_char_stats(raw)
    sub_count = float(len([s for s in parsed.subdomain.split(".") if s])) if parsed.subdomain else 0.0
    path_depth = float(len([s for s in parsed.path.split("/") if s])) if parsed.path else 0.0
    query_params = float(len([p for p in parsed.query.split("&") if p])) if parsed.query else 0.0
    lower_raw = raw.lower()
    token_count = float(sum(lower_raw.count(token) for token in SUSPICIOUS_TOKENS))
    has_non_ascii = any(ord(c) > 127 for c in raw) or ("xn--" in parsed.hostname) or ("xn--" in parsed.normalized)

    features: dict[str, float] = {
        "url_length": float(len(raw)),
        "host_length": float(len(parsed.hostname)),
        "registered_domain_length": float(len(parsed.registered_domain)),
        "dot_count": dots,
        "dot_ratio": dot_r,
        "hyphen_count": hyphs,
        "hyphen_ratio": hyph_r,
        "digit_count": digits,
        "digit_ratio": digit_r,
        "special_char_count": specials,
        "special_char_ratio": special_r,
        "subdomain_count": sub_count,
        "is_ip_host": 1.0 if parsed.is_ip_host else 0.0,
        "has_https": 1.0 if parsed.scheme == "https" else 0.0,
        "path_depth": path_depth,
        "path_length": float(len(parsed.path)),
        "query_length": float(len(parsed.query)),
        "query_param_count": query_params,
        "at_count": float(raw.count("@")),
        "percent_count": float(raw.count("%")),
        "suspicious_token_count": token_count,
        "non_ascii_or_punycode": 1.0 if has_non_ascii else 0.0,
        "hostname_entropy": _calculate_hostname_entropy(parsed.hostname),
    }
    return {name: features[name] for name in FEATURE_NAMES}
