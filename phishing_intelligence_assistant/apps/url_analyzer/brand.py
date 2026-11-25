"""Registered-domain brand similarity heuristic check (plain Python, no Django)."""
from typing import Optional

from apps.core.types import Finding, ParsedURL
from apps.url_analyzer.constants import (
    BRAND_DIST1_MEDIUM_MIN_LEN,
    BRAND_DIST2_LOW_MIN_LEN,
    BRAND_DOMAINS,
    BRAND_MAX_EDIT_DISTANCE,
    BRAND_MIN_LABEL_LEN,
)

_SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2}


def _normalize_lookalike(text: str) -> str:
    """Apply common visual look-alike substitutions to a domain label."""
    return text.replace("0", "o").replace("1", "l").replace("rn", "m").replace("vv", "w")


def _edit_distance(a: str, b: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if len(a) < len(b):
        return _edit_distance(b, a)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (ca != cb)))
        prev = curr
    return prev[-1]


def _extract_label(parsed: ParsedURL) -> str:
    """Extract the primary domain label from registered_domain without suffix."""
    reg = parsed.registered_domain.lower()
    suffix = parsed.suffix.lower()
    if suffix and reg.endswith(f".{suffix}"):
        return reg[: -(len(suffix) + 1)]
    return reg.rsplit(".", 1)[0] if "." in reg else reg


def _score_brand_match(label: str, norm_label: str, brand_domain: str) -> Optional[tuple[int, int, str, str, str]]:
    """Evaluate a single brand domain against the target label using severity rules."""
    bl = brand_domain.split(".")[0]
    if len(bl) < BRAND_MIN_LABEL_LEN or len(label) < BRAND_MIN_LABEL_LEN:
        return None
    if label == bl:
        return (_SEVERITY_RANK["medium"], 0, "medium", brand_domain, "same brand label on a different suffix")
    if norm_label == bl:
        return (_SEVERITY_RANK["high"], 0, "high", brand_domain, "look-alike character substitution")
    dist = min(_edit_distance(label, bl), _edit_distance(norm_label, bl))
    if dist == 1:
        sev = "medium" if len(label) >= BRAND_DIST1_MEDIUM_MIN_LEN else "low"
        return (_SEVERITY_RANK[sev], 1, sev, brand_domain, f"edit distance 1 on {len(label)}-char label")
    if dist == BRAND_MAX_EDIT_DISTANCE and len(label) >= BRAND_DIST2_LOW_MIN_LEN:
        return (_SEVERITY_RANK["low"], 2, "low", brand_domain, f"edit distance 2 on {len(label)}-char label")
    return None


def check_brand_similarity(parsed: ParsedURL) -> list[Finding]:
    """Flag registered domains that closely resemble well-known brand domains."""
    reg = parsed.registered_domain.lower()
    if parsed.is_ip_host or not reg or reg in BRAND_DOMAINS:
        return []
    label = _extract_label(parsed)
    norm_label = _normalize_lookalike(label)
    best: Optional[tuple[int, int, str, str, str]] = None
    for brand_domain in BRAND_DOMAINS:
        cand = _score_brand_match(label, norm_label, brand_domain)
        if cand is not None and (best is None or cand[:2] < best[:2]):
            best = cand
    if best is None:
        return []
    _, dist, severity, brand_domain, reason = best
    return [Finding(
        check_name="brand.similarity", category="heuristic", status="flagged", severity=severity,
        explanation=f"Registered domain '{reg}' resembles '{brand_domain}' ({reason}). This is a warning, not proof.",
        evidence={"registered_domain": reg, "matched_brand": brand_domain, "distance": dist, "reason": reason},
        source="brand",
    )]
