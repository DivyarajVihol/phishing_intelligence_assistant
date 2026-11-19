"""Threat intelligence orchestration service (plain Python)."""
import hashlib
import time
from typing import Any, Callable

from apps.core.types import Finding, ParsedURL, ThreatLookup
from apps.threat_intel import phishtank, urlhaus

_CACHE: dict[str, tuple[ThreatLookup, float]] = {}


def clear_cache() -> None:
    """Clear in-memory threat intelligence lookup cache."""
    _CACHE.clear()


def _get_setting(settings: Any, key: str, default: Any = None) -> Any:
    """Retrieve setting value supporting dict and object attribute access."""
    if isinstance(settings, dict):
        return settings.get(key, default)
    return getattr(settings, key, default)


def _cache_key(normalized_url: str, source: str) -> str:
    """Generate deterministic cache key for URL and intelligence source."""
    raw = f"{normalized_url}:{source}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _query_single_source(
    parsed: ParsedURL,
    settings: Any,
    source: str,
    connector_func: Callable[[ParsedURL, Any], ThreatLookup],
) -> ThreatLookup:
    """Query source with in-memory TTL cache; unavailable results are not cached."""
    ttl = float(_get_setting(settings, "LOOKUP_CACHE_TTL_SECONDS", 3600))
    key = _cache_key(parsed.normalized, source)
    now = time.time()

    if key in _CACHE:
        entry, expire_at = _CACHE[key]
        if now < expire_at:
            return entry
        del _CACHE[key]

    result = connector_func(parsed, settings)
    if result.status != "unavailable" and ttl > 0:
        _CACHE[key] = (result, now + ttl)
    return result


def query_sources(parsed: ParsedURL, settings: Any) -> list[ThreatLookup]:
    """Query enabled threat intelligence connectors with caching."""
    return [
        _query_single_source(parsed, settings, "phishtank", phishtank.lookup),
        _query_single_source(parsed, settings, "urlhaus", urlhaus.lookup),
    ]


def to_findings(lookups: list[ThreatLookup]) -> list[Finding]:
    """Convert threat lookups to analytical findings."""
    findings: list[Finding] = []
    for lk in lookups:
        check_name = f"intel.{lk.source}"
        if lk.status == "match":
            findings.append(
                Finding(
                    check_name=check_name,
                    category="intel",
                    status="flagged",
                    severity="high",
                    explanation=f"URL matched entry in {lk.source} threat intelligence lookup.",
                    evidence={"record_id": lk.record_id, "detail": lk.detail},
                    source=lk.source,
                    checked_at=lk.queried_at,
                )
            )
        elif lk.status == "no_match":
            findings.append(
                Finding(
                    check_name=check_name,
                    category="intel",
                    status="clear",
                    severity="info",
                    explanation="No match found in this source at the time of lookup.",
                    evidence={"record_id": lk.record_id, "detail": lk.detail},
                    source=lk.source,
                    checked_at=lk.queried_at,
                )
            )
        elif lk.status == "unavailable":
            findings.append(
                Finding(
                    check_name=check_name,
                    category="intel",
                    status="unavailable",
                    severity="info",
                    explanation=f"{lk.source} threat intelligence lookup was unavailable.",
                    evidence={"error": lk.error},
                    source=lk.source,
                    checked_at=lk.queried_at,
                )
            )
        else:
            findings.append(
                Finding(
                    check_name=check_name,
                    category="intel",
                    status="not_run",
                    severity="info",
                    explanation=f"{lk.source} source is not configured or disabled.",
                    evidence={},
                    source=lk.source,
                    checked_at=lk.queried_at,
                )
            )
    return findings
