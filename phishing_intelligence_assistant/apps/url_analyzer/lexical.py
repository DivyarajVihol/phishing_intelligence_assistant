"""Lexical heuristic checks for suspicious URL characteristics (plain Python)."""
from apps.core.types import Finding, ParsedURL
from apps.url_analyzer.constants import (
    LEXICAL_MAX_SUBDOMAINS,
    LEXICAL_MAX_URL_LENGTH,
    SUSPICIOUS_TOKENS,
)


def _check_url_length(parsed: ParsedURL) -> list[Finding]:
    """Flag URLs that exceed recommended length threshold."""
    length = len(parsed.original)
    if length > LEXICAL_MAX_URL_LENGTH:
        return [
            Finding(
                check_name="lexical.url_length",
                category="heuristic",
                status="flagged",
                severity="low",
                explanation=(
                    f"URL length ({length} characters) exceeds the threshold of {LEXICAL_MAX_URL_LENGTH}. "
                    "Long URLs may be used to obscure destinations, but this is a warning, not proof."
                ),
                evidence={"length": length, "threshold": LEXICAL_MAX_URL_LENGTH},
                source="lexical",
            )
        ]
    return []


def _check_subdomains(parsed: ParsedURL) -> list[Finding]:
    """Flag URLs with multiple subdomain levels."""
    count = len([s for s in parsed.subdomain.split(".") if s]) if parsed.subdomain else 0
    if count > LEXICAL_MAX_SUBDOMAINS:
        return [
            Finding(
                check_name="lexical.subdomain_count",
                category="heuristic",
                status="flagged",
                severity="medium",
                explanation=(
                    f"Hostname contains {count} subdomain levels (threshold {LEXICAL_MAX_SUBDOMAINS}). "
                    "Excessive subdomains can mimic legitimate domains, but this is a warning, not proof."
                ),
                evidence={"subdomain_count": count, "threshold": LEXICAL_MAX_SUBDOMAINS},
                source="lexical",
            )
        ]
    return []


def _check_ip_host(parsed: ParsedURL) -> list[Finding]:
    """Flag URLs that use an IP address as the host."""
    if parsed.is_ip_host:
        return [
            Finding(
                check_name="lexical.ip_host",
                category="heuristic",
                status="flagged",
                severity="medium",
                explanation=(
                    "URL uses a numerical IP address instead of a domain name. "
                    "Direct IP hosting is common in unmanaged or hostile infrastructure, but this is a warning, not proof."
                ),
                evidence={"hostname": parsed.hostname},
                source="lexical",
            )
        ]
    return []


def _check_suspicious_keywords(parsed: ParsedURL) -> list[Finding]:
    """Flag URLs containing credential- or authentication-related tokens."""
    lower_raw = parsed.original.lower()
    matched = [token for token in SUSPICIOUS_TOKENS if token in lower_raw]
    if matched:
        return [
            Finding(
                check_name="lexical.suspicious_keywords",
                category="heuristic",
                status="flagged",
                severity="medium" if len(matched) > 1 else "low",
                explanation=(
                    f"URL contains sensitive security keywords: {', '.join(matched)}. "
                    "Keywords targeting authentication often appear in phishing lures, but this is a warning, not proof."
                ),
                evidence={"matched_tokens": matched, "count": len(matched)},
                source="lexical",
            )
        ]
    return []


def _check_at_symbol(parsed: ParsedURL) -> list[Finding]:
    """Flag URLs that contain the '@' userinfo character."""
    if "@" in parsed.original or parsed.userinfo:
        return [
            Finding(
                check_name="lexical.at_symbol",
                category="heuristic",
                status="flagged",
                severity="medium",
                explanation=(
                    "URL contains an '@' character in the authority section. "
                    "Preceding text is ignored by browsers for destination host lookup, but this is a warning, not proof."
                ),
                evidence={"userinfo": parsed.userinfo, "at_count": parsed.original.count("@")},
                source="lexical",
            )
        ]
    return []


def _check_https(parsed: ParsedURL) -> list[Finding]:
    """Note missing HTTPS encryption as an informational finding."""
    if parsed.scheme != "https":
        return [
            Finding(
                check_name="lexical.https_scheme",
                category="heuristic",
                status="flagged",
                severity="info",
                explanation=(
                    "URL does not use HTTPS encryption. "
                    "Unencrypted HTTP communication is insecure, though non-HTTPS is a warning, not proof of malice."
                ),
                evidence={"scheme": parsed.scheme},
                source="lexical",
            )
        ]
    return []


def check_lexical(parsed: ParsedURL) -> list[Finding]:
    """Execute all lexical heuristic checks against a parsed URL."""
    findings: list[Finding] = []
    findings.extend(_check_url_length(parsed))
    findings.extend(_check_subdomains(parsed))
    findings.extend(_check_ip_host(parsed))
    findings.extend(_check_suspicious_keywords(parsed))
    findings.extend(_check_at_symbol(parsed))
    findings.extend(_check_https(parsed))
    return findings
