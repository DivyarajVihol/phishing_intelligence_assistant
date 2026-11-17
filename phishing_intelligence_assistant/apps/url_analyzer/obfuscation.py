"""URL obfuscation and deception heuristic checks (plain Python, no Django)."""
import re

from apps.core.types import Finding, ParsedURL
from apps.url_analyzer.constants import BRAND_TOKENS, LEXICAL_MAX_SUBDOMAINS


def _check_percent_encoding(parsed: ParsedURL) -> list[Finding]:
    """Flag percent-encoded characters in hostname or path."""
    in_host = "%" in parsed.hostname
    in_path = "%" in parsed.path
    if in_host or in_path:
        severity = "medium" if in_host else "low"
        comp = "hostname" if in_host else "path"
        return [
            Finding(
                check_name="obfuscation.percent_encoding",
                category="heuristic",
                status="flagged",
                severity=severity,
                explanation=(
                    f"Percent-encoding ('%') was detected in the URL {comp}. "
                    "Encoding characters can bypass simple keyword filters or conceal text, but this is a warning, not proof."
                ),
                evidence={"component": comp, "in_host": in_host, "in_path": in_path},
                source="obfuscation",
            )
        ]
    return []


def _check_userinfo_deception(parsed: ParsedURL) -> list[Finding]:
    """Flag '@' userinfo credentials that obscure the true destination host."""
    if parsed.userinfo:
        return [
            Finding(
                check_name="obfuscation.userinfo_deception",
                category="heuristic",
                status="flagged",
                severity="high",
                explanation=(
                    f"URL contains '@' userinfo credentials ('{parsed.userinfo}') before destination host '{parsed.hostname}'. "
                    "Preceding text is ignored for host resolution and can mislead users, but this is a warning, not proof."
                ),
                evidence={"userinfo": parsed.userinfo, "destination_host": parsed.hostname},
                source="obfuscation",
            )
        ]
    return []


def _check_repeated_separators(parsed: ParsedURL) -> list[Finding]:
    """Flag consecutive separators such as '//' in path or '--' in hostname."""
    has_double_slash = "//" in parsed.path
    clean_host = parsed.hostname.replace("xn--", "")
    has_double_dash = "--" in clean_host
    if has_double_slash or has_double_dash:
        return [
            Finding(
                check_name="obfuscation.repeated_separators",
                category="heuristic",
                status="flagged",
                severity="low",
                explanation=(
                    "Repeated separators ('//' in path or '--' in host) were detected. "
                    "Consecutive delimiters are sometimes used to disguise folder structures or domains, but this is a warning, not proof."
                ),
                evidence={"double_slash_path": has_double_slash, "double_dash_host": has_double_dash},
                source="obfuscation",
            )
        ]
    return []


def _check_unicode_or_punycode(parsed: ParsedURL) -> list[Finding]:
    """Flag non-ASCII or punycode ('xn--') hostnames as homograph warnings."""
    has_non_ascii = any(ord(c) > 127 for c in parsed.hostname)
    has_punycode = "xn--" in parsed.hostname
    if has_non_ascii or has_punycode:
        return [
            Finding(
                check_name="obfuscation.non_ascii_punycode",
                category="heuristic",
                status="flagged",
                severity="medium",
                explanation=(
                    "Hostname uses non-ASCII characters or punycode encoding ('xn--'). "
                    "Internationalized domain names can facilitate lookalike homograph attacks, though IDNs can be legitimate. This is a warning, not proof."
                ),
                evidence={"has_non_ascii": has_non_ascii, "has_punycode": has_punycode},
                source="obfuscation",
            )
        ]
    return []


def _check_excessive_subdomains(parsed: ParsedURL) -> list[Finding]:
    """Flag excessive subdomain nesting beyond standard thresholds."""
    count = len([s for s in parsed.subdomain.split(".") if s]) if parsed.subdomain else 0
    if count > LEXICAL_MAX_SUBDOMAINS:
        return [
            Finding(
                check_name="obfuscation.excessive_subdomains",
                category="heuristic",
                status="flagged",
                severity="low",
                explanation=(
                    f"Hostname contains {count} subdomain levels (threshold {LEXICAL_MAX_SUBDOMAINS}). "
                    "Deep subdomain nesting can mimic reputable domain structures, but this is a warning, not proof."
                ),
                evidence={"subdomain_count": count, "threshold": LEXICAL_MAX_SUBDOMAINS},
                source="obfuscation",
            )
        ]
    return []


def _check_brand_in_subdomain_or_path(parsed: ParsedURL) -> list[Finding]:
    """Flag recognized brand names in subdomain or path when registered domain differs."""
    reg_tokens = set(re.findall(r"[a-z0-9]+", parsed.registered_domain.lower()))
    sub_tokens = set(re.findall(r"[a-z0-9]+", parsed.subdomain.lower()))
    path_tokens = set(re.findall(r"[a-z0-9]+", parsed.path.lower()))

    mismatches: list[str] = []
    for brand in BRAND_TOKENS:
        if brand not in reg_tokens and (brand in sub_tokens or brand in path_tokens):
            mismatches.append(brand)

    if mismatches:
        return [
            Finding(
                check_name="obfuscation.brand_mismatch",
                category="heuristic",
                status="flagged",
                severity="high",
                explanation=(
                    f"Recognized brand token ({', '.join(mismatches)}) appears in subdomain/path while registered domain is '{parsed.registered_domain}'. "
                    "Brand names placed in subcomponents often impersonate legitimate services, but this is a warning, not proof."
                ),
                evidence={"brands": mismatches, "registered_domain": parsed.registered_domain},
                source="obfuscation",
            )
        ]
    return []


def check_obfuscation(parsed: ParsedURL) -> list[Finding]:
    """Execute all URL obfuscation and deception checks against a parsed URL."""
    findings: list[Finding] = []
    findings.extend(_check_percent_encoding(parsed))
    findings.extend(_check_userinfo_deception(parsed))
    findings.extend(_check_repeated_separators(parsed))
    findings.extend(_check_unicode_or_punycode(parsed))
    findings.extend(_check_excessive_subdomains(parsed))
    findings.extend(_check_brand_in_subdomain_or_path(parsed))
    return findings
