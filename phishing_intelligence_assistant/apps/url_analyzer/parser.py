"""URL parsing and normalization (plain Python, no Django)."""
import ipaddress
import urllib.parse
from typing import Optional

import tldextract

from apps.core.types import ParsedURL
from apps.url_analyzer.constants import (
    ALLOWED_SCHEMES,
    BLOCKED_SCHEMES,
    DEFAULT_MAX_URL_LENGTH,
)

_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())


class InvalidURLError(ValueError):
    """Raised when a URL is invalid, unsupported, or violates security constraints."""


def _validate_raw_input(raw: str, max_len: int) -> None:
    """Validate string length, presence, whitespace, and control characters."""
    if not isinstance(raw, str) or not raw or not raw.strip():
        raise InvalidURLError("URL cannot be empty")
    if len(raw) > max_len:
        raise InvalidURLError(f"URL exceeds maximum length of {max_len} characters")
    if any(char.isspace() for char in raw):
        raise InvalidURLError("URL must not contain whitespace characters")
    if any(ord(char) < 32 or ord(char) == 127 for char in raw):
        raise InvalidURLError("URL must not contain control characters")


def _resolve_scheme_and_work_url(raw: str) -> tuple[str, bool, str]:
    """Resolve scheme, flag if assumed, and return a parseable work URL."""
    if "://" in raw:
        scheme_candidate = raw.split("://", 1)[0].lower()
        if scheme_candidate not in ALLOWED_SCHEMES:
            raise InvalidURLError(f"Unsupported scheme: '{scheme_candidate}'")
        return scheme_candidate, False, raw

    if ":" in raw:
        prefix = raw.split(":", 1)[0].lower()
        if prefix in BLOCKED_SCHEMES or (prefix not in ALLOWED_SCHEMES and "/" not in prefix and "@" not in prefix and not prefix.isdigit()):
            raise InvalidURLError(f"Unsupported scheme: '{prefix}'")

    return "http", True, f"http://{raw}"


def _check_is_ip(hostname: str) -> bool:
    """Return True if hostname is an IPv4 or IPv6 address."""
    clean_host = hostname[1:-1] if (hostname.startswith("[") and hostname.endswith("]")) else hostname
    try:
        ipaddress.ip_address(clean_host)
        return True
    except ValueError:
        return False


def _extract_domain_parts(hostname: str, is_ip: bool) -> tuple[str, str, str]:
    """Extract subdomain, registered_domain, and suffix from hostname."""
    if is_ip:
        return "", hostname, ""

    ext = _EXTRACTOR(hostname)
    if ext.suffix:
        subdomain = ext.subdomain
        reg_domain = f"{ext.domain}.{ext.suffix}" if ext.domain else ext.suffix
        return subdomain, reg_domain, ext.suffix

    labels = [part for part in hostname.split(".") if part]
    if len(labels) >= 2:
        return ".".join(labels[:-2]), ".".join(labels[-2:]), ""
    return "", hostname, ""


def _build_normalized_url(
    scheme: str, userinfo: str, hostname: str, port: Optional[int], path: str, query: str, fragment: str
) -> str:
    """Construct normalized URL with punycode hostname and canonical parts."""
    try:
        norm_host = hostname.encode("idna").decode("ascii")
    except Exception:
        norm_host = hostname

    userinfo_part = f"{userinfo}@" if userinfo else ""
    is_default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    port_part = f":{port}" if port is not None and not is_default_port else ""
    norm_path = path if path else "/"
    query_part = f"?{query}" if query else ""
    frag_part = f"#{fragment}" if fragment else ""
    return f"{scheme}://{userinfo_part}{norm_host}{port_part}{norm_path}{query_part}{frag_part}"


def parse_url(raw: str, max_len: int = DEFAULT_MAX_URL_LENGTH) -> ParsedURL:
    """Parse raw URL into structured ParsedURL, applying validation and defaults."""
    _validate_raw_input(raw, max_len)
    scheme, scheme_assumed, work_url = _resolve_scheme_and_work_url(raw)
    parsed = urllib.parse.urlsplit(work_url)

    if not parsed.hostname:
        raise InvalidURLError("URL must contain a valid hostname")

    hostname = parsed.hostname.lower()
    is_ip = _check_is_ip(hostname)
    userinfo = parsed.netloc.rsplit("@", 1)[0] if "@" in parsed.netloc else ""
    subdomain, reg_domain, suffix = _extract_domain_parts(hostname, is_ip)
    normalized = _build_normalized_url(
        scheme, userinfo, hostname, parsed.port, parsed.path, parsed.query, parsed.fragment
    )

    return ParsedURL(
        original=raw,
        normalized=normalized,
        scheme=scheme,
        scheme_assumed=scheme_assumed,
        hostname=hostname,
        subdomain=subdomain,
        registered_domain=reg_domain,
        suffix=suffix,
        port=parsed.port,
        userinfo=userinfo,
        path=parsed.path,
        query=parsed.query,
        fragment=parsed.fragment,
        is_ip_host=is_ip,
    )
