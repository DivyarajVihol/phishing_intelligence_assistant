"""DNS and RDAP domain enrichment checks (plain Python, no Django)."""
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Optional

import dns.exception
import dns.resolver
import requests

from apps.core.types import Finding, ParsedURL

logger = logging.getLogger(__name__)

_VALID_DOMAIN_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)
_MAX_DOMAIN_LEN = 253
_MAX_RDAP_REDIRECTS = 3
_MAX_RDAP_BYTES = 1024 * 1024
_DNS_NO_RECORD_ERRORS = (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers)


def _is_valid_domain(parsed: ParsedURL) -> bool:
    """Return True if parsed registered domain is a valid non-IP domain name."""
    dom = parsed.registered_domain.lower()
    return not parsed.is_ip_host and len(dom) <= _MAX_DOMAIN_LEN and bool(_VALID_DOMAIN_RE.match(dom))


def _unavailable(check_name: str, source: str, explanation: str) -> list[Finding]:
    """Build an unavailable enrichment Finding."""
    return [Finding(
        check_name=check_name, category="enrichment", status="unavailable",
        severity="info", explanation=explanation, source=source,
    )]


def check_dns(parsed: ParsedURL, timeout: float = 5.0) -> list[Finding]:
    """Query A, AAAA, MX, and NS DNS records for the validated registered domain."""
    if not _is_valid_domain(parsed):
        return _unavailable("dns.records", "dns", "DNS check unavailable: invalid or IP registered domain.")
    domain = parsed.registered_domain.lower()
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout
        counts: dict[str, int] = {}
        for rtype in ("A", "AAAA", "MX", "NS"):
            try:
                counts[rtype] = len(resolver.resolve(domain, rtype))
            except _DNS_NO_RECORD_ERRORS:
                counts[rtype] = 0
        has_addr = (counts["A"] + counts["AAAA"]) > 0
        if not has_addr:
            return [Finding(
                check_name="dns.records", category="enrichment", status="flagged", severity="low",
                explanation=f"Domain '{domain}' has no A or AAAA DNS records. This is a warning, not proof.",
                evidence=counts, source="dns",
            )]
        msg = "DNS records resolved." if counts["MX"] > 0 else "DNS A/AAAA records resolved (no MX record; informational only)."
        return [Finding(
            check_name="dns.records", category="enrichment", status="clear",
            severity="info", explanation=msg, evidence=counts, source="dns",
        )]
    except Exception as exc:
        logger.warning("DNS lookup failed for %s: %s", domain, exc)
        return _unavailable("dns.records", "dns", "DNS lookup was unavailable.")


def _fetch_rdap_json(domain: str, timeout: float) -> dict[str, Any]:
    """Fetch RDAP JSON from rdap.org following at most 3 HTTPS-only redirects under 1 MB."""
    url = f"https://rdap.org/domain/{domain}"
    for _ in range(_MAX_RDAP_REDIRECTS + 1):
        if not url.startswith("https://"):
            raise ValueError("Refused non-HTTPS RDAP redirect")
        resp = requests.get(url, timeout=timeout, stream=True, allow_redirects=False)
        if 300 <= resp.status_code < 400 and "location" in resp.headers:
            url = resp.headers["location"]
            resp.close()
            continue
        resp.raise_for_status()
        chunks: list[bytes] = []
        total = 0
        for chunk in resp.iter_content(chunk_size=16384):
            total += len(chunk)
            if total > _MAX_RDAP_BYTES:
                resp.close()
                raise ValueError("RDAP response exceeded 1 MB limit")
            chunks.append(chunk)
        return json.loads(b"".join(chunks).decode("utf-8"))
    raise ValueError("Exceeded maximum RDAP redirects")


def _extract_registration_date(data: dict[str, Any]) -> Optional[datetime]:
    """Extract registration event datetime from RDAP JSON payload."""
    for ev in data.get("events", []):
        if str(ev.get("eventAction", "")).lower() in ("registration", "registered"):
            raw_date = str(ev.get("eventDate", "")).strip()
            if raw_date:
                return datetime.fromisoformat(raw_date.replace("Z", "+00:00"))
    return None


def check_rdap(parsed: ParsedURL, timeout: float = 5.0) -> list[Finding]:
    """Query rdap.org for domain registration age on the validated registered domain."""
    if not _is_valid_domain(parsed):
        return _unavailable("rdap.domain_age", "rdap", "RDAP check unavailable: invalid or IP registered domain.")
    domain = parsed.registered_domain.lower()
    try:
        data = _fetch_rdap_json(domain, timeout)
        created = _extract_registration_date(data)
        if created is None:
            return _unavailable("rdap.domain_age", "rdap", "RDAP registration date was missing or hidden.")
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        age_days = max(0, (datetime.now(timezone.utc) - created).days)
        if age_days < 7:
            sev = "high"
        elif age_days < 30:
            sev = "medium"
        elif age_days < 90:
            sev = "low"
        else:
            return [Finding(
                check_name="rdap.domain_age", category="enrichment", status="clear", severity="info",
                explanation=f"Domain age is {age_days} days.", evidence={"age_days": age_days}, source="rdap",
            )]
        return [Finding(
            check_name="rdap.domain_age", category="enrichment", status="flagged", severity=sev,
            explanation=f"Domain was registered {age_days} days ago. Newly registered domains can be risky, though this is a warning, not proof.",
            evidence={"age_days": age_days}, source="rdap",
        )]
    except Exception as exc:
        logger.warning("RDAP lookup failed for %s: %s", domain, exc)
        return _unavailable("rdap.domain_age", "rdap", "RDAP domain age lookup was unavailable.")
