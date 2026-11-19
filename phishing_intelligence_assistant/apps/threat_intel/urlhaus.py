"""URLhaus threat intelligence connector (plain Python)."""
from datetime import datetime, timezone
from typing import Any
import requests

from apps.core.types import ParsedURL, ThreatLookup

URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/url/"


def _get_setting(settings: Any, key: str, default: Any = None) -> Any:
    """Retrieve setting value supporting dict and object attribute access."""
    if isinstance(settings, dict):
        return settings.get(key, default)
    return getattr(settings, key, default)


def lookup(parsed: ParsedURL, settings: Any) -> ThreatLookup:
    """Query URLhaus API for URL status; never raises."""
    now = datetime.now(timezone.utc)
    if not _get_setting(settings, "ENABLE_URLHAUS", True):
        return ThreatLookup(source="urlhaus", status="not_configured", queried_at=now)

    auth_key = str(_get_setting(settings, "URLHAUS_AUTH_KEY", "") or "").strip()
    if not auth_key:
        return ThreatLookup(source="urlhaus", status="not_configured", queried_at=now)

    timeout = int(_get_setting(settings, "EXTERNAL_TIMEOUT_SECONDS", 5))
    try:
        resp = requests.post(
            URLHAUS_URL,
            data={"url": parsed.normalized},
            headers={"Auth-Key": auth_key},
            timeout=timeout,
            allow_redirects=False,
        )
    except requests.exceptions.Timeout:
        return ThreatLookup(source="urlhaus", status="unavailable", queried_at=now, error="Request timed out")
    except requests.exceptions.RequestException:
        return ThreatLookup(source="urlhaus", status="unavailable", queried_at=now, error="Network or request failure")
    except Exception:
        return ThreatLookup(source="urlhaus", status="unavailable", queried_at=now, error="Unexpected error")

    if resp.status_code in (429, 509):
        return ThreatLookup(
            source="urlhaus", status="unavailable", queried_at=now, error=f"Rate limited (HTTP {resp.status_code})"
        )
    if resp.status_code in (401, 403):
        return ThreatLookup(
            source="urlhaus", status="unavailable", queried_at=now, error="Invalid or unauthorized API key"
        )
    if resp.status_code != 200:
        return ThreatLookup(
            source="urlhaus", status="unavailable", queried_at=now, error=f"HTTP {resp.status_code} error"
        )

    try:
        data = resp.json()
    except Exception:
        return ThreatLookup(source="urlhaus", status="unavailable", queried_at=now, error="Invalid JSON response")

    query_status = data.get("query_status") if isinstance(data, dict) else None
    if query_status == "ok":
        record_id = str(data.get("id")) if data.get("id") is not None else None
        return ThreatLookup(source="urlhaus", status="match", record_id=record_id, detail=data, queried_at=now)
    if query_status == "no_results":
        return ThreatLookup(source="urlhaus", status="no_match", detail=data, queried_at=now)
    if query_status == "invalid_key":
        return ThreatLookup(source="urlhaus", status="unavailable", queried_at=now, error="Invalid API key")
    return ThreatLookup(
        source="urlhaus", status="unavailable", queried_at=now, error=f"Query status: {query_status}"
    )
