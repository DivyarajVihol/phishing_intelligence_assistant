"""PhishTank threat intelligence connector (plain Python)."""
from datetime import datetime, timezone
from typing import Any
import requests

from apps.core.types import ParsedURL, ThreatLookup

PHISHTANK_URL = "https://checkurl.phishtank.com/checkurl/"


def _get_setting(settings: Any, key: str, default: Any = None) -> Any:
    """Retrieve setting value supporting dict and object attribute access."""
    if isinstance(settings, dict):
        return settings.get(key, default)
    return getattr(settings, key, default)


def _handle_response(resp: requests.Response, now: datetime) -> ThreatLookup:
    """Parse HTTP response and extract PhishTank ThreatLookup status."""
    if resp.status_code in (429, 509):
        return ThreatLookup(
            source="phishtank", status="unavailable", queried_at=now, error=f"Rate limited (HTTP {resp.status_code})"
        )
    if resp.status_code != 200:
        return ThreatLookup(
            source="phishtank", status="unavailable", queried_at=now, error=f"HTTP {resp.status_code} error"
        )

    try:
        data = resp.json()
    except Exception:
        return ThreatLookup(source="phishtank", status="unavailable", queried_at=now, error="Invalid JSON response")

    results = data.get("results") if isinstance(data, dict) else None
    if not isinstance(results, dict):
        return ThreatLookup(source="phishtank", status="unavailable", queried_at=now, error="Malformed response data")

    in_database = bool(results.get("in_database", False))
    verified = bool(results.get("verified", False))
    valid = bool(results.get("valid", False))
    record_id = str(results.get("phish_id")) if results.get("phish_id") is not None else None

    if in_database and verified and valid:
        return ThreatLookup(source="phishtank", status="match", record_id=record_id, detail=results, queried_at=now)
    return ThreatLookup(source="phishtank", status="no_match", record_id=record_id, detail=results, queried_at=now)


def lookup(parsed: ParsedURL, settings: Any) -> ThreatLookup:
    """Query PhishTank API for URL status; never raises."""
    now = datetime.now(timezone.utc)
    if not _get_setting(settings, "ENABLE_PHISHTANK", True):
        return ThreatLookup(source="phishtank", status="not_configured", queried_at=now)

    timeout = int(_get_setting(settings, "EXTERNAL_TIMEOUT_SECONDS", 5))
    user_agent = str(_get_setting(settings, "PHISHTANK_USER_AGENT", "phishtank/assistant"))
    app_key = str(_get_setting(settings, "PHISHTANK_APP_KEY", "") or "").strip()

    payload = {"url": parsed.normalized, "format": "json"}
    if app_key:
        payload["app_key"] = app_key

    try:
        resp = requests.post(
            PHISHTANK_URL,
            data=payload,
            headers={"User-Agent": user_agent},
            timeout=timeout,
            allow_redirects=False,
        )
    except requests.exceptions.Timeout:
        return ThreatLookup(source="phishtank", status="unavailable", queried_at=now, error="Request timed out")
    except requests.exceptions.RequestException:
        return ThreatLookup(source="phishtank", status="unavailable", queried_at=now, error="Network or request failure")
    except Exception:
        return ThreatLookup(source="phishtank", status="unavailable", queried_at=now, error="Unexpected error")

    return _handle_response(resp, now)
