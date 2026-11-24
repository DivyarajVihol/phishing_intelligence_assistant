"""History query building and filtering logic (Phase 11)."""
from datetime import date
from typing import Any, Optional

from django.db.models import Q, QuerySet

from apps.analysis.models import Investigation


def filter_by_search(
    qs: QuerySet[Investigation], query: str
) -> QuerySet[Investigation]:
    """Filter investigations by submitted URL, hostname, or registered domain."""
    if not query:
        return qs
    q = query.strip()
    return qs.filter(
        Q(submitted_url__icontains=q)
        | Q(parsed_urls__hostname__icontains=q)
        | Q(parsed_urls__registered_domain__icontains=q)
    ).distinct()


def filter_by_date_range(
    qs: QuerySet[Investigation],
    date_from: Optional[date] = None,
    date_to: Optional[date] = None,
) -> QuerySet[Investigation]:
    """Filter investigations by submitted_at date range (inclusive)."""
    if date_from:
        qs = qs.filter(submitted_at__date__gte=date_from)
    if date_to:
        qs = qs.filter(submitted_at__date__lte=date_to)
    return qs


def filter_by_risk_level(
    qs: QuerySet[Investigation], level: str
) -> QuerySet[Investigation]:
    """Filter investigations by overall risk level."""
    if not level:
        return qs
    return qs.filter(overall_level=level)


def filter_by_intel(
    qs: QuerySet[Investigation], source: str, match_value: str
) -> QuerySet[Investigation]:
    """Filter investigations by threat intelligence source match status."""
    if not match_value:
        return qs
    val = str(match_value).lower().strip()
    if val in ("match", "yes", "1", "true"):
        return qs.filter(
            threat_lookups__source=source, threat_lookups__matched=True
        ).distinct()
    if val in ("no_match", "no", "0", "false"):
        return qs.exclude(
            threat_lookups__source=source, threat_lookups__matched=True
        ).distinct()
    return qs


def filter_by_phishtank(
    qs: QuerySet[Investigation], match_value: str
) -> QuerySet[Investigation]:
    """Filter investigations by PhishTank match status."""
    return filter_by_intel(qs, "phishtank", match_value)


def filter_by_urlhaus(
    qs: QuerySet[Investigation], match_value: str
) -> QuerySet[Investigation]:
    """Filter investigations by URLhaus match status."""
    return filter_by_intel(qs, "urlhaus", match_value)


def filter_by_status(
    qs: QuerySet[Investigation], status: str
) -> QuerySet[Investigation]:
    """Filter investigations by analysis status."""
    if not status:
        return qs
    return qs.filter(status=status)


def filter_by_ml_result(
    qs: QuerySet[Investigation], ml_result: str
) -> QuerySet[Investigation]:
    """Filter investigations by ML model classification result."""
    if not ml_result:
        return qs
    return qs.filter(ml_predictions__predicted_class=ml_result).distinct()


def apply_history_filters(
    qs: QuerySet[Investigation], filters: dict[str, Any]
) -> QuerySet[Investigation]:
    """Apply all active filters to the investigation queryset."""
    qs = filter_by_search(qs, filters.get("q") or "")
    qs = filter_by_date_range(qs, filters.get("date_from"), filters.get("date_to"))
    qs = filter_by_risk_level(qs, filters.get("risk_level") or "")
    qs = filter_by_phishtank(qs, filters.get("phishtank") or "")
    qs = filter_by_urlhaus(qs, filters.get("urlhaus") or "")
    qs = filter_by_status(qs, filters.get("status") or "")
    qs = filter_by_ml_result(qs, filters.get("ml_result") or "")
    return qs


def get_history_queryset(
    filters: Optional[dict[str, Any]] = None,
) -> QuerySet[Investigation]:
    """Build base investigation queryset ordered newest first with applied filters."""
    qs = Investigation.objects.all().order_by("-submitted_at", "-id")
    if filters:
        qs = apply_history_filters(qs, filters)
    return qs
