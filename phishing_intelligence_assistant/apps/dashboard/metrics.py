"""Aggregated metrics calculation for investigation dashboard (Phase 14)."""
from datetime import timedelta
from typing import Any

from django.db.models import Count
from django.utils import timezone

from apps.analysis.models import (
    FindingRecord,
    Investigation,
    MLPredictionRecord,
    ParsedURLRecord,
    ThreatIntelLookupRecord,
)


def get_total_analyses() -> int:
    """Return total number of URL investigations conducted."""
    return Investigation.objects.count()


def get_risk_distribution(total: int) -> list[dict[str, Any]]:
    """Return counts and percentages for each risk level."""
    counts = dict(
        Investigation.objects.values("overall_level")
        .annotate(cnt=Count("id"))
        .values_list("overall_level", "cnt")
    )
    levels = [
        ("high", "High risk", "badge--high"),
        ("medium", "Medium risk", "badge--medium"),
        ("low_observed", "Low observed risk", "badge--low"),
        ("inconclusive", "Inconclusive", "badge--inconclusive"),
    ]
    result = []
    for key, label, badge in levels:
        cnt = counts.get(key, 0)
        pct = (cnt / total * 100) if total > 0 else 0.0
        result.append(
            {
                "key": key,
                "label": label,
                "badge": badge,
                "count": cnt,
                "percentage": round(pct, 1),
            }
        )
    return result


def get_threat_intel_metrics(total: int) -> dict[str, Any]:
    """Return match counts for PhishTank and URLhaus separately."""
    pt_matches = ThreatIntelLookupRecord.objects.filter(
        source="phishtank", matched=True
    ).count()
    uh_matches = ThreatIntelLookupRecord.objects.filter(
        source="urlhaus", matched=True
    ).count()
    pt_pct = (pt_matches / total * 100) if total > 0 else 0.0
    uh_pct = (uh_matches / total * 100) if total > 0 else 0.0
    return {
        "phishtank": {"count": pt_matches, "percentage": round(pt_pct, 1)},
        "urlhaus": {"count": uh_matches, "percentage": round(uh_pct, 1)},
    }


def get_activity_over_time(days: int = 30) -> list[dict[str, Any]]:
    """Return daily analysis counts for the trailing date window."""
    today = timezone.localdate()
    start_date = today - timedelta(days=days - 1)
    counts = dict(
        Investigation.objects.filter(submitted_at__date__gte=start_date)
        .values("submitted_at__date")
        .annotate(cnt=Count("id"))
        .values_list("submitted_at__date", "cnt")
    )
    result = []
    max_count = max(counts.values(), default=1) or 1
    for i in range(days):
        day = start_date + timedelta(days=i)
        cnt = counts.get(day, 0)
        pct = (cnt / max_count * 100) if max_count > 0 else 0.0
        result.append(
            {
                "date": day.isoformat(),
                "count": cnt,
                "percentage": round(pct, 1),
                "max": max_count,
            }
        )
    return result


def get_top_domains(limit: int = 10) -> list[dict[str, Any]]:
    """Return top analyzed registered domains by investigation count."""
    return list(
        ParsedURLRecord.objects.exclude(registered_domain="")
        .values("registered_domain")
        .annotate(count=Count("id"))
        .order_by("-count")[:limit]
    )


def get_top_tlds(limit: int = 10) -> list[dict[str, Any]]:
    """Return top analyzed top-level domains (suffixes) by investigation count."""
    return list(
        ParsedURLRecord.objects.exclude(suffix="")
        .values("suffix")
        .annotate(count=Count("id"))
        .order_by("-count")[:limit]
    )


def get_check_availability() -> list[dict[str, Any]]:
    """Return finding counts (flagged, clear, unavailable, not_run) per check group."""
    rows = FindingRecord.objects.values("check_name", "status").annotate(
        cnt=Count("id")
    )
    groups: dict[str, dict[str, int]] = {}
    for row in rows:
        grp = (
            row["check_name"].split(".")[0]
            if "." in row["check_name"]
            else row["check_name"]
        )
        status = row["status"]
        if grp not in groups:
            groups[grp] = {
                "flagged": 0,
                "clear": 0,
                "unavailable": 0,
                "not_run": 0,
                "total": 0,
            }
        if status in groups[grp]:
            groups[grp][status] += row["cnt"]
        groups[grp]["total"] += row["cnt"]
    return [{"group": grp, **counts} for grp, counts in sorted(groups.items())]


def get_ml_distribution(total: int) -> list[dict[str, Any]]:
    """Return counts and percentages for ML prediction classifications."""
    counts = dict(
        MLPredictionRecord.objects.values("predicted_class")
        .annotate(cnt=Count("id"))
        .values_list("predicted_class", "cnt")
    )
    phish = counts.get("phishing_like", 0)
    benign = counts.get("benign", 0)
    unavail = max(0, total - (phish + benign)) if total > 0 else 0
    items = [
        ("phishing_like", "Phishing-like", phish),
        ("benign", "Not phishing-like", benign),
        ("unavailable", "Unavailable", unavail),
    ]
    result = []
    for key, label, cnt in items:
        pct = (cnt / total * 100) if total > 0 else 0.0
        result.append(
            {
                "key": key,
                "label": label,
                "count": cnt,
                "percentage": round(pct, 1),
            }
        )
    return result


def get_dashboard_metrics() -> dict[str, Any]:
    """Aggregate all 7 dashboard metrics for display."""
    total = get_total_analyses()
    return {
        "total_analyses": total,
        "risk_distribution": get_risk_distribution(total),
        "threat_intel": get_threat_intel_metrics(total),
        "activity_over_time": get_activity_over_time(30),
        "top_domains": get_top_domains(10),
        "top_tlds": get_top_tlds(10),
        "check_availability": get_check_availability(),
        "ml_distribution": get_ml_distribution(total),
    }
