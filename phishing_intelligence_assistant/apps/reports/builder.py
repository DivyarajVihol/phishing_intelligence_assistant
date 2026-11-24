"""Report dictionary builder for HTML and JSON investigation reports (Phase 15)."""
from typing import Any, Optional

from django.utils import timezone

from apps.analysis.models import (
    FindingRecord,
    Investigation,
    MLPredictionRecord,
    ParsedURLRecord,
    ThreatIntelLookupRecord,
)
from apps.core.types import Finding
from apps.risk_engine.engine import assess
from apps.url_analyzer.defang import defang_url

LIMITATION_NOTICE = (
    "These results are indicators for investigation. They do not independently establish that a "
    "website is malicious or safe. A missing threat-feed record does not mean a URL is safe."
)

SUGGESTED_NEXT_STEPS = [
    "Do not open, visit, or enter credentials into the URL on standard user or production devices.",
    "Verify the communication independently through the organisation's official contact channel.",
    "Report the suspicious URL, headers, and context to your internal security or incident response team.",
    "If credentials were submitted, initiate password reset and revoke active user sessions immediately.",
]

LEVEL_MAP = {
    "high": ("High risk", "badge--high"),
    "medium": ("Medium risk", "badge--medium"),
    "low_observed": ("Low observed risk", "badge--low"),
    "inconclusive": ("Inconclusive", "badge--inconclusive"),
}

SOURCE_NAMES = {
    "phishtank": "PhishTank",
    "urlhaus": "URLhaus",
}


def _build_parsed_components(parsed: Optional[ParsedURLRecord]) -> dict[str, Any]:
    """Extract serializable parsed URL components."""
    if not parsed:
        return {}
    return {
        "scheme": parsed.scheme,
        "scheme_assumed": parsed.scheme_assumed,
        "hostname": parsed.hostname,
        "subdomain": parsed.subdomain,
        "registered_domain": parsed.registered_domain,
        "suffix": parsed.suffix,
        "port": parsed.port,
        "path": parsed.path,
        "query": parsed.query,
        "is_ip_host": parsed.is_ip_host,
    }


def _build_assessment(inv: Investigation, findings: list[FindingRecord]) -> dict[str, Any]:
    """Calculate assessment metrics and breakdown for report."""
    finding_objs = [
        Finding(
            check_name=f.check_name, category=f.category, status=f.status,
            severity=f.severity, explanation=f.explanation, evidence=f.evidence,
            source=f.source, checked_at=f.checked_at,
        ) for f in findings
    ]
    assessment = assess(finding_objs)
    label, badge_cls = LEVEL_MAP.get(inv.overall_level, ("Inconclusive", "badge--inconclusive"))
    is_inconc = inv.overall_level == "inconclusive"
    return {
        "level": inv.overall_level,
        "level_label": label,
        "badge_class": badge_cls,
        "score": None if is_inconc else assessment.score,
        "show_score": not is_inconc and assessment.score is not None,
        "summary": assessment.summary,
        "reasons": assessment.reasons,
        "points_breakdown": [{"group": g, "points": pts} for g, pts in assessment.breakdown],
        "coverage": {"completed": assessment.checks_completed, "total": assessment.checks_total},
    }


def _build_threat_intel(lookups: list[ThreatIntelLookupRecord]) -> list[dict[str, Any]]:
    """Format threat intelligence lookup records without secrets or raw detail."""
    results = []
    for lk in lookups:
        results.append({
            "source": lk.source,
            "source_name": SOURCE_NAMES.get(lk.source.lower(), lk.source.title()),
            "status": lk.query_status,
            "matched": lk.matched,
            "source_record_id": lk.source_record_id,
            "queried_at": lk.queried_at.isoformat() if lk.queried_at else None,
        })
    return results


def _build_ml_prediction(ml_rec: Optional[MLPredictionRecord]) -> Optional[dict[str, Any]]:
    """Format ML prediction details if available."""
    if not ml_rec:
        return None
    return {
        "model_name": ml_rec.model_name,
        "model_version": ml_rec.model_version,
        "predicted_class": ml_rec.predicted_class,
        "label": "Phishing-like" if ml_rec.predicted_class == "phishing_like" else "Not phishing-like",
        "score": round(ml_rec.score, 4),
        "threshold": round(ml_rec.threshold, 4),
    }


def _build_findings(
    findings: list[FindingRecord], lookups: list[ThreatIntelLookupRecord]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Group analytical findings into local, enrichment, and unavailable categories."""
    local = [
        {"check_name": f.check_name, "severity": f.severity, "explanation": f.explanation}
        for f in findings if f.category == "heuristic" and f.status != "unavailable"
    ]
    enrichment = [
        {"check_name": f.check_name, "severity": f.severity, "explanation": f.explanation}
        for f in findings if f.category == "enrichment" and f.status != "unavailable"
    ]
    unavailable = [
        {"name": f.check_name, "category": f.category, "explanation": f.explanation}
        for f in findings if f.status == "unavailable"
    ]
    for lk in lookups:
        if lk.query_status == "unavailable":
            unavailable.append({
                "name": lk.source,
                "category": "intel",
                "explanation": lk.error or "Threat intelligence service unavailable",
            })
    return local, enrichment, unavailable


def build_report(investigation: Investigation) -> dict[str, Any]:
    """Build single canonical report dictionary for HTML rendering and JSON export."""
    findings = list(investigation.findings.all())
    lookups = list(investigation.threat_lookups.all())
    parsed = investigation.parsed_urls.first()
    ml_rec = investigation.ml_predictions.first()

    local, enrichment, unavailable = _build_findings(findings, lookups)
    now_iso = timezone.now().isoformat()
    sub_iso = investigation.submitted_at.isoformat() if investigation.submitted_at else None

    return {
        "title": f"Investigation Report #{investigation.id}",
        "report_id": investigation.id,
        "generated_at": now_iso,
        "submitted_at": sub_iso,
        "submitted_url_defanged": defang_url(investigation.submitted_url),
        "submitted_url_raw": investigation.submitted_url,
        "parsed_components": _build_parsed_components(parsed),
        "assessment": _build_assessment(investigation, findings),
        "local_findings": local,
        "enrichment_findings": enrichment,
        "threat_intel": _build_threat_intel(lookups),
        "ml_prediction": _build_ml_prediction(ml_rec),
        "unavailable_checks": unavailable,
        "limitations": LIMITATION_NOTICE,
        "suggested_next_steps": SUGGESTED_NEXT_STEPS,
    }
