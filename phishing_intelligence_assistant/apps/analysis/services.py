"""Analysis service orchestrator and persistence (Phase 9)."""
import logging
from typing import Optional

from django.conf import settings
from django.db import transaction

from apps.analysis.models import (
    FindingRecord,
    Investigation,
    MLPredictionRecord,
    ParsedURLRecord,
    ThreatIntelLookupRecord,
)
from apps.core.types import Assessment, Finding, ParsedURL, Prediction, ThreatLookup
from apps.ml_engine.predict import predict
from apps.risk_engine.engine import assess
from apps.threat_intel import service as threat_intel_service
from apps.url_analyzer.brand import check_brand_similarity
from apps.url_analyzer.domain_checks import check_dns, check_rdap
from apps.url_analyzer.lexical import check_lexical
from apps.url_analyzer.obfuscation import check_obfuscation
from apps.url_analyzer.parser import parse_url

logger = logging.getLogger(__name__)


def _run_lexical(parsed: ParsedURL) -> list[Finding]:
    """Execute lexical heuristic checks, catching exceptions as unavailable findings."""
    try:
        return check_lexical(parsed)
    except Exception as exc:
        logger.warning("Lexical checks failed: %s", exc)
        return [Finding(
            check_name="lexical.error",
            category="heuristic",
            status="unavailable",
            severity="info",
            explanation="Lexical heuristic checks were unavailable.",
            evidence={"error": "Module execution failed"},
            source="lexical",
        )]


def _run_obfuscation(parsed: ParsedURL) -> list[Finding]:
    """Execute obfuscation checks, catching exceptions as unavailable findings."""
    try:
        return check_obfuscation(parsed)
    except Exception as exc:
        logger.warning("Obfuscation checks failed: %s", exc)
        return [Finding(
            check_name="obfuscation.error",
            category="heuristic",
            status="unavailable",
            severity="info",
            explanation="Obfuscation checks were unavailable.",
            evidence={"error": "Module execution failed"},
            source="obfuscation",
        )]


def _run_brand(parsed: ParsedURL) -> list[Finding]:
    """Execute brand similarity checks, catching exceptions as unavailable findings."""
    try:
        return check_brand_similarity(parsed)
    except Exception as exc:
        logger.warning("Brand similarity checks failed: %s", exc)
        return [Finding(
            check_name="brand.error", category="heuristic", status="unavailable", severity="info",
            explanation="Brand similarity checks were unavailable.",
            evidence={"error": "Module execution failed"}, source="brand",
        )]


def _run_dns_rdap(parsed: ParsedURL) -> list[Finding]:
    """Execute DNS and RDAP enrichment checks only when ENABLE_DNS_RDAP is True."""
    if not getattr(settings, "ENABLE_DNS_RDAP", False):
        return []
    timeout = float(getattr(settings, "EXTERNAL_TIMEOUT_SECONDS", 5))
    findings: list[Finding] = []
    for fn, chk, src in ((check_dns, "dns.records", "dns"), (check_rdap, "rdap.domain_age", "rdap")):
        try:
            findings.extend(fn(parsed, timeout=timeout))
        except Exception as exc:
            logger.warning("%s check failed: %s", src.upper(), exc)
            findings.append(Finding(
                check_name=chk, category="enrichment", status="unavailable", severity="info",
                explanation=f"{src.upper()} check was unavailable.", source=src,
            ))
    return findings


def _run_ml(parsed: ParsedURL) -> tuple[Optional[Prediction], list[Finding]]:
    """Execute ML prediction, converting result or failure to Finding."""
    try:
        pred = predict(parsed)
        finding = Finding(
            check_name="ml.prediction",
            category="ml",
            status="flagged" if pred.label == "phishing_like" else "clear",
            severity="medium" if pred.label == "phishing_like" else "info",
            explanation=(
                f"ML model scored URL as phishing-like (score {pred.score:.4f} >= {pred.threshold:.4f})."
                if pred.label == "phishing_like"
                else f"ML model scored URL as benign (score {pred.score:.4f} < {pred.threshold:.4f})."
            ),
            evidence={
                "score": pred.score,
                "threshold": pred.threshold,
                "model_name": pred.model_name,
                "model_version": pred.model_version,
                "label": pred.label,
            },
            source=pred.model_name,
        )
        return pred, [finding]
    except Exception as exc:
        logger.warning("ML prediction failed: %s", exc)
        return None, [Finding(
            check_name="ml.prediction",
            category="ml",
            status="unavailable",
            severity="info",
            explanation="ML model prediction was unavailable.",
            evidence={"error": "Model prediction unavailable"},
            source="ml_engine",
        )]


def _run_threat_intel(parsed: ParsedURL) -> tuple[list[ThreatLookup], list[Finding]]:
    """Execute threat intelligence queries and return lookups and findings."""
    try:
        lookups = threat_intel_service.query_sources(parsed, settings)
        findings = threat_intel_service.to_findings(lookups)
        return lookups, findings
    except Exception as exc:
        logger.warning("Threat intelligence lookup failed: %s", exc)
        return [], [Finding(
            check_name="intel.service",
            category="intel",
            status="unavailable",
            severity="info",
            explanation="Threat intelligence lookups were unavailable.",
            evidence={"error": "Threat intelligence service unavailable"},
            source="threat_intel",
        )]


def _save_investigation(
    raw: str,
    parsed: ParsedURL,
    findings: list[Finding],
    lookups: list[ThreatLookup],
    ml_pred: Optional[Prediction],
    assessment: Assessment,
) -> Investigation:
    """Persist investigation and its related analytical records."""
    with transaction.atomic():
        investigation = Investigation.objects.create(
            submitted_url=raw,
            status="completed",
            overall_level=assessment.level,
            score=assessment.score,
            summary=assessment.summary,
            model_version=ml_pred.model_version if ml_pred else "",
        )
        ParsedURLRecord.objects.create(
            investigation=investigation,
            original=parsed.original,
            normalized=parsed.normalized,
            scheme=parsed.scheme,
            scheme_assumed=parsed.scheme_assumed,
            hostname=parsed.hostname,
            subdomain=parsed.subdomain,
            registered_domain=parsed.registered_domain,
            suffix=parsed.suffix,
            port=parsed.port,
            userinfo=parsed.userinfo,
            path=parsed.path,
            query=parsed.query,
            fragment=parsed.fragment,
            is_ip_host=parsed.is_ip_host,
        )
        FindingRecord.objects.bulk_create([
            FindingRecord(
                investigation=investigation,
                check_name=f.check_name,
                category=f.category,
                status=f.status,
                severity=f.severity,
                explanation=f.explanation,
                evidence=f.evidence,
                source=f.source,
                checked_at=f.checked_at,
            ) for f in findings
        ])
        ThreatIntelLookupRecord.objects.bulk_create([
            ThreatIntelLookupRecord(
                investigation=investigation,
                source=lk.source,
                queried_at=lk.queried_at,
                query_status=lk.status,
                matched=(lk.status == "match"),
                source_record_id=lk.record_id,
                response_summary=lk.detail,
                error=lk.error,
            ) for lk in lookups
        ])
        if ml_pred is not None:
            MLPredictionRecord.objects.create(
                investigation=investigation,
                model_name=ml_pred.model_name,
                model_version=ml_pred.model_version,
                predicted_class=ml_pred.label,
                score=ml_pred.score,
                threshold=ml_pred.threshold,
            )
        return investigation


def analyse_url(raw: str) -> Investigation:
    """Analyze a suspicious URL end-to-end and persist investigation records."""
    max_len = int(getattr(settings, "MAX_URL_LENGTH", 2048))
    parsed = parse_url(raw, max_len=max_len)

    lexical_findings = _run_lexical(parsed)
    obfuscation_findings = _run_obfuscation(parsed)
    brand_findings = _run_brand(parsed)
    ml_pred, ml_findings = _run_ml(parsed)
    lookups, intel_findings = _run_threat_intel(parsed)
    enrichment_findings = _run_dns_rdap(parsed)

    all_findings = lexical_findings + obfuscation_findings + brand_findings + ml_findings + intel_findings + enrichment_findings
    assessment = assess(all_findings)

    return _save_investigation(
        raw=raw,
        parsed=parsed,
        findings=all_findings,
        lookups=lookups,
        ml_pred=ml_pred,
        assessment=assessment,
    )


def get_investigation_context(investigation: Investigation) -> dict:
    """Prepare structured template context for investigation result page."""
    finding_records = list(investigation.findings.all())
    lookups = list(investigation.threat_lookups.all())
    finding_objs = [
        Finding(
            check_name=f.check_name, category=f.category, status=f.status,
            severity=f.severity, explanation=f.explanation, evidence=f.evidence,
            source=f.source, checked_at=f.checked_at,
        ) for f in finding_records
    ]
    assessment = assess(finding_objs)
    level_map = {
        "high": ("High risk", "badge--high"),
        "medium": ("Medium risk", "badge--medium"),
        "low_observed": ("Low observed risk", "badge--low"),
        "inconclusive": ("Inconclusive", "badge--inconclusive"),
    }
    label, badge_cls = level_map.get(
        investigation.overall_level, ("Inconclusive", "badge--inconclusive")
    )
    return {
        "investigation": investigation,
        "parsed": investigation.parsed_urls.first(),
        "ml_pred": investigation.ml_predictions.first(),
        "level_label": label,
        "badge_class": badge_cls,
        "assessment": assessment,
        "show_score": (investigation.overall_level != "inconclusive" and assessment.score is not None),
        "threat_lookups": lookups,
        "local_findings": [f for f in finding_records if f.category == "heuristic" and f.status != "unavailable"],
        "enrichment_findings": [f for f in finding_records if f.category == "enrichment" and f.status != "unavailable"],
        "unavailable_findings": [f for f in finding_records if f.status == "unavailable"],
        "unavailable_lookups": [l for l in lookups if l.query_status == "unavailable"],
    }
