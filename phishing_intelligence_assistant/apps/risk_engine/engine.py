"""Risk engine assessment and scoring implementation (plain Python)."""
from typing import Optional

from apps.core.types import Assessment, Finding
from apps.risk_engine import rules


def _resolve_group(finding: Finding) -> str:
    """Map finding to its risk assessment group based on check_name and category."""
    name = finding.check_name.lower()
    cat = (finding.category or "").lower()
    if name.startswith("obfuscation.") or name.startswith("brand.") or name in ("obfuscation", "brand"):
        return rules.GROUP_OBFUSCATION_BRAND
    if name.startswith("lexical.") or name in ("lexical", "keyword") or "keyword" in name:
        return rules.GROUP_LEXICAL
    if name.startswith("ml.") or name == "ml" or cat == "ml":
        return rules.GROUP_ML
    if name.startswith("dns.") or name.startswith("rdap.") or name.startswith("redirect.") or name in (
        "dns", "rdap", "redirect"
    ):
        return rules.GROUP_DNS_RDAP_REDIRECT
    if name.startswith("intel.") or name == "intel" or cat == "intel":
        return rules.GROUP_INTEL
    if cat in ("obfuscation", "brand"):
        return rules.GROUP_OBFUSCATION_BRAND
    if cat == "lexical":
        return rules.GROUP_LEXICAL
    if cat in ("dns", "rdap", "redirect"):
        return rules.GROUP_DNS_RDAP_REDIRECT
    return name.split(".")[0]


def _calculate_ml_points(finding: Finding) -> float:
    """Calculate scaled points for ML prediction finding."""
    score = float(finding.evidence.get("score", rules.ML_BELOW_THRESHOLD_POINTS))
    threshold = float(finding.evidence.get("threshold", rules.MIN_COVERAGE_RATIO))
    if score < threshold or threshold >= 1.0:
        return rules.ML_BELOW_THRESHOLD_POINTS
    points = rules.ML_CAP * (score - threshold) / (1.0 - threshold)
    return min(points, rules.ML_CAP)


def _calculate_finding_points(finding: Finding, group: str) -> float:
    """Determine points contributed by a flagged finding for its group."""
    if finding.status != "flagged" or finding.severity == "info":
        return float(rules.MIN_SCORE)

    if group == rules.GROUP_OBFUSCATION_BRAND:
        if finding.severity == "high":
            return float(rules.OBFUSCATION_BRAND_HIGH_POINTS)
        if finding.severity == "medium":
            return float(rules.OBFUSCATION_BRAND_MEDIUM_POINTS)
        return float(rules.OBFUSCATION_BRAND_LOW_POINTS)

    if group == rules.GROUP_LEXICAL:
        if finding.severity in ("high", "medium"):
            return float(rules.LEXICAL_MEDIUM_POINTS)
        return float(rules.LEXICAL_LOW_POINTS)

    if group == rules.GROUP_DNS_RDAP_REDIRECT:
        if finding.severity == "high":
            return float(rules.DNS_RDAP_REDIRECT_HIGH_POINTS)
        if finding.severity == "medium":
            return float(rules.DNS_RDAP_REDIRECT_MEDIUM_POINTS)
        return float(rules.DNS_RDAP_REDIRECT_LOW_POINTS)

    if group == rules.GROUP_ML:
        return _calculate_ml_points(finding)

    return float(rules.MIN_SCORE)


def _determine_level_and_score(
    findings: list[Finding],
    raw_score: float,
    has_flagged_intel: bool,
    checks_completed: int,
    checks_total: int,
) -> tuple[str, Optional[int]]:
    """Determine assessment level and final score following the 4-step hierarchy."""
    base_score = min(round(raw_score), rules.MAX_SCORE)

    if has_flagged_intel:
        return rules.LEVEL_HIGH, max(base_score, rules.INTEL_OVERRIDE_MIN_SCORE)

    if checks_total == 0 or checks_completed < (checks_total * rules.MIN_COVERAGE_RATIO):
        return rules.LEVEL_INCONCLUSIVE, None

    if base_score >= rules.BAND_HIGH_MIN:
        level = rules.LEVEL_HIGH
    elif base_score >= rules.BAND_MEDIUM_MIN:
        level = rules.LEVEL_MEDIUM
    else:
        level = rules.LEVEL_LOW_OBSERVED

    if level == rules.LEVEL_LOW_OBSERVED:
        has_unavail_intel_or_ml = any(
            f.status == "unavailable" and _resolve_group(f) in (rules.GROUP_INTEL, rules.GROUP_ML)
            for f in findings
        )
        if has_unavail_intel_or_ml:
            return rules.LEVEL_INCONCLUSIVE, base_score

    return level, base_score


def _build_summary_and_reasons(
    level: str,
    score: Optional[int],
    findings: list[Finding],
    checks_completed: int,
    checks_total: int,
) -> tuple[str, list[str]]:
    """Generate concise human-readable summary and reasons without banned words."""
    reasons: list[str] = [f.explanation for f in findings if f.status == "flagged" and f.explanation]
    has_flagged = any(f.status == "flagged" for f in findings)

    if level == rules.LEVEL_HIGH:
        summary = f"{rules.WORDING_HIGH_RISK}: Suspicious indicators identified (score {score}/100)."
    elif level == rules.LEVEL_MEDIUM:
        summary = f"{rules.WORDING_MEDIUM_RISK}: Suspicious indicators identified (score {score}/100)."
    elif level == rules.LEVEL_LOW_OBSERVED:
        if has_flagged:
            summary = (
                f"{rules.WORDING_LOW_OBSERVED_RISK}: some indicators were noted, "
                f"but the combined score is low (score {score}/100)."
            )
        else:
            summary = (
                f"{rules.WORDING_LOW_OBSERVED_RISK}: No suspicious indicators identified "
                f"in completed checks (score {score}/100)."
            )
            reasons.append("No suspicious indicators identified across completed checks.")
    elif score is None:
        summary = f"{rules.WORDING_INCONCLUSIVE}: Insufficient check coverage ({checks_completed} of {checks_total} completed)."
        reasons.append(f"Check coverage is below half of total checks ({checks_completed}/{checks_total}).")
    else:
        summary = f"{rules.WORDING_INCONCLUSIVE}: Intelligence or ML checks unavailable (score {score}/100)."
        reasons.extend(
            f"{f.check_name} check unavailable: {f.explanation or 'Service did not respond'}"
            for f in findings
            if f.status == "unavailable" and _resolve_group(f) in (rules.GROUP_INTEL, rules.GROUP_ML)
        )

    return summary, reasons


def assess(findings: list[Finding]) -> Assessment:
    """Assess analytical findings and compute risk score, coverage, breakdown, and level."""
    group_points: dict[str, float] = {
        rules.GROUP_OBFUSCATION_BRAND: float(rules.MIN_SCORE),
        rules.GROUP_LEXICAL: float(rules.MIN_SCORE),
        rules.GROUP_ML: float(rules.MIN_SCORE),
        rules.GROUP_DNS_RDAP_REDIRECT: float(rules.MIN_SCORE),
    }

    has_flagged_intel = False
    for f in findings:
        group = _resolve_group(f)
        if group == rules.GROUP_INTEL and f.status == "flagged":
            has_flagged_intel = True
        elif group in group_points:
            group_points[group] += _calculate_finding_points(f, group)

    capped_obf_brand = min(group_points[rules.GROUP_OBFUSCATION_BRAND], float(rules.OBFUSCATION_BRAND_CAP))
    capped_lexical = min(group_points[rules.GROUP_LEXICAL], float(rules.LEXICAL_CAP))
    capped_ml = min(group_points[rules.GROUP_ML], float(rules.ML_CAP))
    capped_dns = min(group_points[rules.GROUP_DNS_RDAP_REDIRECT], float(rules.DNS_RDAP_REDIRECT_CAP))

    raw_score = capped_obf_brand + capped_lexical + capped_ml + capped_dns
    checks_total = len([f for f in findings if f.status != "not_run"])
    checks_completed = len([f for f in findings if f.status in ("flagged", "clear")])

    level, score = _determine_level_and_score(
        findings, raw_score, has_flagged_intel, checks_completed, checks_total
    )

    breakdown = [
        (rules.GROUP_OBFUSCATION_BRAND, int(round(capped_obf_brand))),
        (rules.GROUP_LEXICAL, int(round(capped_lexical))),
        (rules.GROUP_ML, int(round(capped_ml))),
        (rules.GROUP_DNS_RDAP_REDIRECT, int(round(capped_dns))),
    ]

    summary, reasons = _build_summary_and_reasons(
        level, score, findings, checks_completed, checks_total
    )

    return Assessment(
        level=level,
        score=score,
        checks_completed=checks_completed,
        checks_total=checks_total,
        breakdown=breakdown,
        summary=summary,
        reasons=reasons,
    )
