"""Unit tests for risk engine scoring, bands, overrides, and coverage."""
import unittest

from apps.core.types import Finding
from apps.risk_engine import rules
from apps.risk_engine.engine import assess


class TestRiskEngine(unittest.TestCase):
    """Test suite for risk engine assessment logic and point rules."""

    def test_obfuscation_brand_points_and_cap(self) -> None:
        """Assert obfuscation/brand severity points and 30-point cap."""
        findings = [
            Finding(check_name="brand.similarity", category="heuristic", status="flagged", severity="high", explanation="Brand imitation"),
            Finding(check_name="obfuscation.mixed_script", category="heuristic", status="flagged", severity="medium", explanation="Script"),
            Finding(check_name="obfuscation.dot", category="heuristic", status="flagged", severity="low", explanation="Extra dot"),
            Finding(check_name="lexical.clear_check", category="heuristic", status="clear", severity="info", explanation="Clear check"),
        ]
        # 15 + 8 + 3 = 26 points
        assessment = assess(findings)
        self.assertEqual(dict(assessment.breakdown)[rules.GROUP_OBFUSCATION_BRAND], 26)
        self.assertEqual(assessment.score, 26)

        # Cap test: 3 high findings = 45 -> capped at 30
        cap_findings = [
            Finding(check_name="brand.a", category="heuristic", status="flagged", severity="high", explanation="H1"),
            Finding(check_name="brand.b", category="heuristic", status="flagged", severity="high", explanation="H2"),
            Finding(check_name="obfuscation.c", category="heuristic", status="flagged", severity="high", explanation="H3"),
            Finding(check_name="lexical.d", category="heuristic", status="clear", severity="info", explanation="Clear"),
        ]
        cap_assessment = assess(cap_findings)
        self.assertEqual(dict(cap_assessment.breakdown)[rules.GROUP_OBFUSCATION_BRAND], 30)
        self.assertEqual(cap_assessment.score, 30)

    def test_lexical_points_and_cap(self) -> None:
        """Assert lexical severity points and 20-point cap."""
        findings = [
            Finding(check_name="lexical.keyword", category="heuristic", status="flagged", severity="medium", explanation="Keyword"),
            Finding(check_name="lexical.subdomain", category="heuristic", status="flagged", severity="low", explanation="Subdomain"),
            Finding(check_name="brand.clear", category="heuristic", status="clear", severity="info", explanation="Clear"),
        ]
        # 5 + 2 = 7 points
        assessment = assess(findings)
        self.assertEqual(dict(assessment.breakdown)[rules.GROUP_LEXICAL], 7)
        self.assertEqual(assessment.score, 7)

        # Cap test: 5 medium findings = 25 -> capped at 20
        cap_findings = [
            Finding(check_name=f"lexical.check_{i}", category="heuristic", status="flagged", severity="medium", explanation=f"Med {i}")
            for i in range(5)
        ]
        cap_assessment = assess(cap_findings)
        self.assertEqual(dict(cap_assessment.breakdown)[rules.GROUP_LEXICAL], 20)
        self.assertEqual(cap_assessment.score, 20)

    def test_dns_rdap_redirect_points_and_cap(self) -> None:
        """Assert dns/rdap/redirect severity points and 20-point cap."""
        findings = [
            Finding(check_name="dns.suspicious", category="enrichment", status="flagged", severity="high", explanation="DNS high"),
            Finding(check_name="rdap.young_domain", category="enrichment", status="flagged", severity="medium", explanation="Young domain"),
            Finding(check_name="redirect.hops", category="enrichment", status="flagged", severity="low", explanation="Hops"),
            Finding(check_name="lexical.clear", category="heuristic", status="clear", severity="info", explanation="Clear"),
        ]
        # 10 + 6 + 2 = 18 points
        assessment = assess(findings)
        self.assertEqual(dict(assessment.breakdown)[rules.GROUP_DNS_RDAP_REDIRECT], 18)
        self.assertEqual(assessment.score, 18)

        # Cap test: 3 high findings = 30 -> capped at 20
        cap_findings = [
            Finding(check_name=f"dns.check_{i}", category="enrichment", status="flagged", severity="high", explanation=f"DNS {i}")
            for i in range(3)
        ]
        cap_assessment = assess(cap_findings)
        self.assertEqual(dict(cap_assessment.breakdown)[rules.GROUP_DNS_RDAP_REDIRECT], 20)
        self.assertEqual(cap_assessment.score, 20)

    def test_ml_points_below_at_above_threshold(self) -> None:
        """Assert ML points formula below, at, and above the decision threshold."""
        # Below threshold: 0 points
        f_below = [
            Finding(
                check_name="ml.prediction", category="ml", status="flagged", severity="medium",
                explanation="Below", evidence={"score": 0.40, "threshold": 0.60},
            ),
            Finding(check_name="lexical.clear", category="heuristic", status="clear", severity="info", explanation="Clear"),
        ]
        self.assertEqual(dict(assess(f_below).breakdown)[rules.GROUP_ML], 0)

        # At threshold: 0 points
        f_at = [
            Finding(
                check_name="ml.prediction", category="ml", status="flagged", severity="medium",
                explanation="At", evidence={"score": 0.60, "threshold": 0.60},
            ),
            Finding(check_name="lexical.clear", category="heuristic", status="clear", severity="info", explanation="Clear"),
        ]
        self.assertEqual(dict(assess(f_at).breakdown)[rules.GROUP_ML], 0)

        # Above threshold: score 0.80, threshold 0.60 -> 30 * (0.2 / 0.4) = 15 points
        f_above = [
            Finding(
                check_name="ml.prediction", category="ml", status="flagged", severity="medium",
                explanation="Above", evidence={"score": 0.80, "threshold": 0.60},
            ),
            Finding(check_name="lexical.clear", category="heuristic", status="clear", severity="info", explanation="Clear"),
        ]
        self.assertEqual(dict(assess(f_above).breakdown)[rules.GROUP_ML], 15)

    def test_intel_override_beats_low_points(self) -> None:
        """Assert flagged intel finding forces score to at least 90 and level to High."""
        findings = [
            Finding(check_name="intel.phishtank", category="intel", status="flagged", severity="high", explanation="PhishTank match"),
            Finding(check_name="lexical.a", category="heuristic", status="clear", severity="info", explanation="Clear"),
            Finding(check_name="brand.b", category="heuristic", status="clear", severity="info", explanation="Clear"),
            Finding(check_name="ml.c", category="ml", status="clear", severity="info", explanation="Clear"),
        ]
        assessment = assess(findings)
        self.assertEqual(assessment.level, rules.LEVEL_HIGH)
        self.assertGreaterEqual(assessment.score, 90)
        self.assertIn("High risk", assessment.summary)

    def test_low_coverage_gives_inconclusive_with_score_none(self) -> None:
        """Assert coverage below half of total checks gives Inconclusive and score None."""
        findings = [
            Finding(check_name="lexical.length", category="heuristic", status="flagged", severity="low", explanation="Long URL"),
            Finding(check_name="intel.phishtank", category="intel", status="unavailable", severity="info", explanation="Timeout"),
            Finding(check_name="intel.urlhaus", category="intel", status="unavailable", severity="info", explanation="Error"),
            Finding(check_name="ml.prediction", category="ml", status="unavailable", severity="info", explanation="Missing"),
        ]
        # Completed: 1, Total: 4 -> 1 < 2 -> Inconclusive, score None
        assessment = assess(findings)
        self.assertEqual(assessment.level, rules.LEVEL_INCONCLUSIVE)
        self.assertIsNone(assessment.score)
        self.assertIn("Inconclusive", assessment.summary)
        self.assertEqual(assessment.checks_completed, 1)
        self.assertEqual(assessment.checks_total, 4)

    def test_unavailable_intel_gives_inconclusive(self) -> None:
        """Assert Low observed risk becomes Inconclusive when intel or ML is unavailable."""
        findings = [
            Finding(check_name="lexical.check", category="heuristic", status="clear", severity="info", explanation="No issues"),
            Finding(check_name="brand.check", category="heuristic", status="clear", severity="info", explanation="No issues"),
            Finding(check_name="ml.check", category="ml", status="clear", severity="info", explanation="No issues"),
            Finding(check_name="intel.phishtank", category="intel", status="unavailable", severity="info", explanation="Timeout"),
        ]
        # Total: 4, Completed: 3 (>= 2). Score is 0 (Low band), but intel unavailable -> Inconclusive with score 0
        assessment = assess(findings)
        self.assertEqual(assessment.level, rules.LEVEL_INCONCLUSIVE)
        self.assertEqual(assessment.score, 0)
        self.assertIn("Inconclusive", assessment.summary)

    def test_nothing_flagged_with_full_coverage_gives_low_observed_risk(self) -> None:
        """Assert full coverage with zero flagged findings produces Low observed risk."""
        findings = [
            Finding(check_name="lexical.check", category="heuristic", status="clear", severity="info", explanation="Clear"),
            Finding(check_name="brand.check", category="heuristic", status="clear", severity="info", explanation="Clear"),
            Finding(check_name="ml.check", category="ml", status="clear", severity="info", explanation="Clear"),
            Finding(check_name="intel.phishtank", category="intel", status="clear", severity="info", explanation="Clear"),
        ]
        assessment = assess(findings)
        self.assertEqual(assessment.level, rules.LEVEL_LOW_OBSERVED)
        self.assertEqual(assessment.score, 0)
        self.assertIn("Low observed risk", assessment.summary)

    def test_worked_example(self) -> None:
        """Assert worked example: brand 15 + keyword 5 + ML 0.87@0.62 gives score 40, Medium risk."""
        # ML points: 30 * (0.87 - 0.62) / (1 - 0.62) = 30 * 0.25 / 0.38 = 19.7368...
        # Total = 15 + 5 + 19.7368... = 39.7368... -> rounds to 40
        findings = [
            Finding(check_name="brand.similarity", category="heuristic", status="flagged", severity="high", explanation="Brand lookalike"),
            Finding(check_name="lexical.keyword", category="heuristic", status="flagged", severity="medium", explanation="Keyword found"),
            Finding(
                check_name="ml.prediction", category="ml", status="flagged", severity="medium",
                explanation="ML suspicious", evidence={"score": 0.87, "threshold": 0.62},
            ),
        ]
        assessment = assess(findings)
        self.assertEqual(assessment.score, 40)
        self.assertEqual(assessment.level, rules.LEVEL_MEDIUM)
        self.assertIn("Medium risk", assessment.summary)
        breakdown_dict = dict(assessment.breakdown)
        self.assertEqual(breakdown_dict[rules.GROUP_OBFUSCATION_BRAND], 15)
        self.assertEqual(breakdown_dict[rules.GROUP_LEXICAL], 5)
        self.assertEqual(breakdown_dict[rules.GROUP_ML], 20)

    def test_no_summary_text_contains_safe_or_clean(self) -> None:
        """Assert summary and reasons never contain forbidden words 'safe' or 'clean'."""
        scenarios = [
            # Low observed risk scenario
            [Finding(check_name="lexical.a", category="heuristic", status="clear", severity="info", explanation="No indicators")],
            # High risk scenario
            [Finding(check_name="intel.pt", category="intel", status="flagged", severity="high", explanation="Match")],
            # Inconclusive scenario
            [Finding(check_name="lexical.a", category="heuristic", status="unavailable", severity="info", explanation="Timeout")],
        ]
        for findings in scenarios:
            assessment = assess(findings)
            text = f"{assessment.summary} {' '.join(assessment.reasons)}".lower()
            self.assertNotIn("safe", text)
            self.assertNotIn("clean", text)
            self.assertNotIn("confirmed malicious", text)
