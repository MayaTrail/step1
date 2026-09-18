"""
Tests for the workflow evidence packet.

The assertions worth having here are about what the report refuses to claim.
Coverage that reads as a bare percentage, a zero standing in for "never
measured", or an unwatched technique quietly excluded from the denominator are
all ways a report can mislead a reader who is about to show it to an auditor.
"""

from django.test import SimpleTestCase

from apps.workflows.reporting import (
    _rule_rows,
    _uncovered,
    coverage_sentence,
)


def _score(rules, **overrides):
    """
    Build a score payload shaped like the one scoring.build_score stores.

    Args:
        rules: The per-rule verdict dicts.
        **overrides: Any top-level field to replace.

    Returns:
        A score dict.
    """
    counts = {"fired": 0, "silent": 0, "not_integrated": 0}
    for rule in rules:
        counts[rule["verdict"]] = counts.get(rule["verdict"], 0) + 1
    payload = {
        "status": "ok",
        "rules": rules,
        "counts": counts,
        "ruleCount": len(rules),
        "alertsReceived": sum(1 for r in rules if r.get("evidence")),
        "detectionCoverage": round(counts["fired"] / len(rules) * 100) if rules else None,
        "integrationHealth": True,
        "unattributedCount": 0,
        "unattributedTruncated": False,
        "unattributed": [],
    }
    payload.update(overrides)
    return payload


def _rule(rule_id, verdict, technique, *, evidence=None, tier=""):
    """Build one per-rule verdict entry."""
    return {
        "ruleId": rule_id,
        "title": f"Rule {rule_id}",
        "verdict": verdict,
        "severity": "high",
        "technique": technique,
        "matchTier": tier,
        "evidence": evidence,
    }


class RuleRowTests(SimpleTestCase):
    """What the per-rule table carries, and in what order."""

    def test_an_unsettled_run_produces_no_rows(self):
        """A report cannot list verdicts that were never reached."""
        self.assertEqual(_rule_rows(None), [])

    def test_silent_rules_sort_above_fired_ones(self):
        """
        The findings a reader must act on belong at the top.

        A table ordered by rule id scatters the two silent rules through
        twenty that fired, which is how a finding gets missed.
        """
        rows = _rule_rows(_score([
            _rule("t1000", "fired", "T1000", evidence={"alertId": "a"}),
            _rule("t2000", "silent", "T2000"),
            _rule("t3000", "not_integrated", "T3000"),
        ]))
        self.assertEqual([r["verdict"] for r in rows], ["silent", "not_integrated", "fired"])

    def test_evidence_names_the_alert_behind_a_fired_rule(self):
        """A verdict a reader cannot trace to an alert is an assertion."""
        rows = _rule_rows(_score([
            _rule("t1000", "fired", "T1000", tier="exact", evidence={
                "alertId": "abc", "ruleId": "sigma-uuid", "ruleName": "Their rule",
                "severity": "high", "firedAt": "2026-09-17T19:52:17Z",
                "receivedAt": "2026-09-17T19:52:17Z",
            }),
        ]))
        self.assertEqual(rows[0]["evidence"]["alertId"], "abc")
        self.assertEqual(rows[0]["evidence"]["ruleName"], "Their rule")
        self.assertEqual(rows[0]["matchTier"], "exact")

    def test_a_silent_rule_carries_no_evidence(self):
        """Nothing reached it, so there is nothing to show."""
        rows = _rule_rows(_score([_rule("t1000", "silent", "T1000")]))
        self.assertIsNone(rows[0]["evidence"])


class UncoveredTechniqueTests(SimpleTestCase):
    """Techniques the emulation executes that no rule watches."""

    ATTACK_PATH = [
        {"phase": 1, "name": "Initial Access",
         "techniques": [{"id": "T1078.004", "name": "Valid Accounts"}]},
        {"phase": 2, "name": "Impact",
         "techniques": [{"id": "T1486", "name": "Data Encrypted"},
                        {"id": "T1496", "name": "Resource Hijacking"}]},
    ]

    def test_a_technique_with_a_rule_is_not_reported_as_uncovered(self):
        """It was judged, so it is inside the coverage figure already."""
        rows = _rule_rows(_score([_rule("t1078.004", "fired", "T1078.004",
                                        evidence={"alertId": "a"})]))
        uncovered = _uncovered(self.ATTACK_PATH, rows)
        self.assertNotIn("T1078.004", [u["id"] for u in uncovered])

    def test_a_technique_with_no_rule_is_reported(self):
        """
        The case the whole function exists for.

        Without this the emulation could report full coverage while executing a
        step nothing was watching, which is a gap in our content that would
        read as a clean bill of health for the customer.
        """
        rows = _rule_rows(_score([_rule("t1078.004", "fired", "T1078.004",
                                        evidence={"alertId": "a"})]))
        uncovered = _uncovered(self.ATTACK_PATH, rows)
        self.assertEqual({u["id"] for u in uncovered}, {"T1486", "T1496"})
        self.assertEqual(uncovered[0]["phaseName"], "Impact")

    def test_a_rule_id_matches_its_technique_without_metadata(self):
        """A pack that omits technique metadata still counts as coverage."""
        rows = _rule_rows(_score([_rule("t1486", "silent", "")]))
        self.assertNotIn("T1486", [u["id"] for u in _uncovered(self.ATTACK_PATH, rows)])


class CoverageSentenceTests(SimpleTestCase):
    """The wording, which is the product argument rather than house style."""

    def test_coverage_is_phrased_as_rules_evaluated(self):
        """Never a bare percentage: it invites a reader to over-read it."""
        rules = [_rule("t1", "fired", "T1", evidence={"alertId": "a"}),
                 _rule("t2", "silent", "T2")]
        sentence = coverage_sentence(_score(rules), [])
        self.assertIn("1 of 2 rules evaluated", sentence)
        self.assertNotRegex(sentence, r"^\d+%")

    def test_uncovered_techniques_are_declared_as_excluded(self):
        """A figure that silently omits them overstates the client's position."""
        rules = [_rule("t1", "fired", "T1", evidence={"alertId": "a"})]
        sentence = coverage_sentence(_score(rules), [{"id": "T1486"}, {"id": "T1496"}])
        self.assertIn("excluded", sentence)
        self.assertIn("ships no rule", sentence)

    def test_no_endpoint_is_reported_as_a_setup_gap(self):
        """
        The distinction the feature exists for.

        Scoring an unwired integration as nought tells a detection team their
        rules are bad when the fault is a missing webhook. Different team,
        different fix.
        """
        rules = [_rule("t1", "not_integrated", "T1")]
        sentence = coverage_sentence(_score(rules, status="no_endpoint"), [])
        self.assertIn("setup gap", sentence)
        self.assertNotIn("rules evaluated", sentence)

    def test_no_alerts_points_at_the_pipeline_not_the_rules(self):
        """An endpoint that received nothing is not a detection failure."""
        rules = [_rule("t1", "not_integrated", "T1")]
        sentence = coverage_sentence(_score(rules, status="no_alerts"), [])
        self.assertIn("alert pipeline", sentence)

    def test_an_unsettled_run_claims_nothing(self):
        """Before the window closes there is no measurement to report."""
        self.assertIn("not settled", coverage_sentence(None, []))

    def test_an_emulation_with_no_rules_says_so(self):
        """Zero of zero is not a coverage figure."""
        self.assertIn("no detection rules", coverage_sentence(_score([]), []))
