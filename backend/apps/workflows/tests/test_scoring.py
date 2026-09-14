"""
Tests for turning match results into figures.

The distinction under test throughout is between a detection that stayed silent
and one that was never exercised. Collapsing them produces a score that blames
a client's detection engineers for a webhook nobody connected, which is both
wrong and unfixable by the people it accuses.
"""

from django.test import SimpleTestCase

from apps.workflows.correlate import FIRED, NOT_INTEGRATED, SILENT
from apps.workflows.scoring import build_score, headline

MATCHED = {
    "rules": [
        {"ruleId": "a", "title": "A", "severity": "high", "technique": "T1", "verdict": FIRED,
         "matchTier": "exact", "evidence": {"alertId": "1"}},
        {"ruleId": "b", "title": "B", "severity": "low", "technique": "T2", "verdict": SILENT,
         "matchTier": "", "evidence": None},
    ],
    "unmatched": [{"alertId": "9", "ruleName": "Impossible travel"}],
}


class IntegratedTests(SimpleTestCase):
    """A client whose SIEM is posting alerts."""

    def test_coverage_is_measured_over_what_was_exercised(self):
        """One of two expected detections reported means fifty percent."""
        score = build_score(MATCHED, endpoint_configured=True, alerts_received=3)
        self.assertEqual(score["status"], "ok")
        self.assertEqual(score["detectionCoverage"], 50)
        self.assertEqual(score["counts"], {FIRED: 1, SILENT: 1, NOT_INTEGRATED: 0})

    def test_unattributed_alerts_are_counted_separately(self):
        """They are shown for judgement, never folded into coverage."""
        score = build_score(MATCHED, endpoint_configured=True, alerts_received=3)
        self.assertEqual(score["unattributedCount"], 1)
        self.assertEqual(score["detectionCoverage"], 50)

    def test_integration_health_is_true_when_alerts_arrived(self):
        """The signal that separates a real result from an unwired one."""
        self.assertTrue(
            build_score(MATCHED, endpoint_configured=True, alerts_received=1)["integrationHealth"]
        )


class NotIntegratedTests(SimpleTestCase):
    """A client whose alerts never reached us."""

    def test_no_endpoint_marks_every_rule_not_integrated(self):
        """
        Nothing was exercised, so nothing may be reported as a miss.

        Scoring this as nought percent would tell a detection team their rules
        failed when no rule was ever given the chance to run.
        """
        score = build_score(MATCHED, endpoint_configured=False, alerts_received=0)
        self.assertEqual(score["status"], "no_endpoint")
        self.assertEqual(score["counts"][NOT_INTEGRATED], 2)
        self.assertEqual(score["counts"][FIRED], 0)

    def test_no_alerts_is_reported_distinctly_from_no_endpoint(self):
        """
        A configured but silent integration is a different fix.

        One means finish the setup; the other means find out why the SIEM sent
        nothing, which is a question for their pipeline.
        """
        score = build_score(MATCHED, endpoint_configured=True, alerts_received=0)
        self.assertEqual(score["status"], "no_alerts")
        self.assertEqual(score["counts"][NOT_INTEGRATED], 2)

    def test_coverage_is_none_rather_than_zero_when_nothing_ran(self):
        """
        None and nought must render differently.

        A zero reads as "your detections failed"; the honest statement is that
        there is nothing to report yet.
        """
        score = build_score(MATCHED, endpoint_configured=False, alerts_received=0)
        self.assertIsNone(score["detectionCoverage"])
        self.assertFalse(score["integrationHealth"])

    def test_a_fired_verdict_is_overwritten_when_nothing_was_integrated(self):
        """
        Guards the combination that would be a false assurance.

        Without this, stale match output plus a disconnected endpoint could
        report a detection as working when no alert route existed.
        """
        score = build_score(MATCHED, endpoint_configured=False, alerts_received=0)
        self.assertTrue(all(r["verdict"] == NOT_INTEGRATED for r in score["rules"]))
        self.assertTrue(all(r["evidence"] is None for r in score["rules"]))


class EmulationWithoutRulesTests(SimpleTestCase):
    """An emulation that ships nothing to validate."""

    def test_no_rules_is_its_own_status(self):
        """Not a failure of the client's SIEM, so it must not read as one."""
        score = build_score(
            {"rules": [], "unmatched": []}, endpoint_configured=True, alerts_received=2
        )
        self.assertEqual(score["status"], "no_rules")
        self.assertIsNone(score["detectionCoverage"])


class HeadlineTests(SimpleTestCase):
    """The one-sentence summary a list row shows."""

    def test_each_unfinished_state_reads_differently(self):
        """Each one calls for a different action from the reader."""
        no_endpoint = headline(build_score(MATCHED, endpoint_configured=False, alerts_received=0))
        no_alerts = headline(build_score(MATCHED, endpoint_configured=True, alerts_received=0))
        self.assertIn("No alert endpoint", no_endpoint)
        self.assertIn("no alerts", no_alerts)
        self.assertNotEqual(no_endpoint, no_alerts)

    def test_a_real_result_states_the_ratio(self):
        """The sentence a client actually wants to read."""
        self.assertIn(
            "1 of 2",
            headline(build_score(MATCHED, endpoint_configured=True, alerts_received=3)),
        )
