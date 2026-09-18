"""
Tests for coverage history.

The assertions worth having here are about the denominator. Reliability is a
share of the runs that actually judged a rule, and every way of getting that
wrong produces a number that reads as a detection failure when the real problem
was a missing connection, or a detection improvement that only happened because
unfavourable runs stopped being counted.
"""

from types import SimpleNamespace

from django.test import SimpleTestCase

from apps.workflows.coverage_history import (
    FIRING,
    FLAKY,
    NEVER_FIRED,
    NO_DATA,
    SILENT_NOW,
    build_history,
    reliability,
    run_gauge,
    sequence,
    standing,
)

FIRED = "fired"
SILENT = "silent"
NOT_INTEGRATED = "not_integrated"


def _run(
    verdicts,
    *,
    status="ok",
    completed="2026-09-01T00:00:00+00:00",
    window_start="2026-09-01T00:00:00+00:00",
    window_end="2026-09-01T00:02:00+00:00",
    deadline="2026-09-01T00:32:00+00:00",
    attack_status="completed",
    run_status="completed",
    failed_step="",
    evidence_for=(),
):
    """
    Build a stand-in for a completed WorkflowRun.

    Args:
        verdicts: Mapping of rule id to verdict for this run.
        status: The score's own status, "ok" unless the run was never judged.
        completed: ISO timestamp, or None for a run with no completion time.

    Returns:
        An object exposing the `id`, `score` and `completed_at` attributes the
        module reads. A SimpleNamespace rather than a model instance, because
        every function under test is pure and touching the database here would
        only slow the suite down.
    """
    counts = {FIRED: 0, SILENT: 0, NOT_INTEGRATED: 0}
    rules = []
    for rule_id, verdict in verdicts.items():
        counts[verdict] += 1
        rules.append({
            "ruleId": rule_id,
            "title": f"Rule {rule_id}",
            "verdict": verdict,
            "severity": "high",
            "technique": rule_id.upper(),
            "matchTier": "technique" if verdict == FIRED else "",
            "evidence": {
                "ruleName": f"Alert for {rule_id}",
                "severity": "high",
                "firedAt": "2026-09-01T00:05:00+00:00",
                "receivedAt": "2026-09-01T00:05:01+00:00",
            } if (verdict == FIRED and rule_id in evidence_for) else None,
        })
    stamp = lambda value: SimpleNamespace(isoformat=lambda v=value: v) if value else None
    return SimpleNamespace(
        id=f"run-{completed}-{len(rules)}",
        completed_at=stamp(completed),
        window_start=stamp(window_start),
        window_end=stamp(window_end),
        alert_deadline=stamp(deadline),
        status=run_status,
        failed_step=failed_step,
        emulation_run=SimpleNamespace(status="completed") if attack_status else None,
        score={
            "status": status,
            "rules": rules,
            "counts": counts,
            "ruleCount": len(rules),
            "alertsReceived": counts[FIRED],
        },
    )


class SequenceTests(SimpleTestCase):
    """Which runs count toward a rule's record."""

    def test_not_integrated_runs_are_excluded(self):
        """A run that never reached the rule is not a miss."""
        runs = [
            _run({"t1": NOT_INTEGRATED}, status="no_endpoint"),
            _run({"t1": FIRED}),
            _run({"t1": SILENT}),
        ]
        self.assertEqual(sequence(runs, "t1"), [FIRED, SILENT])

    def test_a_rule_absent_from_a_run_is_excluded(self):
        """A rule the emulation did not carry yet contributes nothing."""
        runs = [_run({"t2": FIRED}), _run({"t1": FIRED, "t2": FIRED})]
        self.assertEqual(sequence(runs, "t1"), [FIRED])

    def test_order_is_oldest_first(self):
        """Standing reads the tail, so order has to be preserved."""
        runs = [_run({"t1": SILENT}), _run({"t1": FIRED})]
        self.assertEqual(sequence(runs, "t1"), [SILENT, FIRED])


class ReliabilityTests(SimpleTestCase):
    """The figure the bullet chart draws."""

    def test_share_of_judged_runs_only(self):
        """Two unjudged runs must not drag a perfect rule below 100."""
        runs = [
            _run({"t1": NOT_INTEGRATED}, status="no_alerts"),
            _run({"t1": NOT_INTEGRATED}, status="no_alerts"),
            _run({"t1": FIRED}),
            _run({"t1": FIRED}),
        ]
        result = reliability(runs, "t1")
        self.assertEqual(result["pct"], 100)
        self.assertEqual(result["judged"], 2)
        self.assertEqual(result["fired"], 2)

    def test_none_when_nothing_judged_it(self):
        """None, never 0: an unmeasured rule has no reliability to report."""
        runs = [_run({"t1": NOT_INTEGRATED}, status="no_endpoint")]
        self.assertIsNone(reliability(runs, "t1"))

    def test_never_firing_is_zero_not_none(self):
        """A rule that was judged and never fired genuinely is 0%."""
        runs = [_run({"t1": SILENT}), _run({"t1": SILENT})]
        self.assertEqual(reliability(runs, "t1")["pct"], 0)

    def test_rounds_to_whole_percent(self):
        """One fire in three judged runs is 33, not 33.33."""
        runs = [_run({"t1": FIRED}), _run({"t1": SILENT}), _run({"t1": SILENT})]
        self.assertEqual(reliability(runs, "t1")["pct"], 33)


class StandingTests(SimpleTestCase):
    """Four findings a percentage cannot separate."""

    def test_no_data(self):
        """Nothing judged."""
        self.assertEqual(standing([])["state"], NO_DATA)

    def test_never_fired(self):
        """Judged repeatedly, never once caught."""
        self.assertEqual(standing([SILENT, SILENT, SILENT])["state"], NEVER_FIRED)

    def test_silent_now_is_a_regression(self):
        """Fired before, not firing in the latest judged run."""
        self.assertEqual(standing([FIRED, FIRED, SILENT])["state"], SILENT_NOW)

    def test_flaky_when_it_dipped_and_recovered(self):
        """A rule you cannot rely on is not the same as one that is holding."""
        result = standing([FIRED, SILENT, FIRED])
        self.assertEqual(result["state"], FLAKY)
        self.assertEqual(result["dips"], 1)
        self.assertEqual(result["streak"], 1)

    def test_firing_reports_the_streak_not_a_quality_claim(self):
        """The streak is a fact; the percentage judges whether it is good."""
        result = standing([FIRED, FIRED, FIRED])
        self.assertEqual(result["state"], FIRING)
        self.assertEqual(result["streak"], 3)
        self.assertEqual(result["dips"], 0)

    def test_a_first_run_miss_is_not_a_dip(self):
        """Starting silent then firing is an improvement, not flakiness."""
        result = standing([SILENT, FIRED, FIRED])
        self.assertEqual(result["state"], FIRING)
        self.assertEqual(result["dips"], 0)


class RunGaugeTests(SimpleTestCase):
    """One dial per run."""

    def test_coverage_is_the_fired_share(self):
        """Four of five fired is 80."""
        run = _run({"t1": FIRED, "t2": FIRED, "t3": FIRED, "t4": FIRED, "t5": SILENT})
        gauge = run_gauge(run)
        self.assertEqual(gauge["coverage"], 80)
        self.assertTrue(gauge["judged"])

    def test_unjudged_run_has_no_coverage(self):
        """None, so the dial draws an empty track rather than a zero."""
        run = _run({"t1": NOT_INTEGRATED, "t2": NOT_INTEGRATED}, status="no_endpoint")
        gauge = run_gauge(run)
        self.assertIsNone(gauge["coverage"])
        self.assertFalse(gauge["judged"])
        self.assertEqual(gauge["notIntegrated"], 2)

    def test_verdicts_ride_along_for_client_side_scrubbing(self):
        """The page recomputes windows locally, so it needs the per-rule outcome."""
        run = _run({"t1": FIRED, "t2": SILENT})
        self.assertEqual(run_gauge(run)["verdicts"], {"t1": FIRED, "t2": SILENT})

    def test_window_and_attack_state_ride_along(self):
        """The comparison timeline measures alert latency from the attack end."""
        gauge = run_gauge(_run({"t1": FIRED}))
        self.assertEqual(gauge["windowEnd"], "2026-09-01T00:02:00+00:00")
        self.assertEqual(gauge["alertDeadline"], "2026-09-01T00:32:00+00:00")
        self.assertTrue(gauge["attackCompleted"])

    def test_a_failed_attack_is_reported_as_such(self):
        """Integrity has to be able to say the technique never ran."""
        gauge = run_gauge(_run(
            {"t1": SILENT}, run_status="failed", failed_step="attack",
        ))
        self.assertFalse(gauge["attackCompleted"])

    def test_a_severed_emulation_run_link_is_not_a_failed_attack(self):
        """
        `emulation_run` is SET_NULL, so it goes missing when that record is
        removed. Reading it alone reported a run that produced a full score as
        one whose attack never finished, which is the opposite of the truth.
        """
        gauge = run_gauge(_run({"t1": FIRED}, attack_status=None))
        self.assertTrue(gauge["attackCompleted"])

    def test_outcomes_carry_the_alert_behind_a_verdict(self):
        """The comparison names the alert rather than asserting a bare change."""
        gauge = run_gauge(_run({"t1": FIRED}, evidence_for=("t1",)))
        outcome = gauge["outcomes"]["t1"]
        self.assertEqual(outcome["matchTier"], "technique")
        self.assertEqual(outcome["evidence"]["ruleName"], "Alert for t1")

    def test_a_silent_rule_has_no_evidence(self):
        """None, so the panel can say no alert arrived instead of showing a gap."""
        gauge = run_gauge(_run({"t1": SILENT}))
        self.assertIsNone(gauge["outcomes"]["t1"]["evidence"])

    def test_missing_score_does_not_raise(self):
        """A run whose score never landed still renders as unjudged."""
        gauge = run_gauge(SimpleNamespace(
            id="x", score=None, completed_at=None, window_start=None,
            window_end=None, alert_deadline=None, emulation_run=None,
            status="completed", failed_step="",
        ))
        self.assertIsNone(gauge["coverage"])
        self.assertFalse(gauge["judged"])


class BuildHistoryTests(SimpleTestCase):
    """The assembled payload."""

    def setUp(self):
        """A history with one perfect rule, one flaky rule and one dead rule."""
        self.runs = [
            _run(
                {"t1": NOT_INTEGRATED, "t2": NOT_INTEGRATED, "t3": NOT_INTEGRATED},
                status="no_endpoint",
                completed="2026-09-01T00:00:00+00:00",
            ),
            _run({"t1": FIRED, "t2": FIRED, "t3": SILENT}, completed="2026-09-02T00:00:00+00:00"),
            _run({"t1": FIRED, "t2": SILENT, "t3": SILENT}, completed="2026-09-03T00:00:00+00:00"),
            _run({"t1": FIRED, "t2": FIRED, "t3": SILENT}, completed="2026-09-04T00:00:00+00:00"),
        ]
        self.history = build_history(self.runs, "codefinger", 90)

    def _row(self, rule_id):
        """Find one rule row in the built payload."""
        return next(r for r in self.history["rules"] if r["ruleId"] == rule_id)

    def test_every_run_appears_including_the_unjudged_one(self):
        """The run happened, so the page has to be able to show it."""
        self.assertEqual(len(self.history["runs"]), 4)
        self.assertEqual(self.history["counts"]["runs"], 4)
        self.assertEqual(self.history["counts"]["judged"], 3)

    def test_reliability_excludes_the_unjudged_run(self):
        """t1 fired in all three judged runs."""
        self.assertEqual(self._row("t1")["reliability"], 100)
        self.assertEqual(self._row("t1")["judgedRuns"], 3)

    def test_flaky_rule_is_labelled_flaky(self):
        """t2 fired, dipped, recovered."""
        row = self._row("t2")
        self.assertEqual(row["state"], FLAKY)
        self.assertEqual(row["reliability"], 67)

    def test_never_fired_rule_is_surfaced(self):
        """t3 was judged three times and never caught anything."""
        row = self._row("t3")
        self.assertEqual(row["state"], NEVER_FIRED)
        self.assertEqual(row["reliability"], 0)

    def test_previous_reliability_excludes_the_last_judged_run(self):
        """t2 stood at 50 percent before its most recent run."""
        self.assertEqual(self._row("t2")["previousReliability"], 50)

    def test_meets_target_uses_the_passed_target(self):
        """The threshold is the caller's, not a constant in this module."""
        self.assertTrue(self._row("t1")["meetsTarget"])
        self.assertFalse(self._row("t2")["meetsTarget"])
        self.assertEqual(self.history["counts"]["belowTarget"], 2)

    def test_platform_is_echoed_back(self):
        """Rule rows link to the detection page, which is platform-scoped."""
        self.assertEqual(self.history["platform"], "aws")

    def test_target_is_echoed_back(self):
        """The chart draws the tick from this, so it has to be in the payload."""
        self.assertEqual(self.history["target"], 90)

    def test_rules_are_ordered_by_the_newest_run(self):
        """A rule the latest run no longer carries must not lead the table."""
        self.assertEqual([r["ruleId"] for r in self.history["rules"]], ["t1", "t2", "t3"])

    def test_titles_survive_a_rule_the_latest_run_dropped(self):
        """An edited emulation must not leave an old rule as a bare id."""
        runs = self.runs + [_run({"t1": FIRED}, completed="2026-09-05T00:00:00+00:00")]
        history = build_history(runs, "codefinger", 90)
        row = next(r for r in history["rules"] if r["ruleId"] == "t3")
        self.assertEqual(row["title"], "Rule t3")

    def test_all_unjudged_history_claims_nothing(self):
        """The scarleteel case: four runs, no endpoint, no figures."""
        runs = [
            _run({"t1": NOT_INTEGRATED}, status="no_endpoint"),
            _run({"t1": NOT_INTEGRATED}, status="no_alerts"),
        ]
        history = build_history(runs, "scarleteel", 90)
        self.assertEqual(history["counts"]["judged"], 0)
        self.assertEqual(history["counts"]["belowTarget"], 0)
        row = history["rules"][0]
        self.assertIsNone(row["reliability"])
        self.assertEqual(row["state"], NO_DATA)

    def test_empty_history_is_valid(self):
        """An emulation with no completed runs is a legitimate empty page."""
        history = build_history([], "codefinger", 90)
        self.assertEqual(history["runs"], [])
        self.assertEqual(history["rules"], [])
        self.assertEqual(history["counts"]["judged"], 0)
