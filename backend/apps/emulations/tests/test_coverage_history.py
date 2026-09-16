"""
Tests for coverage trend and detection-regression detection.

Pure functions over detection_check dicts, so no database or provider is
needed. The regression logic is the load-bearing part - it is what a
continuous-assurance alert fires on - so its edge cases get the most attention.
"""

from __future__ import annotations

from django.test import SimpleTestCase

from apps.emulations import coverage_history as ch


def _check(**verdicts):
    """Build a detection_check payload from ruleId=verdict kwargs."""
    rules = [{"ruleId": rid, "verdict": v, "title": rid.upper()} for rid, v in verdicts.items()]
    counts = {
        "fired": sum(1 for v in verdicts.values() if v == "fired"),
        "silent": sum(1 for v in verdicts.values() if v == "silent"),
        "no_logs": sum(1 for v in verdicts.values() if v == "no_logs"),
    }
    return {"status": "ok", "counts": counts, "ruleCount": len(rules), "rules": rules}


class CompareTests(SimpleTestCase):
    """Diffing two runs' verdicts."""

    def test_fired_then_silent_is_a_regression(self):
        """The whole point: a rule that worked and now does not."""
        prev = _check(t1="fired", t2="fired")
        curr = _check(t1="fired", t2="silent")
        result = ch.compare(prev, curr)
        self.assertEqual([r["ruleId"] for r in result["regressions"]], ["t2"])
        self.assertEqual(result["regressions"][0]["from"], "fired")
        self.assertEqual(result["regressions"][0]["to"], "silent")

    def test_silent_then_fired_is_an_improvement(self):
        prev = _check(t1="silent")
        curr = _check(t1="fired")
        result = ch.compare(prev, curr)
        self.assertEqual([r["ruleId"] for r in result["improvements"]], ["t1"])
        self.assertEqual(result["regressions"], [])

    def test_fired_then_no_logs_is_a_regression(self):
        """Losing telemetry for a rule that fired is still a lost detection."""
        result = ch.compare(_check(t1="fired"), _check(t1="no_logs"))
        self.assertEqual(len(result["regressions"]), 1)

    def test_no_logs_then_silent_is_not_a_regression(self):
        """
        A rule that was never confirmed working (no_logs) going silent is not a
        loss - there was no working detection to lose. Flagging it would cry
        wolf and train the team to ignore regressions.
        """
        result = ch.compare(_check(t1="no_logs"), _check(t1="silent"))
        self.assertEqual(result["regressions"], [])
        self.assertEqual(result["improvements"], [])

    def test_new_rule_is_neither(self):
        """A rule absent from the previous run cannot have regressed."""
        result = ch.compare(_check(t1="fired"), _check(t1="fired", t2="silent"))
        self.assertEqual(result["regressions"], [])

    def test_unchanged_counted(self):
        result = ch.compare(_check(t1="fired", t2="silent"), _check(t1="fired", t2="silent"))
        self.assertEqual(result["unchanged"], 2)
        self.assertEqual(result["regressions"], [])

    def test_empty_or_incomplete_checks_are_safe(self):
        """Missing or errored checks yield an empty diff, never a crash."""
        self.assertEqual(ch.compare(None, None)["regressions"], [])
        self.assertEqual(ch.compare({"status": "error"}, _check(t1="fired"))["regressions"], [])


class SnapshotAndTrendTests(SimpleTestCase):
    """Trend points off run objects."""

    class _Run:
        def __init__(self, rid, check, completed):
            self.id = rid
            self.emulation_type = "ambersquid"
            self.detection_check = check
            self.completed_at = completed

    class _When:
        def __init__(self, iso):
            self._iso = iso

        def isoformat(self):
            return self._iso

    def test_fidelity_is_fired_over_rulecount(self):
        run = self._Run("r1", _check(t1="fired", t2="fired", t3="silent"), self._When("2026-01-01T00:00:00"))
        snap = ch.snapshot(run)
        self.assertEqual(snap["counts"], {"fired": 2, "silent": 1, "no_logs": 0})
        self.assertAlmostEqual(snap["fidelity"], round(2 / 3, 3))

    def test_trend_skips_runs_without_a_completed_check(self):
        """A run whose check never completed is omitted, not plotted as zero."""
        runs = [
            self._Run("r1", _check(t1="fired"), self._When("2026-01-02T00:00:00")),
            self._Run("r2", None, self._When("2026-01-03T00:00:00")),
            self._Run("r3", {"status": "error"}, self._When("2026-01-04T00:00:00")),
        ]
        trend = ch.coverage_trend(runs)
        self.assertEqual([p["runId"] for p in trend], ["r1"])

    def test_trend_is_oldest_first(self):
        runs = [
            self._Run("late", _check(t1="fired"), self._When("2026-02-01T00:00:00")),
            self._Run("early", _check(t1="fired"), self._When("2026-01-01T00:00:00")),
        ]
        self.assertEqual([p["runId"] for p in ch.coverage_trend(runs)], ["early", "late"])


class BuildAssuranceTests(SimpleTestCase):
    """The dashboard portfolio summary."""

    class _Run:
        def __init__(self, etype, check, completed):
            import uuid
            self.id = uuid.uuid4()
            self.emulation_type = etype
            self.detection_check = check
            self.completed_at = completed

    class _Sched:
        def __init__(self, etype, cadence, nxt):
            from datetime import datetime, timezone
            self.emulation_type = etype
            self.cadence = cadence
            self.enabled = True
            self.next_run_at = datetime.fromisoformat(nxt).replace(tzinfo=timezone.utc)

    def test_coverage_sums_latest_run_per_emulation(self):
        runs = [
            self._Run("a", _check(t1="fired", t2="silent"), "2026-01-01"),
            self._Run("a", _check(t1="fired", t2="fired"), "2026-01-08"),   # latest for a: 2/2
            self._Run("b", _check(t3="silent"), "2026-01-05"),               # latest for b: 0/1
        ]
        out = ch.build_assurance(runs, [], now=None)
        # a contributes 2 fired / 2, b contributes 0 / 1  => 2/3
        self.assertEqual(out["coverage"]["fired"], 2)
        self.assertEqual(out["coverage"]["total"], 3)
        self.assertEqual(out["coverage"]["emulationsScored"], 2)

    def test_regressions_collected_across_emulations(self):
        runs = [
            self._Run("a", _check(t1="fired"), "2026-01-01"),
            self._Run("a", _check(t1="silent"), "2026-01-08"),  # regression in a
            self._Run("b", _check(t2="fired"), "2026-01-02"),
            self._Run("b", _check(t2="fired"), "2026-01-09"),   # no change in b
        ]
        out = ch.build_assurance(runs, [], now=None)
        self.assertEqual(len(out["regressions"]), 1)
        self.assertEqual(out["regressions"][0]["emulationType"], "a")
        self.assertEqual(out["regressions"][0]["ruleId"], "t1")

    def test_single_run_emulation_has_no_regression(self):
        runs = [self._Run("a", _check(t1="fired"), "2026-01-01")]
        out = ch.build_assurance(runs, [], now=None)
        self.assertEqual(out["regressions"], [])
        self.assertTrue(out["hasRuns"])

    def test_schedules_sorted_by_next_run(self):
        scheds = [self._Sched("b", "weekly", "2026-02-01"), self._Sched("a", "daily", "2026-01-15")]
        out = ch.build_assurance([], scheds, now=None)
        self.assertEqual([s["emulationType"] for s in out["schedules"]], ["a", "b"])
        self.assertEqual(out["scheduleCount"], 2)

    def test_no_runs_is_clean(self):
        out = ch.build_assurance([], [], now=None)
        self.assertFalse(out["hasRuns"])
        self.assertIsNone(out["coverage"]["pct"])
