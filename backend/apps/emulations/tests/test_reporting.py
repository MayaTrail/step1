"""
Tests for the evidence packet and the two-run comparison.

Both are assemblies over `detection_check` payloads already stored on a run, so
these exercise the pure functions directly with hand-built run stubs - no AWS,
no worker, no live run.
"""

from __future__ import annotations

from types import SimpleNamespace

from django.test import SimpleTestCase

from apps.emulations import coverage_history, reporting


def _check(rules, status="ok"):
    """Build a detection_check payload with counts derived from the rules."""
    counts = {"fired": 0, "silent": 0, "no_logs": 0}
    for rule in rules:
        counts[rule["verdict"]] = counts.get(rule["verdict"], 0) + 1
    return {
        "status": status,
        "counts": counts,
        "ruleCount": len(rules),
        "rules": rules,
    }


def _rule(rule_id, verdict, technique_id=None, **extra):
    payload = {
        "ruleId": rule_id,
        "verdict": verdict,
        "title": f"Rule {rule_id}",
        "severity": extra.get("severity", "medium"),
        "matchCount": extra.get("matchCount", 3),
        "evaluableDocuments": extra.get("evaluableDocuments", 1),
        "requiredSources": ["cloudtrail"],
    }
    if technique_id:
        payload["technique"] = {"id": technique_id, "name": "T", "tactic": "Execution"}
    return payload


def _run(run_id, check, completed="2026-09-12T10:00:00+00:00", emulation="ambersquid"):
    return SimpleNamespace(
        id=run_id,
        emulation_type=emulation,
        status="completed",
        detection_check=check,
        started_at=None,
        completed_at=SimpleNamespace(isoformat=lambda c=completed: c),
        phase_current=5,
        phase_total=5,
        stack=SimpleNamespace(name="stack-1", region="us-east-1"),
        triggered_by=SimpleNamespace(email="test@mayatrail.local"),
    )


class CompareRunsTests(SimpleTestCase):
    """compare_runs() puts every rule on the table, not just the breakage."""

    def test_classifies_every_transition(self):
        before = _run("a", _check([
            _rule("t1", "fired"),
            _rule("t2", "fired"),
            _rule("t3", "silent"),
            _rule("t4", "silent"),
            _rule("t5", "fired"),
        ]))
        after = _run("b", _check([
            _rule("t1", "fired"),    # unchanged
            _rule("t2", "silent"),   # regressed
            _rule("t3", "fired"),    # improved
            _rule("t4", "no_logs"),  # changed, but neither a loss nor a gain
            _rule("t6", "fired"),    # added
        ]))                          # t5 removed

        out = coverage_history.compare_runs(before, after)

        by_id = {row["ruleId"]: row["change"] for row in out["rows"]}
        self.assertEqual(by_id["t1"], "unchanged")
        self.assertEqual(by_id["t2"], "regressed")
        self.assertEqual(by_id["t3"], "improved")
        self.assertEqual(by_id["t4"], "changed")
        self.assertEqual(by_id["t5"], "removed")
        self.assertEqual(by_id["t6"], "added")
        self.assertEqual(out["summary"]["regressed"], 1)
        self.assertEqual(out["summary"]["improved"], 1)

    def test_regressions_sort_to_the_top(self):
        before = _run("a", _check([_rule("t1", "fired"), _rule("t2", "fired")]))
        after = _run("b", _check([_rule("t1", "fired"), _rule("t2", "silent")]))

        rows = coverage_history.compare_runs(before, after)["rows"]

        self.assertEqual(rows[0]["ruleId"], "t2")
        self.assertEqual(rows[0]["change"], "regressed")

    def test_fidelity_delta_is_signed(self):
        before = _run("a", _check([_rule("t1", "fired"), _rule("t2", "fired")]))
        after = _run("b", _check([_rule("t1", "fired"), _rule("t2", "silent")]))

        out = coverage_history.compare_runs(before, after)

        self.assertEqual(out["a"]["fidelity"], 1.0)
        self.assertEqual(out["b"]["fidelity"], 0.5)
        self.assertEqual(out["fidelityDelta"], -0.5)

    def test_unjudged_runs_compare_to_an_empty_table(self):
        before = _run("a", _check([], status="error"))
        after = _run("b", _check([], status="error"))

        out = coverage_history.compare_runs(before, after)

        self.assertEqual(out["rows"], [])
        self.assertIsNone(out["fidelityDelta"])


class BuildReportTests(SimpleTestCase):
    """The evidence packet assembles stored facts and names its own gaps."""

    def setUp(self):
        self.check = _check([
            _rule("t1059.009", "silent", "T1059.009"),
            _rule("t1070", "fired", "T1070"),
            _rule("t1136.003", "no_logs", "T1136.003"),
        ])
        self.entry = {
            "display_name": "AMBERSQUID",
            "attack_path": [
                {"phase": 1, "name": "Execution", "techniques": [
                    {"id": "T1059.009", "name": "Cloud API"},
                    {"id": "T1204.003", "name": "Malicious Image"},
                ]},
                {"phase": 2, "name": "Impact", "techniques": [
                    {"id": "T1070", "name": "Indicator Removal"},
                    {"id": "T1496", "name": "Resource Hijacking"},
                ]},
            ],
        }

    def test_coverage_matches_the_stored_check(self):
        report = reporting.build_report(_run("r", self.check), self.entry)

        self.assertEqual(report["coverage"]["fired"], 1)
        self.assertEqual(report["coverage"]["silent"], 1)
        self.assertEqual(report["coverage"]["noLogs"], 1)
        self.assertEqual(report["coverage"]["ruleCount"], 3)
        self.assertEqual(report["coverage"]["fidelity"], round(1 / 3, 3))

    def test_findings_lead_with_what_must_be_acted_on(self):
        report = reporting.build_report(_run("r", self.check), self.entry)

        self.assertEqual(report["findings"][0]["verdict"], "silent")
        self.assertEqual([g["verdict"] for g in report["gaps"]], ["silent", "no_logs"])

    def test_names_techniques_no_rule_looks_for(self):
        """The declared steps with no detection - our gap, not the customer's."""
        report = reporting.build_report(_run("r", self.check), self.entry)

        uncovered = {u["id"] for u in report["uncovered"]}
        self.assertEqual(uncovered, {"T1204.003", "T1496"})
        # A technique that *was* judged never appears as uncovered.
        self.assertNotIn("T1059.009", uncovered)

    def test_uncovered_carries_its_phase_for_context(self):
        report = reporting.build_report(_run("r", self.check), self.entry)

        t1496 = [u for u in report["uncovered"] if u["id"] == "T1496"][0]
        self.assertEqual(t1496["phase"], 2)
        self.assertEqual(t1496["phaseName"], "Impact")

    def test_survives_a_missing_registry_entry(self):
        """An uninstalled package must not take the whole report down."""
        report = reporting.build_report(_run("r", self.check), None)

        self.assertEqual(report["run"]["displayName"], "ambersquid")
        self.assertEqual(report["uncovered"], [])
        self.assertEqual(report["coverage"]["ruleCount"], 3)

    def test_change_report_is_empty_without_a_previous_run(self):
        report = reporting.build_report(_run("r", self.check), self.entry)

        self.assertFalse(report["change"]["hasPrevious"])

    def test_change_report_names_the_regression(self):
        previous = _run("p", _check([_rule("t1059.009", "fired", "T1059.009")]))
        report = reporting.build_report(
            _run("r", self.check), self.entry, previous_run=previous,
        )

        self.assertTrue(report["change"]["hasPrevious"])
        self.assertEqual(
            [r["ruleId"] for r in report["change"]["regressions"]], ["t1059.009"],
        )
