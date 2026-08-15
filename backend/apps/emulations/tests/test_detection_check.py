"""
Tests for the post-run detection coverage check.

The behaviour worth protecting is the three-way verdict. A rule that does not
alert can mean the attack did not do that thing, or that its log source never
reached the archive, and those two lead an engineer to opposite conclusions.
Collapsing them was the failure mode this module exists to avoid, so most of
these tests are about keeping them apart.

Fixtures are real archived detections with the account id, ARNs, source IP and
operator name replaced. They are kept real in shape because the envelope the
notifier writes is the contract this module reads.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

from django.test import SimpleTestCase

from apps.emulations.detection_check import (
    FIRED,
    NO_LOGS,
    SILENT,
    build_report,
    check_rule,
    covered_sources,
    evaluable_documents,
    normalise,
    partition_prefixes,
    required_sources,
)

_FIXTURES = Path(__file__).resolve().parent / "fixtures"

# backend/apps/emulations/tests/ -> repo root is parents[4].
_EMULATIONS_DIR = Path(__file__).resolve().parents[4] / "emulations"
_SCARLETEEL = _EMULATIONS_DIR / "scarleteel" / "detections"


def load_record(name: str) -> dict:
    """
    Load one archived detection fixture as a normalised record.

    Args:
        name: Fixture filename under tests/fixtures.

    Returns:
        The record shape detection_check consumes.
    """
    return normalise(json.loads((_FIXTURES / name).read_text(encoding="utf-8")))


def sigma(technique: str) -> str:
    """
    Read one of scarleteel's shipped Sigma rules.

    Args:
        technique: Technique key as it appears in the filename, e.g. "t1190".

    Returns:
        Raw file contents.
    """
    return (_SCARLETEEL / f"sigma_{technique}.yml").read_text(encoding="utf-8")


def rule(technique: str) -> dict:
    """Build the rule record build_report expects for one technique."""
    return {"ruleId": technique, "title": "", "severity": "", "sigma": sigma(technique)}


class RuleParsingTests(SimpleTestCase):
    """Reading a rule's evaluable documents and the sources it needs."""

    def test_correlation_documents_are_dropped(self):
        """
        The enumeration rule ships a base rule plus a count-over-time
        correlation. The correlation cannot be judged from one event, so only
        the base rule survives, and the rule still carries signal.
        """
        documents = evaluable_documents(sigma("t1087.004"))
        self.assertEqual(len(documents), 1)
        self.assertEqual(documents[0].get("level"), "informational")

    def test_required_sources_reads_a_single_value(self):
        self.assertEqual(
            required_sources(evaluable_documents(sigma("t1098"))),
            {"lambda.amazonaws.com"},
        )

    def test_required_sources_reads_a_list(self):
        self.assertEqual(
            required_sources(evaluable_documents(sigma("t1087.004"))),
            {"iam.amazonaws.com", "s3.amazonaws.com", "secretsmanager.amazonaws.com"},
        )

    def test_undeclared_source_is_empty_not_guessed(self):
        """A rule that names no eventSource constrains no particular source."""
        self.assertEqual(required_sources(evaluable_documents(sigma("t1552.005"))), set())


class VerdictTests(SimpleTestCase):
    """The three-way split, which is the point of the module."""

    def setUp(self):
        self.operator = load_record("archive_sts_operator.json")
        self.emulation = load_record("archive_iam_emulation.json")
        self.records = [self.operator, self.emulation]
        self.covered = covered_sources(self.records)

    def test_covered_sources_come_from_the_records(self):
        self.assertEqual(self.covered, {"sts.amazonaws.com", "iam.amazonaws.com"})

    def test_rule_with_a_match_fires(self):
        outcome = check_rule("t1190", sigma("t1190"), self.records, self.covered)
        self.assertEqual(outcome["verdict"], FIRED)
        self.assertEqual(outcome["matchCount"], 1)

    def test_rule_whose_source_is_absent_reports_no_logs(self):
        """
        The Lambda backdoor rule needs lambda events. None arrived, so the rule
        was never exercised and reporting it as silent would blame the rule for
        a gap in the log pipeline.
        """
        outcome = check_rule("t1098", sigma("t1098"), self.records, self.covered)
        self.assertEqual(outcome["verdict"], NO_LOGS)
        self.assertEqual(outcome["requiredSources"], ["lambda.amazonaws.com"])

    def test_rule_whose_source_arrived_but_did_not_match_is_silent(self):
        """
        The enumeration rule needs iam among others, and iam events did arrive.
        Nothing matched, which is a real finding about the rule or the attack.
        """
        outcome = check_rule("t1087.004", sigma("t1087.004"), self.records, self.covered)
        self.assertEqual(outcome["verdict"], SILENT)

    def test_evidence_names_the_actor_on_a_fired_rule(self):
        """
        The Phase 1 rule matches GetCallerIdentity from any assumed role outside
        the VPC, including an operator's own console session. Naming the actor
        and the archive's is_emulation flag is what stops that being read as a
        successful detection of the attack.
        """
        outcome = check_rule("t1190", sigma("t1190"), self.records, self.covered)
        evidence = outcome["evidence"]
        self.assertIn("session:analyst", evidence["actor"])
        self.assertFalse(evidence["isEmulation"])
        self.assertEqual(evidence["eventName"], "GetCallerIdentity")

    def test_no_evidence_on_a_rule_that_did_not_fire(self):
        outcome = check_rule("t1098", sigma("t1098"), self.records, self.covered)
        self.assertIsNone(outcome["evidence"])


class ReportTests(SimpleTestCase):
    """The assembled report served to the coverage page."""

    def setUp(self):
        # Three sources, chosen so the fixture set reproduces the coverage of
        # the live archive: sts and iam and secretsmanager arrive, lambda and s3
        # and cloudtrail do not.
        self.records = [
            load_record("archive_sts_operator.json"),
            load_record("archive_iam_emulation.json"),
            load_record("archive_secretsmanager.json"),
        ]
        self.rules = [
            rule(t)
            for t in ("t1087.004", "t1098", "t1190", "t1552.001", "t1552.005", "t1555.006", "t1562.008")
        ]

    def test_every_rule_gets_exactly_one_verdict(self):
        report = build_report(self.rules, self.records)
        self.assertEqual(report["ruleCount"], len(self.rules))
        self.assertEqual(sum(report["counts"].values()), len(self.rules))

    def test_scarleteel_against_this_archive(self):
        """
        One rule fires, three stay silent, three have no telemetry. Locks in the
        shape of the answer for the rule set as shipped.
        """
        report = build_report(self.rules, self.records)
        self.assertEqual(report["counts"][FIRED], 1)
        self.assertEqual(report["counts"][NO_LOGS], 3)
        self.assertEqual(report["counts"][SILENT], 3)

    def test_fired_rules_sort_first(self):
        """The page reads top down, so what fired must not be buried."""
        verdicts = [r["verdict"] for r in build_report(self.rules, self.records)["rules"]]
        self.assertEqual(verdicts[0], FIRED)
        self.assertEqual(verdicts[-1], NO_LOGS)

    def test_empty_archive_reports_no_logs_not_silence(self):
        """
        With nothing archived, no source is covered, so every rule that declares
        one is a logging gap rather than a rule that failed to match.
        """
        report = build_report(self.rules, [])
        self.assertEqual(report["eventCount"], 0)
        self.assertEqual(report["counts"][FIRED], 0)
        # t1552.005 declares no source, so it cannot be called a logging gap.
        self.assertEqual(report["counts"][NO_LOGS], 6)
        self.assertEqual(report["counts"][SILENT], 1)

    def test_rule_without_sigma_is_skipped(self):
        """A KQL-only rule cannot be judged in process, so it is not reported."""
        report = build_report([{"ruleId": "t9999", "sigma": None}], self.records)
        self.assertEqual(report["ruleCount"], 0)


class PartitionTests(SimpleTestCase):
    """Key prefixes for the window, so a run never lists the whole archive."""

    def test_single_day_window(self):
        start = datetime(2026, 8, 15, 2, 31, tzinfo=timezone.utc)
        end = datetime(2026, 8, 15, 2, 39, tzinfo=timezone.utc)
        self.assertEqual(
            partition_prefixes(start, end, "detections/"),
            ["detections/year=2026/month=08/day=15/"],
        )

    def test_window_crossing_midnight_spans_two_partitions(self):
        start = datetime(2026, 8, 14, 23, 55, tzinfo=timezone.utc)
        end = datetime(2026, 8, 15, 0, 10, tzinfo=timezone.utc)
        self.assertEqual(
            partition_prefixes(start, end, "detections/"),
            [
                "detections/year=2026/month=08/day=14/",
                "detections/year=2026/month=08/day=15/",
            ],
        )

    def test_a_wide_window_is_capped(self):
        """A malformed window must not turn into a listing of the whole archive."""
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        end = datetime(2026, 12, 31, tzinfo=timezone.utc)
        self.assertEqual(len(partition_prefixes(start, end, "detections/")), 7)
