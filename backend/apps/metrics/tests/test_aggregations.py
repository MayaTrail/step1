"""
Tests for the dashboard metric aggregations.

Where possible these cross-check an aggregation against the live registry rather
than hard-coding totals, so they stay correct as emulations are added.  A few
assertions lock behaviour that must not regress (sub-technique roll-up, revoked
T1562 -> T1685 resolution, the scarleteel platform/detection counts).
"""

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

from django.test import SimpleTestCase

from apps.emulations import registry as registry_wrapper
from apps.metrics import aggregations
from apps.metrics.mitre import catalog

_REPO_ROOT = Path(__file__).resolve().parents[4]
_FALLBACK_EMULATIONS_DIR = _REPO_ROOT / "emulations"


def _ensure_registry_loaded() -> None:
    """Point the registry at the Docker mount or the repo emulations/ directory."""
    env_dir = os.environ.get("EMULATIONS_BASE_DIR", "")
    base = Path(env_dir) if env_dir and Path(env_dir).is_dir() else _FALLBACK_EMULATIONS_DIR
    os.environ["EMULATIONS_BASE_DIR"] = str(base)
    registry_wrapper.reset_cache()


def _expected_covered() -> set[str]:
    """Recompute the covered technique set straight from the registry."""
    covered: set[str] = set()
    for entry in registry_wrapper.list_emulations():
        for mapping in entry.get("mitre_mappings", []) or []:
            tid = mapping.get("id")
            if isinstance(tid, str) and catalog.is_known(tid):
                covered.add(catalog.normalize_technique(tid))
    return covered


class MitreCoverageTests(SimpleTestCase):
    """The coverage summary is consistent with the catalogue and the registry."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        _ensure_registry_loaded()

    def test_summary_totals_match_catalogue_and_registry(self):
        summary = aggregations.mitre_coverage()["summary"]
        self.assertEqual(summary["totalTechniques"], catalog.technique_count())
        self.assertEqual(summary["coveredTechniques"], len(_expected_covered()))

    def test_every_catalogue_tactic_is_present_with_status(self):
        payload = aggregations.mitre_coverage()
        self.assertEqual(len(payload["tactics"]), len(catalog.tactics()))
        for tactic in payload["tactics"]:
            self.assertIn(tactic["status"], {"covered", "partial", "none"})
            self.assertLessEqual(tactic["coveredCount"], tactic["techniqueCount"])

    def test_distribution_counts_sum_to_tactic_total(self):
        payload = aggregations.mitre_coverage()
        dist = payload["summary"]["distribution"]
        self.assertEqual(sum(dist.values()), len(payload["tactics"]))

    def test_highlights_and_insights_present(self):
        payload = aggregations.mitre_coverage()
        self.assertIsNotNone(payload["summary"]["mostCovered"])
        self.assertIsNotNone(payload["summary"]["leastCovered"])
        self.assertGreater(len(payload["insights"]), 0)

    def test_filters_expose_options(self):
        filters = aggregations.mitre_coverage()["filters"]
        self.assertIn("aws", {p["id"] for p in filters["platforms"]})
        self.assertIn("scarleteel", {e["id"] for e in filters["emulations"]})
        self.assertEqual(len(filters["tactics"]), len(catalog.tactics()))

    def test_platform_filter_with_no_match_yields_zero_coverage(self):
        """Filtering to a platform with no emulations zeroes coverage."""
        summary = aggregations.mitre_coverage(platform="azure")["summary"]
        self.assertEqual(summary["coveredTechniques"], 0)


class TacticDetailTests(SimpleTestCase):
    """The per-tactic drill-down reports covered/missing techniques and relations."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        _ensure_registry_loaded()

    def test_unknown_tactic_returns_none(self):
        self.assertIsNone(aggregations.tactic_detail("not-a-tactic"))

    def test_initial_access_covered_and_missing_partition(self):
        detail = aggregations.tactic_detail("initial-access")
        ids_covered = {t["id"] for t in detail["covered"]}
        ids_missing = {t["id"] for t in detail["missing"]}
        # scarleteel covers T1190 under Initial Access.
        self.assertIn("T1190", ids_covered)
        self.assertEqual(ids_covered & ids_missing, set())
        self.assertEqual(
            len(detail["covered"]) + len(detail["missing"]),
            detail["tactic"]["techniqueCount"],
        )

    def test_related_emulations_and_recommendation(self):
        detail = aggregations.tactic_detail("initial-access")
        self.assertIn("scarleteel", {e["id"] for e in detail["relatedEmulations"]})
        self.assertTrue(detail["recommendation"])


class ThreatCoverageTests(SimpleTestCase):
    """One row per emulation, with the shared catalogue denominator."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        _ensure_registry_loaded()

    def test_scarleteel_row_present_with_expected_techniques(self):
        payload = aggregations.threat_coverage()
        rows = {r["id"]: r for r in payload["actors"]}
        self.assertIn("scarleteel", rows)
        self.assertEqual(rows["scarleteel"]["techniqueCount"], 8)

    def test_rows_sorted_by_coverage_descending(self):
        rows = aggregations.threat_coverage()["actors"]
        pcts = [r["coveragePct"] for r in rows]
        self.assertEqual(pcts, sorted(pcts, reverse=True))

    def test_coverage_by_content_is_present_and_bounded(self):
        """Each actor reports covered/total/pct per content type, covered <= total."""
        for actor in aggregations.threat_coverage()["actors"]:
            cbc = actor["coverageByContent"]
            self.assertEqual(set(cbc), {"emulations", "playbooks", "detections"})
            for block in cbc.values():
                self.assertLessEqual(block["covered"], block["total"])
            # An emulation backs all of its own techniques.
            self.assertEqual(cbc["emulations"]["covered"], cbc["emulations"]["total"])

    def test_scarleteel_content_backing_matches_artifacts(self):
        """scarleteel: 8 techniques, detections back 6, the playbook references 4."""
        rows = {r["id"]: r for r in aggregations.threat_coverage()["actors"]}
        cbc = rows["scarleteel"]["coverageByContent"]
        self.assertEqual(cbc["emulations"], {"covered": 8, "total": 8, "pct": 100.0})
        self.assertEqual(cbc["detections"]["covered"], 6)
        self.assertEqual(cbc["playbooks"]["covered"], 4)


class PlatformCoverageTests(SimpleTestCase):
    """Per-platform content depth, with all supported platforms represented."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        _ensure_registry_loaded()

    def test_all_supported_platforms_returned_by_default(self):
        payload = aggregations.platform_coverage()
        returned = {p["platform"] for p in payload["platforms"]}
        self.assertEqual(returned, set(aggregations.SUPPORTED_PLATFORMS))

    def test_aws_counts_reflect_scarleteel(self):
        payload = aggregations.platform_coverage()
        aws = next(p for p in payload["platforms"] if p["platform"] == "aws")
        self.assertGreaterEqual(aws["emulations"], 1)
        self.assertGreaterEqual(aws["playbooks"], 1)
        self.assertGreaterEqual(aws["detections"], 12)

    def test_platform_filter_restricts_result(self):
        payload = aggregations.platform_coverage("aws")
        self.assertEqual([p["platform"] for p in payload["platforms"]], ["aws"])


class NavigatorLayerTests(SimpleTestCase):
    """The exported ATT&CK Navigator layer is valid and reflects coverage."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        _ensure_registry_loaded()

    def test_layer_shape(self):
        layer = aggregations.navigator_layer()
        self.assertEqual(layer["domain"], "enterprise-attack")
        self.assertEqual(layer["versions"]["layer"], "4.5")
        # attack version is the major release, derived from the catalogue.
        self.assertEqual(layer["versions"]["attack"], catalog.attack_version().split(".", 1)[0])
        self.assertIsInstance(layer["techniques"], list)

    def test_technique_ids_are_known_parents(self):
        """Every exported ID is a normalised, catalogue-known parent technique."""
        covered = _expected_covered()
        ids = {t["techniqueID"] for t in aggregations.navigator_layer()["techniques"]}
        self.assertEqual(ids, covered)
        for tid in ids:
            self.assertNotIn(".", tid)
            self.assertTrue(catalog.is_known(tid))

    def test_entries_are_scored_and_commented(self):
        layer = aggregations.navigator_layer()
        t1190 = next(t for t in layer["techniques"] if t["techniqueID"] == "T1190")
        self.assertEqual(t1190["score"], 1)
        self.assertEqual(t1190["color"], aggregations.NAVIGATOR_COVERED_COLOR)
        self.assertIn("SCARLETEEL", t1190["comment"])


class CoverageSummaryTests(SimpleTestCase):
    """
    KPI summary.  EmulationRun is mocked so the suite stays DB-free (the project
    generates migrations at startup, so no test database is available); the run
    count and last-run query are exercised through the mock, while the
    registry-derived figures are checked against the live registry.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        _ensure_registry_loaded()

    def _mock_emulation_run(self, *, count: int, last_completed):
        """Build a MagicMock standing in for the EmulationRun model."""
        mock = MagicMock()
        mock.objects.count.return_value = count
        (
            mock.objects.filter.return_value.order_by.return_value.values_list.return_value.first
        ).return_value = last_completed
        mock.Status.COMPLETED = "completed"
        return mock

    def test_registry_derived_values_and_empty_runs(self):
        mock = self._mock_emulation_run(count=0, last_completed=None)
        with patch("apps.emulations.models.EmulationRun", mock):
            summary = aggregations.coverage_summary()

        self.assertEqual(summary["totalTechniques"], catalog.technique_count())
        self.assertEqual(summary["coveredTechniques"], len(_expected_covered()))
        self.assertEqual(summary["emulationsExecuted"], 0)
        self.assertIsNone(summary["lastSuccessfulRun"])
        expected_detections = sum(
            len(e.get("detection_files", []) or [])
            for e in registry_wrapper.list_emulations()
        )
        self.assertEqual(summary["detectionCoverage"], expected_detections)

    def test_last_successful_run_is_serialised(self):
        import datetime as dt

        when = dt.datetime(2026, 6, 16, 9, 30, tzinfo=dt.timezone.utc)
        mock = self._mock_emulation_run(count=184, last_completed=when)
        with patch("apps.emulations.models.EmulationRun", mock):
            summary = aggregations.coverage_summary()

        self.assertEqual(summary["emulationsExecuted"], 184)
        self.assertEqual(summary["lastSuccessfulRun"], when.isoformat())


class AttackSurfaceTests(SimpleTestCase):
    """The attack-surface taxonomy groups services correctly and drops nothing."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        _ensure_registry_loaded()

    def test_groups_known_services_and_others(self):
        entries = [
            {"services": ["IAM", "Kubernetes RBAC"]},
            {"services": ["S3", "Totally New Service"]},
        ]
        by_name = {c["name"]: c["services"] for c in aggregations._attack_surface(entries)}

        self.assertEqual(by_name["Identity & Access"], ["IAM", "Kubernetes RBAC"])
        self.assertEqual(by_name["Storage & Data"], ["S3"])
        # An unmapped service is never dropped; it lands in "Other".
        self.assertEqual(by_name["Other"], ["Totally New Service"])

    def test_categories_follow_declared_order(self):
        entries = [{"services": ["S3", "IAM", "Route53"]}]
        names = [c["name"] for c in aggregations._attack_surface(entries)]
        self.assertEqual(names, ["Identity & Access", "Storage & Data", "Networking"])

    def test_distinct_services_deduplicated_across_emulations(self):
        entries = [{"services": ["IAM"]}, {"services": ["IAM", "STS"]}]
        identity = next(
            c for c in aggregations._attack_surface(entries) if c["name"] == "Identity & Access"
        )
        self.assertEqual(identity["services"], ["IAM", "STS"])

    def test_platform_coverage_includes_attack_surface(self):
        row = next(
            p for p in aggregations.platform_coverage("k8s")["platforms"] if p["platform"] == "k8s"
        )
        self.assertIn("attackSurface", row)
        for category in row["attackSurface"]:
            self.assertIn("name", category)
            self.assertTrue(category["services"])
