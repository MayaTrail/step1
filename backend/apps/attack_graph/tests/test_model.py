"""
What a scan row records.

The status vocabulary is asserted against EmulationRun's rather than against a
literal list: the frontend reads both through the same status chips, and a
scan that reports "succeeded" where a run reports "completed" produces a row
that renders as unknown with no error anywhere.
"""

from django.test import SimpleTestCase

from apps.attack_graph.models import (
    ACTIVE_SCAN_STATUSES,
    SCAN_STALE_AFTER_SECONDS,
    ScoutScan,
)
from apps.attack_graph.constants import SCAN_TIME_LIMIT
from apps.emulations.models import EmulationRun


class ScoutScanShapeTests(SimpleTestCase):
    """Model shape, without touching the database."""

    def test_status_vocabulary_matches_emulation_runs(self):
        self.assertEqual(
            sorted(ScoutScan.Status.values),
            sorted(EmulationRun.Status.values),
        )

    def test_newest_scans_come_first(self):
        self.assertEqual(ScoutScan._meta.ordering, ["-created_at"])

    def test_a_running_scan_can_be_traced_to_its_celery_task(self):
        self.assertTrue(ScoutScan._meta.get_field("task_id").blank)

    def test_lifecycle_timestamps_start_empty(self):
        for name in ("started_at", "completed_at"):
            self.assertTrue(ScoutScan._meta.get_field(name).null, name)

    def test_a_result_is_absent_until_there_is_one(self):
        self.assertTrue(ScoutScan._meta.get_field("result").null)


class StaleScanTests(SimpleTestCase):
    """
    The rule that keeps a dead scan from locking a user out.

    Two endpoints refuse a request while a scan is active: the trigger, and
    disconnecting the audit role. Celery's hard time_limit kills the worker
    process outright, so a crashed scan never runs its own failure handler and
    never reaches a terminal status — and a scan the worker never picked up
    sits at "pending" indefinitely. Keyed on status alone, one such row would
    refuse both endpoints forever, with no way out from the UI. These tests
    assert the cutoff exists and is wide enough not to cut off a live scan.
    """

    def test_active_means_pending_or_running(self):
        self.assertEqual(
            sorted(ACTIVE_SCAN_STATUSES),
            [ScoutScan.Status.PENDING, ScoutScan.Status.RUNNING],
        )

    def test_a_scan_is_stale_only_after_the_hard_time_limit(self):
        # Below the hard limit and the cutoff would reap a scan that is still
        # legitimately running, letting a second one start beside it.
        self.assertGreater(SCAN_STALE_AFTER_SECONDS, SCAN_TIME_LIMIT)

    def test_the_cutoff_is_not_so_wide_it_never_fires(self):
        # An hour of lockout after a worker crash is already unpleasant. This
        # is a sanity bound, not a tuned value.
        self.assertLessEqual(SCAN_STALE_AFTER_SECONDS, 3600)
