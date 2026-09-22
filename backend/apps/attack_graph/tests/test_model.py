"""
What a scan row records.

The status vocabulary is asserted against EmulationRun's rather than against a
literal list: the frontend reads both through the same status chips, and a
scan that reports "succeeded" where a run reports "completed" produces a row
that renders as unknown with no error anywhere.
"""

import pathlib
import re
import unittest

from django.test import SimpleTestCase

from apps.attack_graph.models import (
    ACTIVE_SCAN_STATUSES,
    SCAN_STALE_AFTER_SECONDS,
    ScoutScan,
)
from apps.attack_graph.constants import SCAN_TIME_LIMIT
from apps.emulations.models import EmulationRun

try:
    from apps.attack_graph.serializers import (
        ScoutScanDetailSerializer,
        ScoutScanListSerializer,
    )
    HAS_DRF = True
except ImportError:  # DRF is not installed under config.settings.ci
    HAS_DRF = False


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


class GraphFieldTests(SimpleTestCase):
    """
    ScoutScan.graph holds Scout's own Graph.to_dict(), and never reaches the
    polled endpoints.

    Nullable is the permanent state for every scan stored before this field
    existed — nothing backfills them, so `None` is normal rather than a bug.
    """

    def test_graph_is_nullable_and_defaults_to_none(self):
        field = ScoutScan._meta.get_field("graph")
        self.assertTrue(field.null)
        self.assertTrue(field.blank)
        self.assertIsNone(ScoutScan().graph)

    @unittest.skipUnless(HAS_DRF, "DRF is not installed under config.settings.ci")
    def test_the_detail_serializer_never_returns_the_graph(self):
        # Necessary, not sufficient — see the queryset test below. This one is
        # what stops a later fields = "__all__".
        self.assertNotIn("graph", ScoutScanDetailSerializer.Meta.fields)

    @unittest.skipUnless(HAS_DRF, "DRF is not installed under config.settings.ci")
    def test_the_list_serializer_never_returns_the_graph(self):
        self.assertNotIn("graph", ScoutScanListSerializer.Meta.fields)

    def test_the_polled_querysets_defer_the_graph(self):
        # Keeping `graph` out of Meta.fields stops DRF rendering it. It does
        # NOT stop Django fetching it: ScoutScanDetailView.get and
        # ScoutScanListView.get_queryset are bare filter() calls, i.e.
        # SELECT *, so without .defer() the blob is read out of Postgres and
        # deserialized by psycopg on every 3s poll and for every row of the
        # history strip — with the serializer tests above passing throughout.
        # There is no DRF pagination configured, so the list is every scan the
        # user has ever run.
        source = (
            pathlib.Path(__file__).resolve().parents[1] / "views.py"
        ).read_text(encoding="utf-8")
        # Two call sites, counted rather than merely present: a later view
        # that queries ScoutScan without deferring is exactly the regression,
        # and `assertIn` would not notice it. Keep the literal out of the
        # comments in views.py or this count stops meaning what it says.
        self.assertEqual(source.count('.defer("graph")'), 2)

    def test_the_serializer_fields_lists_do_not_mention_graph(self):
        # The skipUnless tests above do not run in CI. This one does: it reads
        # the file, so the invariant is defended where DRF is absent.
        #
        # Scoped to the two `fields = [...]` lists rather than the whole file:
        # Task 10 adds documentation, and a grep for the bare word over the
        # whole source would fail on an explanatory comment that happens to
        # quote it.
        source = (
            pathlib.Path(__file__).resolve().parents[1] / "serializers.py"
        ).read_text(encoding="utf-8")
        for block in re.findall(r"fields = \[[^\]]*\]", source):
            self.assertNotIn("graph", block)
