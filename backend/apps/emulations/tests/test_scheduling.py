"""
Tests for the scheduled-run cadence logic.

Pure date arithmetic (apps/emulations/scheduling.py). The Beat task itself
(run_scheduled_emulations) reuses the deploy pipeline and needs a worker and
AWS to do anything, so it is not exercised here; the schedule *selection and
advancement* - which decides what fires and when - is.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from django.test import SimpleTestCase

from apps.emulations import scheduling

NOW = datetime(2026, 1, 15, 12, 0, tzinfo=timezone.utc)


class NextAfterTests(SimpleTestCase):
    """The first run time for a new schedule."""

    def test_intervals(self):
        self.assertEqual(scheduling.next_after("daily", NOW), NOW + timedelta(days=1))
        self.assertEqual(scheduling.next_after("weekly", NOW), NOW + timedelta(weeks=1))
        self.assertEqual(scheduling.next_after("monthly", NOW), NOW + timedelta(days=30))

    def test_unknown_cadence_falls_back_to_weekly(self):
        """A bad stored cadence must not wedge the Beat task."""
        self.assertEqual(scheduling.next_after("fortnightly", NOW), NOW + timedelta(weeks=1))


class AdvanceTests(SimpleTestCase):
    """Advancing a due schedule past now."""

    def test_advances_one_step_when_just_due(self):
        current = NOW - timedelta(minutes=5)
        self.assertEqual(scheduling.advance(current, "weekly", NOW), current + timedelta(weeks=1))

    def test_keeps_cadence_phase(self):
        """
        A weekly schedule stays on its original weekday rather than resetting to
        now + 7 days, so 'every Monday' does not drift to whenever it last ran.
        """
        monday = datetime(2026, 1, 5, 9, 0, tzinfo=timezone.utc)  # a Monday
        now = datetime(2026, 1, 20, 15, 0, tzinfo=timezone.utc)   # 2+ weeks later
        nxt = scheduling.advance(monday, "weekly", now)
        self.assertGreater(nxt, now)
        self.assertEqual(nxt.weekday(), monday.weekday())  # still a Monday

    def test_catches_up_without_bursting(self):
        """
        A schedule stale by many intervals advances to a single future time, not
        a backlog of past times that would fire a burst of runs.
        """
        stale = NOW - timedelta(days=90)
        nxt = scheduling.advance(stale, "daily", NOW)
        self.assertGreater(nxt, NOW)
        self.assertLessEqual(nxt, NOW + timedelta(days=1))

    def test_future_schedule_is_untouched(self):
        future = NOW + timedelta(days=3)
        self.assertEqual(scheduling.advance(future, "daily", NOW), future)


class IsDueTests(SimpleTestCase):
    """The due check."""

    def test_due_when_past(self):
        self.assertTrue(scheduling.is_due(NOW - timedelta(seconds=1), NOW))

    def test_not_due_when_future(self):
        self.assertFalse(scheduling.is_due(NOW + timedelta(seconds=1), NOW))
