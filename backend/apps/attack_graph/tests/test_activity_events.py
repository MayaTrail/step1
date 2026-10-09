"""
A scan appears in the activity trail.

LogEntry.Event is a closed enum, so a task writing "scan.completed" against an
enum that does not define it writes a row nothing renders. Every other
lifecycle action in the product shows up in the notification panel; a scan
that runs for ten minutes and leaves no trace is the odd one out.
"""

from django.test import SimpleTestCase

from apps.logs.models import LogEntry


class ScanEventTests(SimpleTestCase):
    """The enum members the scan task writes."""

    def test_the_three_scan_events_exist(self):
        self.assertEqual(LogEntry.Event.SCAN_STARTED, "scan.started")
        self.assertEqual(LogEntry.Event.SCAN_COMPLETED, "scan.completed")
        self.assertEqual(LogEntry.Event.SCAN_FAILED, "scan.failed")

    def test_they_are_selectable_choices(self):
        values = dict(LogEntry.Event.choices)
        for value in ("scan.started", "scan.completed", "scan.failed"):
            self.assertIn(value, values)
