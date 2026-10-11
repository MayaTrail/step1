"""
A scan appears in the activity trail.

LogEntry.Event is a closed enum, so a task writing an event value against an
enum that does not define it writes a row nothing renders. Every other
lifecycle action in the product shows up in the notification panel; a scan
that runs for ten minutes and leaves no trace is the odd one out.
"""

from django.test import SimpleTestCase

from apps.logs.models import LogEntry


class ScanEventTests(SimpleTestCase):
    """The enum members the scan task writes."""

    VALUES = {
        "SCAN_STARTED": "attack_graph.scan_started",
        "SCAN_COMPLETED": "attack_graph.scan_completed",
        "SCAN_FAILED": "attack_graph.scan_failed",
        "SCAN_DELETED": "attack_graph.scan_deleted",
    }

    def test_the_scan_events_exist_under_the_feature_prefix(self):
        # Prefixed because the guardrail check is also a kind of scan, and an
        # unprefixed "scan.started" in the trail would not say which.
        for member, value in self.VALUES.items():
            self.assertEqual(getattr(LogEntry.Event, member), value)

    def test_they_are_selectable_choices(self):
        values = dict(LogEntry.Event.choices)
        for value in self.VALUES.values():
            self.assertIn(value, values)
