"""
The scan task, with the Scout service and AWS replaced.

The service's reply is a real Scout report (fixtures/scout_report.json), so
the task's hand-off to the envelope runs for real. What is checked is the row
each outcome leaves behind, the activity trail, and that the service is told
to drop a result once it is stored.
"""

import json
from pathlib import Path
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.attack_graph import scout_client, tasks
from apps.attack_graph.models import ScoutScan
from apps.logs.models import LogEntry

FIXTURES = Path(__file__).resolve().parent / "fixtures"
CREDS = {"AWS_ACCESS_KEY_ID": "a", "AWS_SECRET_ACCESS_KEY": "b", "AWS_SESSION_TOKEN": "c"}
GRAPH = {"nodes": [{"id": "arn:aws:iam::111122223333:user/alice", "type": "IAM_USER"}], "edges": []}


def _completed_outcome() -> dict:
    return {
        "status": "completed",
        "account_id": "111122223333",
        "collection": {"mode": "account", "coverage": None},
        "report": json.loads((FIXTURES / "scout_report.json").read_text("utf-8")),
        "graph": GRAPH,
    }


class RunScoutScanTests(TestCase):
    """Every way a scan can end."""

    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="auditor", email="auditor@example.com", password="x",
            aws_audit_role_arn="arn:aws:iam::111122223333:role/scout-audit",
            aws_audit_regions=["us-east-1"],
        )
        self.scan = ScoutScan.objects.create(user=self.user)
        self.patches = {
            "creds": mock.patch.object(tasks, "_audit_credentials", return_value=CREDS),
            "start": mock.patch.object(scout_client, "start_scan", return_value="svc-1"),
            "wait": mock.patch.object(scout_client, "wait_for_scan", return_value=_completed_outcome()),
            "delete": mock.patch.object(scout_client, "delete_scan"),
        }
        self.mocks = {name: patch.start() for name, patch in self.patches.items()}
        self.addCleanup(mock.patch.stopall)

    def _run(self) -> ScoutScan:
        tasks.run_scout_scan(str(self.scan.id))
        return ScoutScan.objects.get(id=self.scan.id)

    def _events(self) -> list[str]:
        return list(LogEntry.objects.filter(actor=self.user).order_by("timestamp").values_list("event", flat=True))

    def test_a_completed_scan_stores_the_envelope_and_the_graph(self):
        scan = self._run()
        self.assertEqual(scan.status, ScoutScan.Status.COMPLETED)
        self.assertEqual(scan.result["state"], "findings")
        self.assertEqual(scan.result["regions"], ["us-east-1"])
        self.assertEqual(scan.graph, GRAPH)
        self.mocks["start"].assert_called_once_with(CREDS, ["us-east-1"], narrate_top=25)
        self.mocks["delete"].assert_called_once_with("svc-1")
        self.assertEqual(self._events(), [LogEntry.Event.SCAN_STARTED, LogEntry.Event.SCAN_COMPLETED])

    def test_a_scan_the_service_failed_keeps_its_reason(self):
        self.mocks["wait"].return_value = {"status": "failed", "error": "The security token included in the request is invalid"}
        scan = self._run()
        self.assertEqual(scan.status, ScoutScan.Status.FAILED)
        self.assertEqual(scan.error_message, "The security token included in the request is invalid")
        self.mocks["delete"].assert_called_once_with("svc-1")
        self.assertEqual(self._events()[-1], LogEntry.Event.SCAN_FAILED)

    def test_an_unreachable_service_fails_the_scan_with_its_message(self):
        self.mocks["start"].side_effect = scout_client.ScoutServiceError(scout_client.UNREACHABLE)
        scan = self._run()
        self.assertEqual(scan.status, ScoutScan.Status.FAILED)
        self.assertEqual(scan.error_message, scout_client.UNREACHABLE)
        self.mocks["delete"].assert_not_called()

    def test_a_role_that_cannot_be_assumed_fails_with_the_aws_reason(self):
        self.mocks["creds"].side_effect = tasks.ScanFailure("not authorized to perform sts:AssumeRole")
        scan = self._run()
        self.assertEqual(scan.error_message, "not authorized to perform sts:AssumeRole")
        self.mocks["start"].assert_not_called()

    def test_an_unexpected_error_shows_the_generic_message(self):
        self.mocks["wait"].side_effect = RuntimeError("internal detail")
        with self.assertLogs("apps.attack_graph.tasks", level="ERROR"):
            scan = self._run()
        self.assertEqual(scan.error_message, tasks.UNEXPECTED_FAILURE_MESSAGE)
        self.mocks["delete"].assert_called_once_with("svc-1")
