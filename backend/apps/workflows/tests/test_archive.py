"""
Tests for archiving workflow runs, and for the deletion it deliberately refuses.

Archiving exists so a user can clear old runs out of the way. Deleting a
completed run would do that too, and is refused on purpose: reliability on the
coverage history page is a share of judged runs, so removing the runs where a
rule stayed silent raises that rule's figure. A detection would appear to
improve because the evidence of its failures was destroyed.

View tests need DRF, which requirements-test.txt omits, so they skip when it is
absent, matching the other suites.
"""

from __future__ import annotations

import unittest

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from apps.logs.models import LogEntry
from apps.workflows.models import WorkflowRun

try:
    from rest_framework.test import APIRequestFactory, force_authenticate

    from apps.workflows.views import (
        CoverageHistoryView,
        WorkflowRunDetailView,
        WorkflowRunListView,
    )

    HAS_DRF = True
except ImportError:  # pragma: no cover
    HAS_DRF = False

User = get_user_model()


def _enterprise_user(name="deteng"):
    """Create a verified, non-demo user, which is what IsEnterpriseUser wants."""
    return User.objects.create_user(
        username=name,
        email=f"{name}@example.com",
        password="pw",
        is_verified=True,
        is_demo=False,
    )


def _score(fired, silent):
    """Build a settled score payload with the given verdict counts."""
    rules = (
        [{"ruleId": f"t{i}", "title": f"Rule t{i}", "verdict": "fired",
          "severity": "high", "technique": f"T{i}"} for i in range(fired)]
        + [{"ruleId": f"s{i}", "title": f"Rule s{i}", "verdict": "silent",
            "severity": "high", "technique": f"S{i}"} for i in range(silent)]
    )
    return {
        "status": "ok",
        "rules": rules,
        "counts": {"fired": fired, "silent": silent, "not_integrated": 0},
        "ruleCount": fired + silent,
        "alertsReceived": fired,
    }


def _completed_run(owner, emulation="codefinger", *, fired=4, silent=1, archived=False):
    """Create a completed run, optionally already archived."""
    return WorkflowRun.objects.create(
        owner=owner,
        emulation_type=emulation,
        status=WorkflowRun.Status.COMPLETED,
        completed_at=timezone.now(),
        archived_at=timezone.now() if archived else None,
        score=_score(fired, silent),
    )


@unittest.skipUnless(HAS_DRF, "DRF not installed")
class ArchiveTests(TestCase):
    """PATCH /api/workflows/runs/<id>/ with {"archived": bool}."""

    def setUp(self):
        self.factory = APIRequestFactory()
        self.user = _enterprise_user()
        self.view = WorkflowRunDetailView.as_view()

    def _patch(self, run, body, user=None):
        """Send a PATCH to the detail view as the given user."""
        request = self.factory.patch("/api/workflows/runs/x/", body, format="json")
        force_authenticate(request, user=user or self.user)
        return self.view(request, workflow_id=str(run.id))

    def test_archiving_a_completed_run_succeeds(self):
        """The everyday action."""
        run = _completed_run(self.user)
        response = self._patch(run, {"archived": True})
        self.assertEqual(response.status_code, 200)
        run.refresh_from_db()
        self.assertIsNotNone(run.archived_at)

    def test_archiving_is_reversible(self):
        """Restoring puts the run back into history, which deletion cannot."""
        run = _completed_run(self.user, archived=True)
        response = self._patch(run, {"archived": False})
        self.assertEqual(response.status_code, 200)
        run.refresh_from_db()
        self.assertIsNone(run.archived_at)

    def test_archiving_keeps_the_report(self):
        """The evidence survives; only its visibility changed."""
        run = _completed_run(self.user)
        self._patch(run, {"archived": True})
        run.refresh_from_db()
        self.assertEqual(run.score["counts"]["fired"], 4)
        self.assertEqual(len(run.score["rules"]), 5)

    def test_an_in_flight_run_cannot_be_archived(self):
        """Hiding a live run would leave a deploy running with nothing tracking it."""
        run = WorkflowRun.objects.create(
            owner=self.user,
            emulation_type="codefinger",
            status=WorkflowRun.Status.AWAITING_ALERTS,
        )
        response = self._patch(run, {"archived": True})
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.data["reason"], "in_progress")

    def test_a_non_boolean_is_rejected(self):
        """A missing or string flag must not be read as truthy."""
        run = _completed_run(self.user)
        self.assertEqual(self._patch(run, {"archived": "yes"}).status_code, 400)
        self.assertEqual(self._patch(run, {}).status_code, 400)
        run.refresh_from_db()
        self.assertIsNone(run.archived_at)

    def test_another_users_run_is_not_found(self):
        """Owner-scoped, so someone else's run is 404 rather than 403."""
        other = _enterprise_user("someone-else")
        run = _completed_run(other)
        self.assertEqual(self._patch(run, {"archived": True}).status_code, 404)

    def test_archiving_is_recorded_in_the_activity_trail(self):
        """Archiving changes the figures shown, so the trail has to explain it."""
        run = _completed_run(self.user)
        self._patch(run, {"archived": True})
        self.assertTrue(
            LogEntry.objects.filter(event=LogEntry.Event.WORKFLOW_ARCHIVED).exists()
        )
        self._patch(run, {"archived": False})
        self.assertTrue(
            LogEntry.objects.filter(event=LogEntry.Event.WORKFLOW_RESTORED).exists()
        )

    def test_archiving_twice_writes_one_entry(self):
        """A no-op PATCH must not pad the audit trail."""
        run = _completed_run(self.user)
        self._patch(run, {"archived": True})
        self._patch(run, {"archived": True})
        self.assertEqual(
            LogEntry.objects.filter(event=LogEntry.Event.WORKFLOW_ARCHIVED).count(), 1
        )


@unittest.skipUnless(HAS_DRF, "DRF not installed")
class DeletionStaysRefusedTests(TestCase):
    """The rule archiving exists to avoid breaking."""

    def setUp(self):
        self.factory = APIRequestFactory()
        self.user = _enterprise_user()
        self.view = WorkflowRunDetailView.as_view()

    def _delete(self, run):
        request = self.factory.delete("/api/workflows/runs/x/")
        force_authenticate(request, user=self.user)
        return self.view(request, workflow_id=str(run.id))

    def test_a_completed_run_cannot_be_deleted(self):
        """Its report is the record of what the client's SIEM caught."""
        run = _completed_run(self.user)
        response = self._delete(run)
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.data["reason"], "completed")
        self.assertTrue(WorkflowRun.objects.filter(id=run.id).exists())

    def test_the_refusal_points_at_archiving(self):
        """A refusal without an alternative is a dead end."""
        run = _completed_run(self.user)
        self.assertIn("Archive", self._delete(run).data["detail"])

    def test_a_failed_run_is_still_deletable(self):
        """A failed run measured nothing, so there is no evidence to protect."""
        run = WorkflowRun.objects.create(
            owner=self.user,
            emulation_type="codefinger",
            status=WorkflowRun.Status.FAILED,
        )
        self.assertEqual(self._delete(run).status_code, 204)
        self.assertFalse(WorkflowRun.objects.filter(id=run.id).exists())


@unittest.skipUnless(HAS_DRF, "DRF not installed")
class ArchivedRunsAreHiddenTests(TestCase):
    """What archiving actually changes."""

    def setUp(self):
        self.factory = APIRequestFactory()
        self.user = _enterprise_user()

    def _list(self, query=""):
        request = self.factory.get(f"/api/workflows/runs/{query}")
        force_authenticate(request, user=self.user)
        return WorkflowRunListView.as_view()(request)

    def _coverage(self, query="?emulation=codefinger"):
        request = self.factory.get(f"/api/workflows/coverage/{query}")
        force_authenticate(request, user=self.user)
        return CoverageHistoryView.as_view()(request)

    def test_archived_runs_drop_out_of_the_list(self):
        """The clutter problem archiving was asked for."""
        _completed_run(self.user)
        _completed_run(self.user, archived=True)
        self.assertEqual(len(self._list().data["runs"]), 1)

    def test_archived_runs_can_be_asked_for(self):
        """Hidden, never gone."""
        _completed_run(self.user)
        _completed_run(self.user, archived=True)
        self.assertEqual(len(self._list("?archived=true").data["runs"]), 2)

    def test_archived_runs_leave_coverage_history(self):
        """Archiving one of two runs halves the judged count."""
        _completed_run(self.user, fired=4, silent=1)
        _completed_run(self.user, fired=4, silent=1, archived=True)
        data = self._coverage().data
        self.assertEqual(data["counts"]["runs"], 1)
        self.assertEqual(data["counts"]["judged"], 1)

    def test_archiving_every_run_still_leaves_a_route_back(self):
        """
        The page builds its emulation selector from the archived list too, so
        archiving everything must not make the emulation itself unreachable.
        """
        _completed_run(self.user, archived=True)
        _completed_run(self.user, archived=True)
        self.assertEqual(len(self._list().data["runs"]), 0)
        restorable = self._list("?archived=true").data["runs"]
        self.assertEqual(len(restorable), 2)
        self.assertTrue(all(run["archivedAt"] for run in restorable))

    def test_the_list_reports_when_a_run_was_archived(self):
        """The panel shows an archived date, so the field has to be serialised."""
        _completed_run(self.user, archived=True)
        run = self._list("?archived=true").data["runs"][0]
        self.assertIsNotNone(run["archivedAt"])

    def test_coverage_needs_an_emulation(self):
        """Without one there is no history to build."""
        self.assertEqual(self._coverage("").status_code, 400)

    def test_an_emulation_with_no_runs_is_an_empty_page_not_a_404(self):
        """A legitimate page that happens to be empty."""
        response = self._coverage("?emulation=never-run")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["runs"], [])

    def test_failed_runs_are_not_coverage_history(self):
        """A failed run never attacked, so it measured nothing."""
        WorkflowRun.objects.create(
            owner=self.user,
            emulation_type="codefinger",
            status=WorkflowRun.Status.FAILED,
            completed_at=timezone.now(),
        )
        self.assertEqual(self._coverage().data["counts"]["runs"], 0)

    def test_another_users_runs_are_not_counted(self):
        """Coverage history is owner-scoped like every other workflow route."""
        other = _enterprise_user("someone-else")
        _completed_run(other)
        self.assertEqual(self._coverage().data["counts"]["runs"], 0)
