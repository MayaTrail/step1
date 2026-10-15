"""
Tests for reading a run's alerts while it waits, and for ending the wait early.

A client watching a run needs two things before the window closes: proof that
their SIEM is reporting (the count and the bodies it posted), and a way to stop
waiting once it has reported everything. Both read the same attribution rule
the score uses, so these tests pin that the page and the score agree.

View tests need DRF, which requirements-test.txt omits, and settling imports
workflows.tasks and through it pulumi, so each suite skips where its
dependencies are absent and runs in the backend container.
"""

from __future__ import annotations

import unittest
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from apps.logs.models import LogEntry
from apps.workflows.models import AlertEndpoint, IngestedAlert, WorkflowRun

try:
    from rest_framework.test import APIRequestFactory, force_authenticate

    from apps.workflows.views import (
        WINDOW_ALERTS_SHOWN,
        WorkflowRunAlertsView,
        WorkflowRunDetailView,
        WorkflowRunSettleView,
    )

    HAS_DRF = True
except ImportError:  # pragma: no cover
    HAS_DRF = False

try:
    import pulumi  # noqa: F401

    HAS_PULUMI = True
except ImportError:  # pragma: no cover
    HAS_PULUMI = False

User = get_user_model()


def _user(name="deteng"):
    """Create a verified, non-demo user."""
    return User.objects.create_user(
        username=name, email=f"{name}@example.com", password="pw",
        is_verified=True, is_demo=False,
    )


def _endpoint(owner):
    """Create an enabled endpoint; the secret is irrelevant to these tests."""
    return AlertEndpoint.objects.create(owner=owner, name="SIEM", secret_encrypted=b"x")


def _waiting_run(owner, minutes_open=5, minutes_left=25):
    """Create a run whose alert window opened a few minutes ago and is still open."""
    now = timezone.now()
    return WorkflowRun.objects.create(
        owner=owner,
        emulation_type="codefinger",
        status=WorkflowRun.Status.AWAITING_ALERTS,
        window_start=now - timedelta(minutes=minutes_open),
        alert_deadline=now + timedelta(minutes=minutes_left),
    )


def _alert(endpoint, received_at, name="Rule", raw=None):
    """
    Store an alert as if it arrived at `received_at`.

    received_at is auto_now_add, so it is set by an update after the insert.
    """
    alert = IngestedAlert.objects.create(
        endpoint=endpoint, rule_name=name, technique="T1485", severity="high",
        raw=raw if raw is not None else {"ruleName": name},
    )
    IngestedAlert.objects.filter(id=alert.id).update(received_at=received_at)
    return alert


@unittest.skipUnless(HAS_DRF, "DRF not installed")
class WindowAlertsTests(TestCase):
    """GET /runs/<id>/ alertCount and GET /runs/<id>/alerts/."""

    def setUp(self):
        self.factory = APIRequestFactory()
        self.user = _user()
        self.endpoint = _endpoint(self.user)
        self.run = _waiting_run(self.user)

    def _get(self, view, run, user=None):
        """GET a run-scoped view as the given user."""
        request = self.factory.get("/api/workflows/runs/x/")
        force_authenticate(request, user=user or self.user)
        return view.as_view()(request, workflow_id=str(run.id))

    def test_count_includes_only_the_window(self):
        """An alert from before the window opened belongs to an earlier run."""
        now = timezone.now()
        _alert(self.endpoint, now - timedelta(minutes=1))
        _alert(self.endpoint, now - timedelta(minutes=2))
        _alert(self.endpoint, now - timedelta(hours=2))
        response = self._get(WorkflowRunDetailView, self.run)
        self.assertEqual(response.data["alertCount"], 2)

    def test_another_users_alerts_are_not_counted(self):
        """Attribution is by owner, so one tenant's SIEM never feeds another's run."""
        other = _user("someone-else")
        _alert(_endpoint(other), timezone.now() - timedelta(minutes=1))
        self.assertEqual(self._get(WorkflowRunDetailView, self.run).data["alertCount"], 0)

    def test_alerts_are_newest_first_with_their_bodies(self):
        """The reader is watching for what just arrived, and needs the body as posted."""
        now = timezone.now()
        _alert(self.endpoint, now - timedelta(minutes=3), name="older")
        _alert(self.endpoint, now - timedelta(minutes=1), name="newer", raw={"event": {"eventName": "X"}})
        data = self._get(WorkflowRunAlertsView, self.run).data
        self.assertEqual([a["ruleName"] for a in data["alerts"]], ["newer", "older"])
        self.assertEqual(data["alerts"][0]["raw"], {"event": {"eventName": "X"}})

    def test_bodies_are_capped_but_the_count_is_not(self):
        """Bodies can be 64 KB each; the count still says how many there were."""
        now = timezone.now()
        for i in range(WINDOW_ALERTS_SHOWN + 3):
            _alert(self.endpoint, now - timedelta(seconds=10 + i))
        data = self._get(WorkflowRunAlertsView, self.run).data
        self.assertEqual(data["count"], WINDOW_ALERTS_SHOWN + 3)
        self.assertEqual(len(data["alerts"]), WINDOW_ALERTS_SHOWN)

    def test_a_run_before_its_window_has_no_alerts(self):
        """Nothing is attributed until the attack has finished and the window opens."""
        run = WorkflowRun.objects.create(
            owner=self.user, emulation_type="codefinger", status=WorkflowRun.Status.ATTACKING,
        )
        _alert(self.endpoint, timezone.now())
        self.assertEqual(self._get(WorkflowRunAlertsView, run).data, {"count": 0, "alerts": []})

    def test_another_users_run_is_not_found(self):
        """Alert bodies come from the client's environment, so they are owner-scoped."""
        other = _user("someone-else")
        self.assertEqual(self._get(WorkflowRunAlertsView, self.run, user=other).status_code, 404)


@unittest.skipUnless(HAS_DRF and HAS_PULUMI, "DRF or pulumi not installed")
class SettleTests(TestCase):
    """POST /runs/<id>/settle/."""

    def setUp(self):
        self.factory = APIRequestFactory()
        self.user = _user()
        self.endpoint = _endpoint(self.user)

    def _settle(self, run, user=None):
        """POST to the settle view as the given user."""
        request = self.factory.post("/api/workflows/runs/x/settle/")
        force_authenticate(request, user=user or self.user)
        return WorkflowRunSettleView.as_view()(request, workflow_id=str(run.id))

    def test_a_waiting_run_is_scored_now(self):
        """The run completes with a score, without waiting for the deadline."""
        run = _waiting_run(self.user)
        _alert(self.endpoint, timezone.now() - timedelta(minutes=1))
        response = self._settle(run)
        self.assertEqual(response.status_code, 200)
        run.refresh_from_db()
        self.assertEqual(run.status, WorkflowRun.Status.COMPLETED)
        self.assertEqual(run.score["alertsReceived"], 1)
        self.assertLessEqual(run.alert_deadline, timezone.now())

    def test_alerts_after_stopping_are_not_counted(self):
        """The window closed when the owner stopped waiting, so later arrivals are outside it."""
        run = _waiting_run(self.user)
        self._settle(run)
        _alert(self.endpoint, timezone.now() + timedelta(seconds=5))
        run.refresh_from_db()
        self.assertEqual(run.window_alerts().count(), 0)

    def test_stopping_early_is_recorded(self):
        """A shorter window explains a lower score, so the trail has to say so."""
        self._settle(_waiting_run(self.user))
        entry = LogEntry.objects.get(event=LogEntry.Event.WORKFLOW_COMPLETED)
        self.assertIn("early", entry.message)

    def test_a_run_not_waiting_is_refused(self):
        """A second click, or a run the tick already scored, must not score it again."""
        run = _waiting_run(self.user)
        self._settle(run)
        response = self._settle(run)
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.data["reason"], "not_waiting")
        self.assertEqual(
            LogEntry.objects.filter(event=LogEntry.Event.WORKFLOW_COMPLETED).count(), 1
        )

    def test_another_users_run_is_not_found(self):
        """Owner-scoped, so someone else's run is 404 and stays open."""
        run = _waiting_run(self.user)
        self.assertEqual(self._settle(run, user=_user("someone-else")).status_code, 404)
        run.refresh_from_db()
        self.assertEqual(run.status, WorkflowRun.Status.AWAITING_ALERTS)
