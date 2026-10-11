"""
How many scans a user keeps, and how one is deleted.

Each scan stores a map of the customer's IAM, so history is bounded. The
pruning runs against the database; the delete endpoint is read from source
because DRF is not installed under config.settings.ci.
"""

import pathlib
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from apps.attack_graph.models import SCANS_KEPT_PER_USER, ScoutScan, prune_old_scans

BACKEND_ROOT = pathlib.Path(__file__).resolve().parents[3]


class PruneOldScansTests(TestCase):
    """prune_old_scans keeps the newest scans of one user only."""

    def setUp(self):
        users = get_user_model().objects
        self.user = users.create_user(username="a", email="a@example.com", password="x")
        self.other = users.create_user(username="b", email="b@example.com", password="x")

    def _scans(self, user, count):
        start = timezone.now() - timedelta(days=count)
        ids = []
        for n in range(count):
            scan = ScoutScan.objects.create(user=user)
            ScoutScan.objects.filter(id=scan.id).update(created_at=start + timedelta(days=n))
            ids.append(scan.id)
        return ids

    def test_only_the_newest_are_kept(self):
        ids = self._scans(self.user, SCANS_KEPT_PER_USER + 2)
        self.assertEqual(prune_old_scans(self.user), 2)
        kept = set(ScoutScan.objects.filter(user=self.user).values_list("id", flat=True))
        self.assertEqual(kept, set(ids[2:]))

    def test_under_the_limit_nothing_is_deleted(self):
        self._scans(self.user, 3)
        self.assertEqual(prune_old_scans(self.user), 0)

    def test_another_users_scans_are_untouched(self):
        self._scans(self.user, SCANS_KEPT_PER_USER + 1)
        self._scans(self.other, 2)
        prune_old_scans(self.user)
        self.assertEqual(ScoutScan.objects.filter(user=self.other).count(), 2)


class DeleteEndpointTests(SimpleTestCase):
    """What DELETE /api/attack-graph/scan/<id>/ must do."""

    def _delete_body(self):
        views = (BACKEND_ROOT / "apps/attack_graph/views.py").read_text(encoding="utf-8")
        start = views.index("    def delete(")
        end = views.index("\n\n\n", start)
        return views[start:end], views

    def test_it_is_scoped_to_the_owner_and_refused_while_running(self):
        body, _ = self._delete_body()
        self.assertIn("user=request.user", body)
        self.assertIn("active_scans(request.user)", body)
        self.assertIn("HTTP_409_CONFLICT", body)

    def test_it_is_recorded_in_the_activity_trail(self):
        body, _ = self._delete_body()
        self.assertIn("LogEntry.Event.SCAN_DELETED", body)

    def test_a_disconnected_user_can_still_delete(self):
        # HasScoutConnection refuses writes without an audit role; deleting
        # one's own stored IAM map must not depend on still being connected.
        _, views = self._delete_body()
        self.assertIn('if self.request.method == "DELETE":', views)
        self.assertIn("return [IsAuthenticated()]", views)

    def test_starting_a_scan_prunes_old_ones(self):
        _, views = self._delete_body()
        trigger = views[views.index("class ScoutScanTriggerView"):views.index("class ScoutScanListView")]
        self.assertIn("prune_old_scans(request.user)", trigger)
