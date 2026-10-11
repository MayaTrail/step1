"""
The /api/stacks/ surface is read-only.

The generic write actions it once had read Pulumi state from a shared bucket
instead of the user's own, so a destroy deleted the record and left the AWS
resources running. These tests keep them from coming back: a stack is created
and torn down only through /api/emulations/.
"""

import unittest

from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.infrastructure.models import Stack

try:
    from rest_framework.test import APIClient
    HAS_DRF = True
except ImportError:  # DRF is not installed under config.settings.ci
    HAS_DRF = False


@unittest.skipUnless(HAS_DRF, "DRF is not installed under config.settings.ci")
class StackApiTests(TestCase):
    """What /api/stacks/ answers for a verified user who owns one stack."""

    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="owner", email="owner@example.com", password="x",
            aws_role_arn="arn:aws:iam::111122223333:role/mayatrail-connected",
            is_verified=True,
        )
        self.stack = Stack.objects.create(
            owner=self.user, name="scarleteel-test", emulation_type="scarleteel",
            status=Stack.Status.READY_FOR_ATTACK,
        )
        self.client = APIClient()
        self.client.force_authenticate(self.user)

    def test_list_detail_and_progress_still_answer(self):
        """The emulation lifecycle polls these while a stack deploys."""
        base = f"/api/stacks/{self.stack.id}/"
        self.assertEqual(self.client.get("/api/stacks/").status_code, 200)
        self.assertEqual(self.client.get(base).status_code, 200)
        self.assertEqual(self.client.get(f"{base}progress/").status_code, 200)

    def test_no_write_reaches_a_stack(self):
        """Create, the old actions and delete are all refused, and the stack is untouched."""
        base = f"/api/stacks/{self.stack.id}/"
        self.assertEqual(self.client.post("/api/stacks/", {"name": "x"}).status_code, 405)
        for path in ("deploy/", "destroy/", "force-destroy/", "refresh/", "preview/"):
            self.assertEqual(self.client.post(f"{base}{path}").status_code, 404, path)
        self.assertEqual(self.client.delete(base).status_code, 405)
        self.assertEqual(self.client.patch(base, {"name": "y"}).status_code, 405)
        self.stack.refresh_from_db()
        self.assertEqual(self.stack.status, Stack.Status.READY_FOR_ATTACK)

    def test_the_demo_lookup_is_gone(self):
        """GET /api/stacks/demo/ is now just an unknown stack id."""
        self.assertEqual(self.client.get("/api/stacks/demo/").status_code, 404)
