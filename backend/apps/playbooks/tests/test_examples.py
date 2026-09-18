"""
Tests for the starter example playbooks.

The template example is authored in this repo and always seeds. The forked
example needs the emulation packages on disk, so it is allowed to be absent -
the tests assert the degradation is graceful rather than requiring the fork.
"""

from __future__ import annotations

from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.playbooks.examples import TEMPLATE_TITLE, seed_examples
from apps.playbooks.models import Playbook
from apps.playbooks.sources import PlaybookSourceError
from apps.playbooks.tests import make_user

User = get_user_model()


class SeedExamplesTests(TestCase):
    """Seeding behaviour."""

    def _user(self, name: str = "newcomer"):
        """Create a user without tripping the post_save seeding signal."""
        return make_user(name)

    def test_template_is_always_seeded(self):
        """The annotated template needs nothing from disk, so it always lands."""
        user = self._user()
        with mock.patch(
            "apps.playbooks.examples.load_shipped_playbook",
            side_effect=PlaybookSourceError("no packages here"),
        ):
            created = seed_examples(user)

        self.assertEqual(len(created), 1)
        self.assertEqual(created[0].title, TEMPLATE_TITLE)
        self.assertTrue(created[0].is_example)

    def test_both_examples_seed_when_packages_are_available(self):
        """With the emulation packages present, the user gets template + fork."""
        user = self._user()
        with mock.patch(
            "apps.playbooks.examples.load_shipped_playbook",
            return_value=("Codefinger", "# IR Playbook: Codefinger\n\n## 1. Preparation\n"),
        ):
            created = seed_examples(user)

        self.assertEqual(len(created), 2)
        forked = [p for p in created if p.is_fork]
        self.assertEqual(len(forked), 1)
        self.assertEqual(forked[0].source_emulation, "codefinger")
        self.assertTrue(all(p.is_example for p in created))

    def test_template_demonstrates_every_block_type(self):
        """
        The template's whole job is to show what each block is for, so it must
        actually contain one of each - a phase, a step, a command and a
        decision. A future edit that drops one silently makes it a worse
        teaching tool, and nothing else would catch that.
        """
        user = self._user()
        with mock.patch(
            "apps.playbooks.examples.load_shipped_playbook",
            side_effect=PlaybookSourceError("skip the fork"),
        ):
            body = seed_examples(user)[0].body

        self.assertIn("\n## ", body)          # phase
        self.assertIn("\n#### Step ", body)   # step
        self.assertIn("```bash", body)        # command
        self.assertIn("**Decision - ", body)  # decision
        self.assertIn("| If | Then |", body)  # decision branches

    def test_seeding_is_idempotent(self):
        """A user who already has playbooks is left alone."""
        user = self._user()
        with mock.patch(
            "apps.playbooks.examples.load_shipped_playbook",
            side_effect=PlaybookSourceError("skip"),
        ):
            first = seed_examples(user)
            second = seed_examples(user)

        self.assertEqual(len(first), 1)
        self.assertEqual(second, [])
        self.assertEqual(Playbook.objects.filter(owner=user).count(), 1)

    def test_deleted_examples_are_not_resurrected(self):
        """
        Someone who deletes the examples and writes their own must not have the
        examples pushed back at them by a later backfill.
        """
        user = self._user()
        with mock.patch(
            "apps.playbooks.examples.load_shipped_playbook",
            side_effect=PlaybookSourceError("skip"),
        ):
            seed_examples(user)
        Playbook.objects.filter(owner=user, is_example=True).delete()
        Playbook.objects.create(owner=user, title="My own")

        with mock.patch(
            "apps.playbooks.examples.load_shipped_playbook",
            side_effect=PlaybookSourceError("skip"),
        ):
            self.assertEqual(seed_examples(user), [])
        self.assertEqual(Playbook.objects.filter(owner=user).count(), 1)


class SeedSignalTests(TestCase):
    """The post_save hook that seeds on signup."""

    def test_new_user_is_seeded(self):
        """Creating a user seeds their library."""
        with mock.patch(
            "apps.playbooks.examples.load_shipped_playbook",
            side_effect=PlaybookSourceError("skip the fork"),
        ):
            user = User.objects.create_user(
                username="fresh", email="fresh@example.com", password="pw"
            )
        self.assertEqual(Playbook.objects.filter(owner=user).count(), 1)

    def test_signup_survives_a_seeding_failure(self):
        """
        A user must still be created when seeding blows up. Losing a signup
        because an example playbook could not be written would be a far worse
        outcome than an empty library.
        """
        with mock.patch(
            "apps.playbooks.examples.seed_examples",
            side_effect=RuntimeError("database on fire"),
        ):
            user = User.objects.create_user(
                username="unlucky", email="unlucky@example.com", password="pw"
            )
        self.assertTrue(User.objects.filter(pk=user.pk).exists())
        self.assertEqual(Playbook.objects.filter(owner=user).count(), 0)

    def test_saving_an_existing_user_does_not_reseed(self):
        """Only creation seeds; a later save must not add more."""
        with mock.patch(
            "apps.playbooks.examples.load_shipped_playbook",
            side_effect=PlaybookSourceError("skip"),
        ):
            user = User.objects.create_user(
                username="returning", email="returning@example.com", password="pw"
            )
            user.first_name = "Changed"
            user.save()
        self.assertEqual(Playbook.objects.filter(owner=user).count(), 1)
