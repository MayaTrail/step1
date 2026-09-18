"""
Tests for the playbooks app.

Model and serializer behaviour runs everywhere. The view tests need DRF, which
requirements-test.txt deliberately omits, so they skip when it is absent - the
same pattern the detection-validator test uses for pySigma. Install
requirements.txt as well to run the whole file.
"""

from __future__ import annotations

import unittest

from django.test import TestCase

from apps.playbooks.models import Playbook
from apps.playbooks.tests import make_user

try:
    # Import the module under test, not merely `rest_framework`. Importing any
    # DRF view module also resolves DEFAULT_AUTHENTICATION_CLASSES, which pulls
    # in simplejwt, so a narrower probe would pass here and then fail inside the
    # test body.
    from apps.playbooks import serializers as _serializers  # noqa: F401
    from apps.playbooks import views as _views  # noqa: F401

    HAS_DRF = True
except ImportError:  # pragma: no cover - exercised only on the slim test env
    HAS_DRF = False



class PlaybookModelTests(TestCase):
    """Model-level behaviour."""

    @classmethod
    def setUpTestData(cls):
        """Create an author shared by every test in the class."""
        cls.user = make_user("responder")

    def test_slug_is_derived_from_title(self):
        """save() fills the slug from the title."""
        pb = Playbook.objects.create(owner=self.user, title="AMBERSQUID - our response")
        self.assertEqual(pb.slug, "ambersquid-our-response")

    def test_slug_follows_a_retitle(self):
        """The slug is recomputed on every save, not only the first."""
        pb = Playbook.objects.create(owner=self.user, title="First name")
        pb.title = "Second name"
        pb.save()
        self.assertEqual(pb.slug, "second-name")

    def test_is_fork_reflects_source_emulation(self):
        """is_fork is True only for playbooks seeded from a shipped one."""
        scratch = Playbook.objects.create(owner=self.user, title="From scratch")
        forked = Playbook.objects.create(
            owner=self.user, title="Forked", source_emulation="ambersquid"
        )
        self.assertFalse(scratch.is_fork)
        self.assertTrue(forked.is_fork)

    def test_defaults_are_private_draft(self):
        """A new playbook is nobody else's business until the author says so."""
        pb = Playbook.objects.create(owner=self.user, title="Draft")
        self.assertEqual(pb.status, Playbook.Status.DRAFT)
        self.assertEqual(pb.visibility, Playbook.Visibility.PRIVATE)

    def test_ordering_is_most_recently_edited_first(self):
        """Meta.ordering puts the freshest edit at the top of a listing."""
        older = Playbook.objects.create(owner=self.user, title="Older")
        newer = Playbook.objects.create(owner=self.user, title="Newer")
        older.summary = "touched"
        older.save()
        self.assertEqual(
            list(Playbook.objects.values_list("title", flat=True)), ["Older", "Newer"]
        )
        self.assertEqual(newer.title, "Newer")


@unittest.skipUnless(HAS_DRF, "djangorestframework is not installed")
class PlaybookSerializerTests(TestCase):
    """Validation rules that guard the stored document."""

    @classmethod
    def setUpTestData(cls):
        """Create an author shared by every test in the class."""
        cls.user = make_user("author")

    def test_blank_title_is_rejected(self):
        """A whitespace-only title is not a title."""
        from apps.playbooks.serializers import PlaybookSerializer

        s = PlaybookSerializer(data={"title": "   ", "body": "x"})
        self.assertFalse(s.is_valid())
        self.assertIn("title", s.errors)

    def test_oversized_body_is_rejected(self):
        """The body cap keeps a runaway paste out of the table."""
        from apps.playbooks.serializers import MAX_BODY_BYTES, PlaybookSerializer

        s = PlaybookSerializer(data={"title": "Big", "body": "a" * (MAX_BODY_BYTES + 1)})
        self.assertFalse(s.is_valid())
        self.assertIn("body", s.errors)

    def test_fork_rejects_a_traversing_emulation_name(self):
        """emulation_type becomes a path segment, so separators are refused."""
        from apps.playbooks.serializers import PlaybookForkSerializer

        for bad in ["../../etc", "a/b", "a\\b", ".hidden"]:
            with self.subTest(value=bad):
                s = PlaybookForkSerializer(data={"emulation_type": bad})
                self.assertFalse(s.is_valid(), "%r should be rejected" % bad)

    def test_fork_accepts_a_bare_package_name(self):
        """A normal package name passes."""
        from apps.playbooks.serializers import PlaybookForkSerializer

        s = PlaybookForkSerializer(data={"emulation_type": "ambersquid"})
        self.assertTrue(s.is_valid(), s.errors)

    def test_list_serializer_omits_the_body(self):
        """Listing playbooks must not ship every document with it."""
        from apps.playbooks.serializers import PlaybookListSerializer

        pb = Playbook.objects.create(
            owner=self.user, title="Has a body", body="# lots of markdown"
        )
        self.assertNotIn("body", PlaybookListSerializer(pb).data)


@unittest.skipUnless(HAS_DRF, "djangorestframework is not installed")
class PlaybookVisibilityTests(TestCase):
    """Who can see and change what."""

    @classmethod
    def setUpTestData(cls):
        """Two unrelated users and one playbook each."""
        cls.alice = make_user("alice")
        cls.bob = make_user("bob")
        cls.alice_private = Playbook.objects.create(
            owner=cls.alice, title="Alice private"
        )
        cls.alice_shared = Playbook.objects.create(
            owner=cls.alice,
            title="Alice shared",
            visibility=Playbook.Visibility.ORGANIZATION,
        )

    def test_private_playbook_is_invisible_to_others(self):
        """_visible_to excludes another user's private playbook."""
        from apps.playbooks.views import _visible_to

        titles = set(_visible_to(self.bob).values_list("title", flat=True))
        self.assertNotIn("Alice private", titles)
        self.assertIn("Alice shared", titles)

    def test_author_sees_their_own_private_playbook(self):
        """The author always sees their own work."""
        from apps.playbooks.views import _visible_to

        titles = set(_visible_to(self.alice).values_list("title", flat=True))
        self.assertEqual(titles, {"Alice private", "Alice shared"})

    def test_only_the_owner_may_write(self):
        """IsOwner refuses a non-author even on a shared playbook."""
        from apps.playbooks.views import IsOwner

        class _Req:
            def __init__(self, user):
                self.user = user

        checker = IsOwner()
        self.assertTrue(
            checker.has_object_permission(_Req(self.alice), None, self.alice_shared)
        )
        self.assertFalse(
            checker.has_object_permission(_Req(self.bob), None, self.alice_shared)
        )
