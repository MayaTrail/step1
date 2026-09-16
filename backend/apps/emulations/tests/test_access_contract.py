"""
The Explorer contract: read the whole product, change nothing.

A signed-up user with no AWS connection ("Explorer") browses the catalogue,
detections and playbooks to decide whether connecting is worth it. The gate sits
on the action, not the page, because every mutating endpoint ultimately changes
something in the tenant's AWS account -- which is exactly what an unconnected
user has not proven they own.

Lives under apps.emulations rather than apps.infrastructure (where the class
itself lives) for one practical reason: CI runs `apps.emulations apps.metrics
apps.guardrails`, so a test placed with the class would never execute.

Two layers, because they fail for different reasons and CI can only run one:

  * Wiring, always runs. Reads the source, needs no dependencies. Catches the
    regression that actually matters -- a view reverting to a blanket check, or
    a new endpoint added without the method-aware one.
  * Behaviour, skipped when DRF is absent. config.settings.ci deliberately omits
    DRF to keep the test image small, so this layer runs locally and in the
    container but not in the GitHub job.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path
from types import SimpleNamespace

from django.test import SimpleTestCase

try:
    from apps.infrastructure.permissions import HasAWSConnection

    HAS_DRF = True
except ImportError:  # config.settings.ci omits DRF on purpose
    HasAWSConnection = None
    HAS_DRF = False

SAFE = ("GET", "HEAD", "OPTIONS")
MUTATING = ("POST", "PUT", "PATCH", "DELETE")

_VIEWS = Path(__file__).resolve().parents[1] / "views.py"


def _user(*, authenticated=True, verified=False, demo=False):
    """Build the minimal user shape the permission class reads."""
    return SimpleNamespace(
        is_authenticated=authenticated, is_verified=verified, is_demo=demo
    )


def _request(method, user):
    """Build the minimal request shape the permission class reads."""
    return SimpleNamespace(method=method, user=user)


class PermissionWiringTests(SimpleTestCase):
    """Every emulation view delegates to the method-aware permission class."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.source = _VIEWS.read_text(encoding="utf-8")

    def test_no_view_uses_the_blanket_check(self):
        """
        IsEnterpriseUser gates every method, so a view using it makes its own
        GET unreachable for an Explorer and quietly breaks browsing.
        """
        self.assertNotIn(
            "IsEnterpriseUser",
            self.source,
            "apps/emulations/views.py must use HasAWSConnection so reads stay open",
        )

    def test_every_view_declares_a_permission(self):
        """
        A view with no permission_classes inherits the project default, which is
        not the contract this file exists to pin.
        """
        classes = re.findall(r"^class (\w+View)\(", self.source, re.M)
        declared = self.source.count("permission_classes = [HasAWSConnection]")
        self.assertEqual(
            len(classes),
            declared,
            f"{len(classes)} views but {declared} declare HasAWSConnection; "
            "a new endpoint was added without the contract",
        )

    def test_mutating_views_exist_to_be_gated(self):
        """
        Guard against the contract passing vacuously. If the deploy, attack and
        destroy endpoints were renamed away, the tests above would still pass
        while nothing was actually being gated.
        """
        for view in ("EmulationDeployView", "EmulationAttackView", "EmulationDestroyView"):
            with self.subTest(view=view):
                self.assertIn(f"class {view}(", self.source)


@unittest.skipUnless(HAS_DRF, "DRF is not installed under config.settings.ci")
class ExplorerBehaviourTests(SimpleTestCase):
    """Authenticated, no AWS connection."""

    def setUp(self):
        self.permission = HasAWSConnection()
        self.explorer = _user(verified=False)

    def test_can_read_everything(self):
        for method in SAFE:
            with self.subTest(method=method):
                self.assertTrue(
                    self.permission.has_permission(_request(method, self.explorer), None),
                    f"Explorer must be able to {method}",
                )

    def test_cannot_change_anything(self):
        for method in MUTATING:
            with self.subTest(method=method):
                self.assertFalse(
                    self.permission.has_permission(_request(method, self.explorer), None),
                    f"Explorer must NOT be able to {method}",
                )


@unittest.skipUnless(HAS_DRF, "DRF is not installed under config.settings.ci")
class ConnectedAndAnonymousTests(SimpleTestCase):
    """The two ends of the range: a verified role, and no session at all."""

    def setUp(self):
        self.permission = HasAWSConnection()

    def test_connected_user_can_do_everything(self):
        connected = _user(verified=True)
        for method in SAFE + MUTATING:
            with self.subTest(method=method):
                self.assertTrue(
                    self.permission.has_permission(_request(method, connected), None)
                )

    def test_anonymous_is_denied_even_on_reads(self):
        anon = _user(authenticated=False)
        for method in SAFE + MUTATING:
            with self.subTest(method=method):
                self.assertFalse(
                    self.permission.has_permission(_request(method, anon), None)
                )


@unittest.skipUnless(HAS_DRF, "DRF is not installed under config.settings.ci")
class DemoUserTests(SimpleTestCase):
    """
    Demo users keep their pre-existing treatment.

    The demo model is dormant (zero users) but its code paths are still live, and
    retiring it was deliberately deferred. Pinning the behaviour here means a
    future cleanup has to change this test on purpose rather than by accident.
    """

    def setUp(self):
        self.permission = HasAWSConnection()
        self.demo = _user(verified=True, demo=True)

    def test_demo_user_can_read(self):
        self.assertTrue(self.permission.has_permission(_request("GET", self.demo), None))

    def test_demo_user_cannot_write_even_when_verified(self):
        self.assertFalse(
            self.permission.has_permission(_request("POST", self.demo), None),
            "is_demo must still block writes, matching the old IsEnterpriseUser",
        )
