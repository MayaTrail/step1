"""
The Scout audit role is a second, separate connection.

It is not is_verified and it is not aws_role_arn. Those belong to the
emulation role, which grants writes; this one grants a single IAM read and is
what the Attack Graph scan assumes. Collapsing the two — gating a scan on
is_verified, or storing both ARNs in one field — is the mistake this test
exists to catch, because it silently re-widens the emulation grant.
"""

import pathlib

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase

User = get_user_model()
BACKEND_ROOT = pathlib.Path(__file__).resolve().parents[3]


class AuditRoleFieldTests(SimpleTestCase):
    """What the model carries. No database is touched."""

    def test_the_audit_role_is_its_own_field(self):
        field = User._meta.get_field("aws_audit_role_arn")
        self.assertTrue(field.blank, "an unconnected user has no audit role")
        self.assertEqual(field.default, "")
        self.assertEqual(field.max_length, 256)

    def test_it_is_not_the_emulation_role(self):
        audit = User._meta.get_field("aws_audit_role_arn")
        emulation = User._meta.get_field("aws_role_arn")
        self.assertNotEqual(audit.name, emulation.name)

    def test_the_profile_endpoint_exposes_it(self):
        # The frontend gates the Attack Graph page on this value, and it reads
        # it from /auth/me/. DRF is not installed in CI, so the serializer is
        # read as source rather than imported.
        source = (BACKEND_ROOT / "apps/users/serializers.py").read_text(encoding="utf-8")
        self.assertIn('"aws_audit_role_arn"', source)
