"""
One place calls STS AssumeRole.

Both the emulation deploy path and the Scout scan need temporary credentials,
with different role ARNs and different session names. A second hand-rolled
sts.assume_role() would work on the day it is written and then drift — a
changed duration or session name in one copy and not the other is invisible
until a tenant's CloudTrail stops making sense. This test reads the source
rather than importing it: boto3 is not installed in CI.
"""

import pathlib

from django.test import SimpleTestCase

BACKEND_ROOT = pathlib.Path(__file__).resolve().parents[3]

# Every module that resolves tenant credentials.
CREDENTIAL_SOURCES = [
    "apps/connectors/aws.py",
    "apps/emulations/tasks.py",
    "apps/attack_graph/tasks.py",
]


class AssumeRoleCallSiteTests(SimpleTestCase):
    """Where sts.assume_role may appear."""

    def _source(self, relative):
        path = BACKEND_ROOT / relative
        return path.read_text(encoding="utf-8") if path.exists() else ""

    def test_only_the_shared_helper_calls_assume_role(self):
        offenders = [
            name
            for name in CREDENTIAL_SOURCES
            if name != "apps/connectors/aws.py" and ".assume_role(" in self._source(name)
        ]
        self.assertEqual(
            offenders,
            [],
            f"{offenders} call sts.assume_role directly; use connectors.aws.assume_role_arn",
        )

    def test_the_helper_is_parameterised_by_arn_session_name_and_duration(self):
        source = self._source("apps/connectors/aws.py")
        self.assertIn("def assume_role_arn(", source)
        for parameter in ("role_arn: str", "session_name: str", "duration_seconds: int"):
            self.assertIn(parameter, source, parameter)

    def test_a_connect_time_verify_asks_for_the_shortest_session(self):
        # AWS rejects AssumeRole outright when DurationSeconds exceeds the
        # role's MaxSessionDuration, and an org creating a read-only auditor
        # role is exactly the org that caps it. The existing emulation verify
        # already asks for the 900s minimum for this reason
        # (connectors/views.py, "# minimum allowed"); a one-hour session for a
        # single GetAccountAuthorizationDetails call would narrow which roles
        # can connect, for nothing.
        source = self._source("apps/connectors/aws.py")
        self.assertIn("VERIFY_SESSION_SECONDS = 900", source)

    def test_the_emulation_wrapper_still_names_its_own_session(self):
        source = self._source("apps/emulations/tasks.py")
        self.assertIn("mayatrail-emulation-", source)
