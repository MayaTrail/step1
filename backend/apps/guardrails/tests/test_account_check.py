"""
Tests for POST /api/guardrails/emulation/<type>/check/.

AWS is never called: boto3.client is replaced so the STS assume and the IAM
simulate both come from stubs. What is tested is the endpoint's contract, and
in particular the two refusals that have to read as something other than a
failure:

  * An emulation with no declared actions is a gap in our own catalogue, so
    the endpoint says there is nothing to check rather than reporting that
    nothing would be prevented.
  * A connected role without iam:SimulatePrincipalPolicy predates this
    feature. The response names the permission to add, so the client can offer
    the fix instead of rendering an error.

The DRF import guard mirrors apps/workflows/tests/test_archive.py: the
backend-tests job installs requirements-test.txt, and these skip cleanly where
DRF's test helpers are absent.
"""

from __future__ import annotations

import unittest
from unittest.mock import patch

from botocore.exceptions import ClientError
from django.contrib.auth import get_user_model
from django.test import TestCase

from apps.logs.models import LogEntry

try:
    from rest_framework.test import APIRequestFactory, force_authenticate

    from apps.guardrails.views import EmulationAccountCheckView

    HAS_DRF = True
except ImportError:  # pragma: no cover
    HAS_DRF = False

User = get_user_model()

ROLE = "arn:aws:iam::123456789012:role/MayaTrailLab"

# One emulation that declares actions, and one that declares none.
ANNOTATED = {
    "name": "sample",
    "display_name": "Sample",
    "platform": "aws",
    "attack_path": [
        {"phase": 1, "name": "Impact", "aws_actions": ["s3:DeleteObject"]},
        {"phase": 2, "name": "Access", "aws_actions": ["sts:GetCallerIdentity"]},
    ],
}
UNANNOTATED = {"name": "bare", "display_name": "Bare", "platform": "aws", "attack_path": [{"phase": 1, "name": "X"}]}


def _assume_response():
    """A minimal STS AssumeRole response."""
    return {"Credentials": {"AccessKeyId": "AK", "SecretAccessKey": "SK", "SessionToken": "ST"}}


class StubSTS:
    """Returns credentials for any role."""

    def assume_role(self, **kwargs):
        """Record nothing; the endpoint only needs the credentials back."""
        return _assume_response()


class StubIAM:
    """Replays one simulator response, or raises a prepared error."""

    def __init__(self, results=None, error=None):
        """Store what the next simulate call should do."""
        self.results = results or []
        self.error = error
        self.requests = []

    def simulate_principal_policy(self, **kwargs):
        """Return the prepared evaluations, or raise."""
        self.requests.append(kwargs)
        if self.error:
            raise self.error
        return {"EvaluationResults": self.results, "IsTruncated": False}


def _client_factory(iam):
    """A boto3.client replacement routing by service name."""
    def factory(service, **kwargs):
        return StubSTS() if service == "sts" else iam
    return factory


@unittest.skipUnless(HAS_DRF, "DRF test helpers are not installed")
class AccountCheckTests(TestCase):
    """The endpoint's behaviour, with AWS stubbed out."""

    def setUp(self):
        """A verified user with a connected role, and the view under test."""
        self.factory = APIRequestFactory()
        self.user = User.objects.create_user(
            username="cloudsec",
            email="cloudsec@example.com",
            password="pw",
            is_verified=True,
            is_demo=False,
        )
        self.user.aws_role_arn = ROLE
        self.user.save(update_fields=["aws_role_arn"])
        self.view = EmulationAccountCheckView.as_view()

    def _post(self, iam, body=None, manifest=ANNOTATED, emulation="sample"):
        """Call the endpoint with the registry and boto3 both stubbed."""
        request = self.factory.post(f"/api/guardrails/emulation/{emulation}/check/", body or {}, format="json")
        force_authenticate(request, user=self.user)
        entry = None if manifest is None else {"name": manifest["name"], "manifest": manifest}
        with patch("apps.guardrails.views.get_emulation", return_value=entry), \
                patch("apps.guardrails.views.boto3.client", _client_factory(iam)):
            return self.view(request, emulation_type=emulation)

    def test_an_scp_deny_is_reported_as_prevention(self):
        """The headline case: the caller's organization refuses an action."""
        iam = StubIAM([
            {"EvalActionName": "s3:DeleteObject", "EvalDecision": "explicitDeny",
             "OrganizationsDecisionDetail": {"AllowedByOrganizations": False}},
            {"EvalActionName": "sts:GetCallerIdentity", "EvalDecision": "allowed"},
        ])
        response = self._post(iam)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["summary"]["prevented"], ["s3:DeleteObject"])
        self.assertEqual(response.data["basis"], "simulated")
        phases = {p["phase"]: p["verdict"] for p in response.data["phases"]}
        self.assertEqual(phases, {1: "denied", 2: "allowed"})

    def test_a_missing_permission_names_itself(self):
        """A role that predates the feature gets a fix, not an error page."""
        error = ClientError(
            {"Error": {"Code": "AccessDenied", "Message":
                       "User: arn:aws:sts::1:assumed-role/X is not authorized to perform: "
                       "iam:SimulatePrincipalPolicy on resource: *"}},
            "SimulatePrincipalPolicy",
        )
        response = self._post(StubIAM(error=error))
        self.assertEqual(response.status_code, 422)
        self.assertEqual(response.data["missingPermission"], "iam:SimulatePrincipalPolicy")

    def test_another_aws_error_is_not_a_missing_permission(self):
        """Only the simulate denial offers the policy fix."""
        error = ClientError({"Error": {"Code": "Throttling", "Message": "Rate exceeded"}}, "SimulatePrincipalPolicy")
        response = self._post(StubIAM(error=error))
        self.assertEqual(response.status_code, 422)
        self.assertIsNone(response.data["missingPermission"])

    def test_an_emulation_with_no_actions_is_refused_clearly(self):
        """Nothing to check must never read as nothing being prevented."""
        iam = StubIAM()
        response = self._post(iam, manifest=UNANNOTATED, emulation="bare")
        self.assertEqual(response.status_code, 409)
        self.assertEqual(iam.requests, [], "AWS must not be called when there is nothing to ask")

    def test_an_unknown_emulation_is_404(self):
        """A typo in the URL is not an AWS problem."""
        response = self._post(StubIAM(), manifest=None, emulation="nope")
        self.assertEqual(response.status_code, 404)

    def test_the_default_region_is_sent(self):
        """A lab deploys to us-east-1 unless told otherwise, so judge that."""
        iam = StubIAM([{"EvalActionName": "s3:DeleteObject", "EvalDecision": "allowed"}])
        self._post(iam)
        entries = iam.requests[0]["ContextEntries"]
        self.assertEqual(entries[0]["ContextKeyValues"], ["us-east-1"])

    def test_a_chosen_region_is_used(self):
        """An organization restricted to one region needs that region judged."""
        iam = StubIAM([{"EvalActionName": "s3:DeleteObject", "EvalDecision": "allowed"}])
        self._post(iam, body={"region": "eu-west-1"})
        self.assertEqual(iam.requests[0]["ContextEntries"][0]["ContextKeyValues"], ["eu-west-1"])

    def test_a_bad_region_is_rejected_before_aws(self):
        """A caller must not be able to put arbitrary text in a condition value."""
        iam = StubIAM()
        response = self._post(iam, body={"region": "'; DROP"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(iam.requests, [])

    def test_the_response_carries_the_role_name_not_its_arn(self):
        """The caller owns the ARN, but the response has no need for an account id."""
        iam = StubIAM([{"EvalActionName": "s3:DeleteObject", "EvalDecision": "allowed"}])
        response = self._post(iam)
        self.assertEqual(response.data["identity"], "MayaTrailLab")
        self.assertNotIn("123456789012", str(response.data))

    def test_the_check_is_recorded_in_the_trail(self):
        """It reads the caller's IAM configuration, so it is auditable."""
        iam = StubIAM([{"EvalActionName": "s3:DeleteObject", "EvalDecision": "allowed"}])
        self._post(iam)
        entry = LogEntry.objects.filter(event=LogEntry.Event.GUARDRAIL_CHECK).first()
        self.assertIsNotNone(entry)
        self.assertEqual(entry.actor, self.user)

    def test_an_unverified_user_is_refused(self):
        """The endpoint spends an AWS call, so it needs a real connection."""
        self.user.is_verified = False
        self.user.save(update_fields=["is_verified"])
        response = self._post(StubIAM())
        self.assertEqual(response.status_code, 403)
