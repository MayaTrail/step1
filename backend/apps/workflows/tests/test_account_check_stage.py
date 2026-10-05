"""
Tests for the account check a workflow runs once its lab is deployed, just
before the attack.

It runs then because the lab's own identities only exist from then on, and
they are the ones the attack acts as. The stage may finish or be skipped,
never fail: every case here asserts that the attack still started. A skip must
also never store AWS's error message, which names the caller's ARN and so the
account id.

AWS is never called: boto3.client is replaced so STS and IAM answer from
prepared responses. workflows.tasks imports the deploy tasks and through them
pulumi, which requirements-test.txt omits, so the suite skips where it is
absent and runs in the backend container.
"""

from __future__ import annotations

import json
import unittest
from datetime import timedelta
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from apps.infrastructure.models import Stack

from apps.logs.models import LogEntry
from apps.workflows.models import WorkflowRun

try:
    from botocore.exceptions import ClientError

    from apps.workflows import tasks

    HAS_RUNTIME = True
except ImportError:  # pragma: no cover
    HAS_RUNTIME = False

User = get_user_model()

ACCOUNT_ID = "123456789012"
ROLE = f"arn:aws:iam::{ACCOUNT_ID}:role/mayatrail-connected"

ANNOTATED = {
    "display_name": "Sample",
    "attack_path": [
        {"phase": 1, "name": "Discover", "aws_actions": ["s3:ListAllMyBuckets"], "acting_as": "connected_role"},
        {"phase": 2, "name": "Collect", "aws_actions": ["s3:GetObject"], "acting_as": "connected_role"},
    ],
}

LAB_USER = {
    "display_name": "Stolen",
    "identities": {"stolen_user": {"kind": "lab_user", "label": "The lab's stolen user", "output": "victim_user_name"}},
    "attack_path": [
        {"phase": 1, "name": "Collect", "aws_actions": ["s3:GetObject"], "acting_as": "stolen_user"},
    ],
}

UNANNOTATED = {
    "display_name": "Cluster",
    "attack_path": [{"phase": 1, "name": "Exec into pod"}],
}


def _allowed(action):
    """A simulator result allowing one action."""
    return {"EvalActionName": action, "EvalDecision": "allowed"}


def _client_error(code, message):
    """A botocore ClientError as AWS would raise it."""
    return ClientError({"Error": {"Code": code, "Message": message}}, "SimulatePrincipalPolicy")


class StubSTS:
    """Returns credentials for any role."""

    def assume_role(self, **kwargs):
        """Hand back temporary credentials."""
        return {"Credentials": {"AccessKeyId": "AK", "SecretAccessKey": "SK", "SessionToken": "ST"}}


class StubIAM:
    """Replays prepared simulator results, or raises a prepared error."""

    def __init__(self, results=None, error=None):
        """Store what the simulate call should do."""
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


def _refuse_aws(service, **kwargs):
    """A boto3.client replacement for cases that must not reach AWS."""
    raise AssertionError(f"AWS was called ({service}) when the check should have been skipped")


@unittest.skipUnless(HAS_RUNTIME, "the deploy runtime (pulumi, boto3) is not installed")
class AccountCheckStageTests(TestCase):
    """What a workflow stores just before attacking, and that it always attacks."""

    def setUp(self):
        """A verified owner with a connected role and a pending workflow."""
        self.user = User.objects.create_user(
            username="cloudsec",
            email="cloudsec@example.com",
            password="pw",
            is_verified=True,
            is_demo=False,
        )
        self.user.aws_role_arn = ROLE
        self.user.save(update_fields=["aws_role_arn"])
        self.workflow = WorkflowRun.objects.create(owner=self.user, emulation_type="sample")

    def _start(self, boto3_client, manifest=ANNOTATED, outputs=None):
        """
        Start the attack on a ready lab, with the registry, boto3 and the attack task stubbed.

        The lab is in eu-west-1, not the default region, so a test can tell
        that the check used the lab's own region.
        """
        self.workflow.stack = Stack.objects.create(
            name="sample-wf-test",
            owner=self.user,
            emulation_type="sample",
            status=Stack.Status.READY_FOR_ATTACK,
            region="eu-west-1",
            outputs=outputs or {},
            expires_at=timezone.now() + timedelta(hours=1),
        )
        self.workflow.status = WorkflowRun.Status.DEPLOYING
        self.workflow.save(update_fields=["stack", "status"])
        attack = MagicMock()
        with patch.object(tasks, "get_emulation", return_value={"manifest": manifest}), \
                patch.object(tasks, "run_emulation_attack", attack), \
                patch("boto3.client", boto3_client):
            tasks._start_attack(self.workflow)
        self.workflow.refresh_from_db()
        return attack

    def _assert_deployed(self, attack):
        """The stage never holds the attack back."""
        self.assertEqual(self.workflow.status, WorkflowRun.Status.ATTACKING)
        self.assertIsNotNone(self.workflow.emulation_run)
        attack.apply_async.assert_called_once()

    def test_checked_result_is_stored_with_the_stack_region(self):
        """A completed check stores the same result the emulation page gets."""
        iam = StubIAM(results=[_allowed("s3:ListAllMyBuckets"), _allowed("s3:GetObject")])
        deploy = self._start(_client_factory(iam))

        self._assert_deployed(deploy)
        record = self.workflow.account_check
        self.assertEqual(record["status"], "checked")
        result = record["result"]
        self.assertEqual(result["identity"], "mayatrail-connected")
        self.assertEqual(result["region"], self.workflow.stack.region)
        self.assertEqual(result["summary"]["actionsChecked"], 2)
        self.assertEqual([p["verdict"] for p in result["phases"]], ["allowed", "allowed"])
        self.assertTrue(record["afterDeploy"])
        # AWS was asked about the region the lab was deployed to, not a default.
        context = iam.requests[0]["ContextEntries"][0]
        self.assertEqual(context["ContextKeyValues"], ["eu-west-1"])

    def test_missing_permission_is_skipped_without_the_account_id(self):
        """A role without the simulate permission skips the stage, and AWS's message is not kept."""
        error = _client_error(
            "AccessDenied",
            f"User: arn:aws:sts::{ACCOUNT_ID}:assumed-role/mayatrail-connected/s is not "
            "authorized to perform: iam:SimulatePrincipalPolicy",
        )
        deploy = self._start(_client_factory(StubIAM(error=error)))

        self._assert_deployed(deploy)
        record = self.workflow.account_check
        self.assertEqual(record["status"], "skipped")
        self.assertEqual(record["reason"], "missing_permission")
        self.assertEqual(record["errorCode"], "AccessDenied")
        self.assertNotIn(ACCOUNT_ID, json.dumps(record))

    def test_other_aws_refusal_is_skipped_as_an_aws_error(self):
        """Any other AWS refusal is a skip with its code, not a missing permission."""
        error = _client_error("Throttling", "Rate exceeded")
        deploy = self._start(_client_factory(StubIAM(error=error)))

        self._assert_deployed(deploy)
        self.assertEqual(self.workflow.account_check["reason"], "aws_error")
        self.assertEqual(self.workflow.account_check["errorCode"], "Throttling")

    def test_unexpected_failure_is_skipped(self):
        """A bug in the check is a skip, never a failed workflow."""
        deploy = self._start(_client_factory(StubIAM(error=RuntimeError("boom"))))

        self._assert_deployed(deploy)
        self.assertEqual(self.workflow.account_check["reason"], "check_failed")
        self.assertNotIn("errorCode", self.workflow.account_check)

    def test_no_connected_role_skips_without_calling_aws(self):
        """Without a role there is nothing to assume."""
        self.user.aws_role_arn = ""
        self.user.save(update_fields=["aws_role_arn"])
        deploy = self._start(_refuse_aws)

        self._assert_deployed(deploy)
        self.assertEqual(self.workflow.account_check["reason"], "no_connected_role")

    def test_emulation_without_actions_skips_without_calling_aws(self):
        """An emulation with no IAM-authorised call has nothing to check."""
        deploy = self._start(_refuse_aws, manifest=UNANNOTATED)

        self._assert_deployed(deploy)
        self.assertEqual(self.workflow.account_check["reason"], "nothing_to_check")

    def test_no_notification_is_recorded(self):
        """The run's own notifications cover it; a per-run check event would be noise."""
        iam = StubIAM(results=[_allowed("s3:ListAllMyBuckets"), _allowed("s3:GetObject")])
        self._start(_client_factory(iam))

        self.assertFalse(LogEntry.objects.filter(event=LogEntry.Event.GUARDRAIL_CHECK).exists())

    def test_a_lab_identity_is_checked_in_the_runs_own_lab(self):
        """The stolen user exists by now, so it is simulated as the principal its output names."""
        iam = StubIAM(results=[_allowed("s3:GetObject")])
        attack = self._start(_client_factory(iam), manifest=LAB_USER, outputs={"victim_user_name": "lab-victim"})

        self._assert_deployed(attack)
        self.assertEqual(iam.requests[0]["PolicySourceArn"], f"arn:aws:iam::{ACCOUNT_ID}:user/lab-victim")
        result = self.workflow.account_check["result"]
        self.assertEqual(result["identities"][0]["status"], "checked")
        self.assertEqual(result["phases"][0]["verdict"], "allowed")

    def test_the_deploy_no_longer_checks(self):
        """Before the lab exists its identities cannot be checked, so the deploy step leaves the record empty."""
        deploy = MagicMock()
        deploy.apply_async.return_value = MagicMock(id="task-1")
        with patch.object(tasks, "get_emulation", return_value={"manifest": ANNOTATED}), \
                patch.object(tasks, "deploy_emulation_stack", deploy), \
                patch("boto3.client", _refuse_aws):
            tasks._start_deploy(self.workflow)
        self.workflow.refresh_from_db()
        self.assertEqual(self.workflow.status, WorkflowRun.Status.DEPLOYING)
        self.assertIsNone(self.workflow.account_check)

    def test_run_predating_the_check_has_none(self):
        """Runs created before this stage carry no record, which the page shows as not checked."""
        self.assertIsNone(WorkflowRun.objects.get(pk=self.workflow.pk).account_check)
