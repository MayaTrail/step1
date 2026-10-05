"""
Tests for the account prevention check (apps/guardrails/simulate.py).

Every test feeds a recorded SimulatePrincipalPolicy response through a stub
client, so the suite never calls AWS. The shapes come from the API reference
for EvaluationResult: EvalDecision, OrganizationsDecisionDetail,
PermissionsBoundaryDecisionDetail and MissingContextValues.

The distinction these tests exist to protect is the one between a guardrail
refusing an action and the connected role simply lacking the permission. Both
stop the attack; only the first is prevention, and reporting the second as
prevention would tell a reader their organization is protected when their lab
is misconfigured.
"""

from __future__ import annotations

import importlib.util
import json
import unittest
from unittest.mock import patch

from django.test import SimpleTestCase

from apps.guardrails.simulate import (
    ALLOWED,
    BY_IDENTITY_POLICY,
    BY_ORGANIZATION,
    BY_PERMISSIONS_BOUNDARY,
    DENIED,
    NOT_CHECKED,
    UNDECIDED,
    check_account,
    evaluate,
    phase_verdicts,
    summarise,
)

ROLE = "arn:aws:iam::123456789012:role/MayaTrail"


class StubClient:
    """An IAM client that replays prepared responses and records its calls."""

    def __init__(self, *responses):
        """Store the pages to return, oldest first."""
        self.responses = list(responses)
        self.requests = []

    def simulate_principal_policy(self, **kwargs):
        """Record the request and return the next prepared page."""
        self.requests.append(kwargs)
        return self.responses.pop(0)


def result(action, decision, organizations=None, boundary=None, missing=None):
    """Build one EvaluationResult the way AWS returns it."""
    row = {"EvalActionName": action, "EvalDecision": decision}
    if organizations is not None:
        row["OrganizationsDecisionDetail"] = {"AllowedByOrganizations": organizations}
    if boundary is not None:
        row["PermissionsBoundaryDecisionDetail"] = {"AllowedByPermissionsBoundary": boundary}
    if missing:
        row["MissingContextValues"] = missing
    return row


def page(*results, truncated=False, marker=None):
    """Build one simulator response page."""
    body = {"EvaluationResults": list(results), "IsTruncated": truncated}
    if marker:
        body["Marker"] = marker
    return body


class VerdictTests(SimpleTestCase):
    """Each AWS decision shape maps to one verdict and one cause."""

    def _one(self, evaluation):
        """Evaluate a single result and return its row."""
        client = StubClient(page(evaluation))
        return evaluate(client, ROLE, ["s3:DeleteObject"], "us-east-1")[0]

    def test_an_allow_is_allowed(self):
        """Nothing in the caller's policies refuses it."""
        row = self._one(result("s3:DeleteObject", "allowed"))
        self.assertEqual(row["verdict"], ALLOWED)
        self.assertIsNone(row["deniedBy"])

    def test_an_scp_deny_is_prevention(self):
        """The organization refused it, which is a guardrail working."""
        row = self._one(result("s3:DeleteObject", "explicitDeny", organizations=False))
        self.assertEqual(row["verdict"], DENIED)
        self.assertEqual(row["deniedBy"], BY_ORGANIZATION)

    def test_a_permissions_boundary_deny_is_prevention(self):
        """A boundary is a deliberate ceiling on the identity, so it counts."""
        row = self._one(result("s3:DeleteObject", "explicitDeny", organizations=True, boundary=False))
        self.assertEqual(row["deniedBy"], BY_PERMISSIONS_BOUNDARY)

    def test_an_implicit_deny_is_the_role_lacking_the_permission(self):
        """No policy allowed it, which is a setup problem and not prevention."""
        row = self._one(result("s3:DeleteObject", "implicitDeny"))
        self.assertEqual(row["verdict"], DENIED)
        self.assertEqual(row["deniedBy"], BY_IDENTITY_POLICY)

    def test_a_deny_both_layers_allowed_is_the_identity_policy(self):
        """An explicit deny in the role's own policy, not a guardrail."""
        row = self._one(result("s3:DeleteObject", "explicitDeny", organizations=True, boundary=True))
        self.assertEqual(row["deniedBy"], BY_IDENTITY_POLICY)

    def test_a_missing_condition_value_is_undecided(self):
        """A deny outside approved regions cannot be judged without the region."""
        row = self._one(result("s3:DeleteObject", "implicitDeny", missing=["aws:RequestedRegion"]))
        self.assertEqual(row["verdict"], UNDECIDED)
        self.assertEqual(row["missingContext"], ["aws:RequestedRegion"])

    def test_an_allow_with_a_missing_value_is_undecided_too(self):
        """The unsupplied value could flip the allow, so it is not an answer."""
        row = self._one(result("s3:DeleteObject", "allowed", missing=["s3:ResourceAccount"]))
        self.assertEqual(row["verdict"], UNDECIDED)

    def test_an_scp_deny_outranks_a_missing_value(self):
        """No later value reinstates an action the organization already denied."""
        row = self._one(
            result("s3:DeleteObject", "explicitDeny", organizations=False, missing=["aws:RequestedRegion"])
        )
        self.assertEqual(row["verdict"], DENIED)
        self.assertEqual(row["deniedBy"], BY_ORGANIZATION)


class RequestTests(SimpleTestCase):
    """What is sent to AWS."""

    def test_actions_are_deduplicated_and_sorted(self):
        """Phases overlap, so the same action often arrives more than once."""
        client = StubClient(page(result("s3:GetObject", "allowed")))
        evaluate(client, ROLE, ["s3:GetObject", "iam:PassRole", "s3:GetObject"], None)
        self.assertEqual(client.requests[0]["ActionNames"], ["iam:PassRole", "s3:GetObject"])

    def test_a_region_is_supplied_as_a_condition_value(self):
        """Region-conditional policies can only be judged with the region."""
        client = StubClient(page(result("s3:GetObject", "allowed")))
        evaluate(client, ROLE, ["s3:GetObject"], "eu-west-1")
        entries = client.requests[0]["ContextEntries"]
        self.assertEqual(entries[0]["ContextKeyName"], "aws:RequestedRegion")
        self.assertEqual(entries[0]["ContextKeyValues"], ["eu-west-1"])

    def test_no_region_means_no_context_entry(self):
        """Supplying a guessed region would produce a confidently wrong answer."""
        client = StubClient(page(result("s3:GetObject", "allowed")))
        evaluate(client, ROLE, ["s3:GetObject"], None)
        self.assertNotIn("ContextEntries", client.requests[0])

    def test_no_actions_makes_no_call(self):
        """An unannotated emulation must not cost an AWS request."""
        client = StubClient()
        self.assertEqual(evaluate(client, ROLE, [], "us-east-1"), [])
        self.assertEqual(client.requests, [])

    def test_a_truncated_response_is_followed(self):
        """Silently dropping a page would understate what was checked."""
        client = StubClient(
            page(result("s3:GetObject", "allowed"), truncated=True, marker="next"),
            page(result("s3:PutObject", "explicitDeny", organizations=False)),
        )
        rows = evaluate(client, ROLE, ["s3:GetObject", "s3:PutObject"], None)
        self.assertEqual(len(rows), 2)
        self.assertEqual(client.requests[1]["Marker"], "next")


class SummaryTests(SimpleTestCase):
    """The figures the lane shows."""

    def setUp(self):
        """One row of each kind."""
        self.rows = [
            {"action": "s3:DeleteObject", "verdict": DENIED, "deniedBy": BY_ORGANIZATION, "missingContext": []},
            {"action": "s3:PutObject", "verdict": DENIED, "deniedBy": BY_PERMISSIONS_BOUNDARY, "missingContext": []},
            {"action": "iam:CreateUser", "verdict": DENIED, "deniedBy": BY_IDENTITY_POLICY, "missingContext": []},
            {"action": "s3:GetObject", "verdict": UNDECIDED, "deniedBy": None, "missingContext": ["aws:RequestedRegion"]},
            {"action": "sts:GetCallerIdentity", "verdict": ALLOWED, "deniedBy": None, "missingContext": []},
        ]

    def test_prevention_counts_guardrails_only(self):
        """The organization's deny and the boundary's deny, and nothing else."""
        self.assertEqual(summarise(self.rows)["prevented"], ["s3:DeleteObject", "s3:PutObject"])

    def test_a_missing_permission_is_reported_separately(self):
        """It stops the attack but says nothing about the organization."""
        self.assertEqual(summarise(self.rows)["roleCannotPerform"], ["iam:CreateUser"])

    def test_every_action_is_accounted_for(self):
        """A reader adding up the lists must reach the number checked."""
        summary = summarise(self.rows)
        counted = sum(len(summary[key]) for key in ("prevented", "undecided", "roleCannotPerform", "allowed"))
        self.assertEqual(counted, summary["actionsChecked"])


class PhaseVerdictTests(SimpleTestCase):
    """Folding action verdicts up to phases."""

    def _phases(self, *action_lists):
        """Build an attack_path whose phases carry the given actions."""
        return [
            {"phase": i, "name": f"Phase {i}", "aws_actions": list(actions)}
            for i, actions in enumerate(action_lists, start=1)
        ]

    def test_one_refused_action_prevents_the_phase(self):
        """An attacker who cannot make one of a phase's calls cannot finish it."""
        rows = [
            {"action": "s3:GetObject", "verdict": ALLOWED, "deniedBy": None, "missingContext": []},
            {"action": "s3:DeleteObject", "verdict": DENIED, "deniedBy": BY_ORGANIZATION, "missingContext": []},
        ]
        verdicts = phase_verdicts(self._phases(["s3:GetObject", "s3:DeleteObject"]), rows)
        self.assertEqual(verdicts[0]["verdict"], DENIED)
        self.assertEqual(verdicts[0]["preventedActions"], ["s3:DeleteObject"])

    def test_an_undecided_action_outranks_an_allowed_one(self):
        """A phase is only allowed when every action in it was decided."""
        rows = [
            {"action": "s3:GetObject", "verdict": ALLOWED, "deniedBy": None, "missingContext": []},
            {"action": "s3:PutObject", "verdict": UNDECIDED, "deniedBy": None, "missingContext": ["aws:RequestedRegion"]},
        ]
        verdicts = phase_verdicts(self._phases(["s3:GetObject", "s3:PutObject"]), rows)
        self.assertEqual(verdicts[0]["verdict"], UNDECIDED)

    def test_a_phase_with_no_iam_call_says_so(self):
        """An exploit over HTTP cannot be refused by any identity policy."""
        verdicts = phase_verdicts(self._phases([]), [])
        self.assertEqual(verdicts[0]["verdict"], "no_iam_call")

    def test_a_missing_permission_is_not_prevention_at_phase_level(self):
        """The phase is blocked, but by our own lab, so it reads differently."""
        rows = [{"action": "iam:CreateUser", "verdict": DENIED, "deniedBy": BY_IDENTITY_POLICY, "missingContext": []}]
        verdicts = phase_verdicts(self._phases(["iam:CreateUser"]), rows)
        self.assertEqual(verdicts[0]["verdict"], "role_cannot_perform")
        self.assertEqual(verdicts[0]["preventedActions"], [])

    def test_matching_ignores_case(self):
        """AWS echoes the action name back and IAM is case-insensitive."""
        rows = [{"action": "S3:DeleteObject", "verdict": DENIED, "deniedBy": BY_ORGANIZATION, "missingContext": []}]
        verdicts = phase_verdicts(self._phases(["s3:DeleteObject"]), rows)
        self.assertEqual(verdicts[0]["verdict"], DENIED)


STOLEN_USER = {"stolen_user": {"kind": "lab_user", "label": "The lab's stolen user", "output": "victim_user_name"}}


def _manifest(*phases, identities=None):
    """An AWS manifest with the given phases and declared identities."""
    return {"display_name": "Sample", "identities": identities or {}, "attack_path": list(phases)}


class IdentityTests(SimpleTestCase):
    """Only the connected role's actions are judged; the rest name who performs them."""

    def test_nothing_as_the_connected_role_makes_no_aws_call(self):
        """With no action to ask about, AWS is not called and nothing is claimed."""
        manifest = _manifest(
            {"phase": 1, "name": "Collect", "aws_actions": ["s3:GetObject", "s3:ListBucket"], "acting_as": "stolen_user"},
            identities=STOLEN_USER,
        )
        with patch.dict("sys.modules", {"boto3": None}):
            result = check_account(ROLE, "s", "sample", manifest, "us-east-1")
        self.assertEqual(result["summary"]["actionsChecked"], 0)
        self.assertEqual(result["summary"]["notChecked"], ["s3:GetObject", "s3:ListBucket"])
        self.assertEqual(result["phases"][0]["verdict"], NOT_CHECKED)
        self.assertEqual(result["phases"][0]["notCheckedIdentities"], ["stolen_user"])
        self.assertEqual(
            result["identities"],
            [{"key": "stolen_user", "label": "The lab's stolen user", "kind": "lab_user", "actions": 2,
              "checked": False, "status": "not_deployed"}],
        )

    def test_an_undeclared_phase_is_not_assumed_to_be_the_connected_role(self):
        """Without acting_as nobody is assumed, so nothing is sent to AWS."""
        manifest = _manifest({"phase": 1, "name": "Impact", "aws_actions": ["s3:DeleteObject"]})
        with patch.dict("sys.modules", {"boto3": None}):
            result = check_account(ROLE, "s", "sample", manifest, "us-east-1")
        self.assertEqual(result["actions"][0]["verdict"], NOT_CHECKED)
        self.assertEqual(result["identities"][0]["kind"], "undeclared")

    @unittest.skipUnless(importlib.util.find_spec("boto3"), "boto3 is not installed")
    def test_only_the_connected_roles_actions_are_sent(self):
        """The stolen user's actions never reach AWS as if the connected role made them."""
        manifest = _manifest(
            {"phase": 1, "name": "Start", "aws_actions": ["ecs:RunTask"], "acting_as": "connected_role"},
            {"phase": 2, "name": "Collect", "aws_actions": ["s3:GetObject"], "acting_as": "stolen_user"},
            identities=STOLEN_USER,
        )
        iam = StubClient(page(result("ecs:RunTask", "allowed")))

        class Sts:
            """Hands back credentials for any role."""

            def assume_role(self, **kwargs):
                """Return temporary credentials."""
                return {"Credentials": {"AccessKeyId": "A", "SecretAccessKey": "S", "SessionToken": "T"}}

        with patch("boto3.client", lambda service, **kwargs: Sts() if service == "sts" else iam):
            checked = check_account(ROLE, "s", "sample", manifest, "us-east-1")
        self.assertEqual(iam.requests[0]["ActionNames"], ["ecs:RunTask"])
        self.assertEqual([p["verdict"] for p in checked["phases"]], [ALLOWED, NOT_CHECKED])
        self.assertEqual(checked["summary"]["actionsChecked"], 1)


class IdentityPhaseVerdictTests(SimpleTestCase):
    """Folding when a phase mixes identities."""

    PHASE = {
        "phase": 1,
        "name": "Mixed",
        "aws_actions": ["s3:GetObject", "s3:DeleteObject"],
        "acting_as": {"connected_role": ["s3:DeleteObject"], "stolen_user": ["s3:GetObject"]},
    }

    def _rows(self, connected_verdict, denied_by=None):
        """One judged connected-role row and one unchecked stolen-user row."""
        return [
            {"action": "s3:DeleteObject", "identity": "connected_role", "verdict": connected_verdict,
             "deniedBy": denied_by, "missingContext": []},
            {"action": "s3:GetObject", "identity": "stolen_user", "verdict": NOT_CHECKED,
             "deniedBy": None, "missingContext": []},
        ]

    def test_a_refusal_outranks_an_unchecked_action(self):
        """One refused call stops the phase, whoever makes the others."""
        verdicts = phase_verdicts([self.PHASE], self._rows(DENIED, BY_ORGANIZATION))
        self.assertEqual(verdicts[0]["verdict"], DENIED)

    def test_an_unchecked_action_keeps_the_phase_from_being_allowed(self):
        """Allowed would claim something nobody checked."""
        verdicts = phase_verdicts([self.PHASE], self._rows(ALLOWED))
        self.assertEqual(verdicts[0]["verdict"], NOT_CHECKED)
        self.assertEqual(verdicts[0]["notCheckedActions"], ["s3:GetObject"])

    def test_an_unchecked_action_outranks_an_undecided_one(self):
        """Not checked is the stronger caveat: part of the phase was never asked about."""
        verdicts = phase_verdicts([self.PHASE], self._rows(UNDECIDED))
        self.assertEqual(verdicts[0]["verdict"], NOT_CHECKED)

    def test_rows_are_matched_by_identity_and_action(self):
        """The same action under two identities is two separate rows."""
        phase = dict(self.PHASE, acting_as={"stolen_user": ["s3:GetObject", "s3:DeleteObject"]})
        verdicts = phase_verdicts([phase], self._rows(DENIED, BY_ORGANIZATION))
        self.assertEqual(verdicts[0]["rows"], [{"identity": "stolen_user", "action": "s3:GetObject"}])


class _Sts:
    """Hands back credentials for any role."""

    def assume_role(self, **kwargs):
        """Return temporary credentials."""
        return {"Credentials": {"AccessKeyId": "A", "SecretAccessKey": "S", "SessionToken": "T"}}


class _RecordingIam:
    """Answers every simulation as allowed, or as denied for chosen actions, and records who was asked."""

    def __init__(self, denied=None):
        """Store the actions to deny and the denial's shape."""
        self.denied = denied or {}
        self.requests = []

    def simulate_principal_policy(self, **kwargs):
        """Record the principal and answer per action."""
        self.requests.append(kwargs)
        results = []
        for action in kwargs["ActionNames"]:
            if action in self.denied:
                results.append(result(action, "implicitDeny", **self.denied[action]))
            else:
                results.append(result(action, "allowed"))
        return page(*results)


LAB_ROLE = {"instance_role": {"kind": "lab_role", "label": "The stolen EC2 instance role", "output": "instance_role_arn"}}
LAB_ROLE_ARN = "arn:aws:iam::123456789012:role/lab-instance-role"


@unittest.skipUnless(importlib.util.find_spec("boto3"), "boto3 is not installed")
class LabIdentityTests(SimpleTestCase):
    """Lab identities are checked once the lab is deployed, as the principal its output names."""

    def _check(self, manifest, outputs, iam):
        """Run the check with STS and IAM stubbed."""
        with patch("boto3.client", lambda service, **kwargs: _Sts() if service == "sts" else iam):
            return check_account(ROLE, "s", "sample", manifest, "us-east-1", outputs)

    def test_a_lab_user_is_simulated_by_the_arn_built_from_its_name(self):
        """A name output is joined to the account and the default path."""
        manifest = _manifest(
            {"phase": 1, "name": "Collect", "aws_actions": ["s3:GetObject"], "acting_as": "stolen_user"},
            identities=STOLEN_USER,
        )
        iam = _RecordingIam()
        checked = self._check(manifest, {"victim_user_name": "lab-victim"}, iam)
        self.assertEqual(iam.requests[0]["PolicySourceArn"], "arn:aws:iam::123456789012:user/lab-victim")
        self.assertEqual(checked["phases"][0]["verdict"], ALLOWED)
        self.assertEqual(checked["identities"][0]["status"], "checked")

    def test_each_identity_gets_its_own_simulation(self):
        """AWS evaluates one principal per call, so a mixed phase makes two."""
        manifest = _manifest(
            {"phase": 1, "name": "Mixed", "aws_actions": ["sts:AssumeRole", "cloudtrail:StopLogging"],
             "acting_as": {"connected_role": ["sts:AssumeRole"], "instance_role": ["cloudtrail:StopLogging"]}},
            identities=LAB_ROLE,
        )
        iam = _RecordingIam()
        self._check(manifest, {"instance_role_arn": LAB_ROLE_ARN}, iam)
        asked = {r["PolicySourceArn"]: r["ActionNames"] for r in iam.requests}
        self.assertEqual(asked, {ROLE: ["sts:AssumeRole"], LAB_ROLE_ARN: ["cloudtrail:StopLogging"]})

    def test_an_scp_refusal_on_a_lab_identity_is_prevention(self):
        """The point of checking lab identities: a guardrail on the identity the attack really uses."""
        manifest = _manifest(
            {"phase": 4, "name": "Evasion", "aws_actions": ["cloudtrail:StopLogging"], "acting_as": "instance_role"},
            identities=LAB_ROLE,
        )
        iam = _RecordingIam(denied={"cloudtrail:StopLogging": {"organizations": False}})
        checked = self._check(manifest, {"instance_role_arn": LAB_ROLE_ARN}, iam)
        self.assertEqual(checked["phases"][0]["verdict"], DENIED)
        self.assertEqual(checked["summary"]["prevented"], ["cloudtrail:StopLogging"])

    def test_a_lab_identity_lacking_a_permission_is_not_the_readers_role(self):
        """The lab's own policy is the emulation's setup, reported apart from the connected role."""
        manifest = _manifest(
            {"phase": 1, "name": "Collect", "aws_actions": ["s3:GetObject"], "acting_as": "instance_role"},
            identities=LAB_ROLE,
        )
        iam = _RecordingIam(denied={"s3:GetObject": {"organizations": True, "boundary": True}})
        checked = self._check(manifest, {"instance_role_arn": LAB_ROLE_ARN}, iam)
        self.assertEqual(checked["summary"]["roleCannotPerform"], [])
        self.assertEqual(checked["summary"]["labCannotPerform"], ["s3:GetObject"])

    def test_a_lab_without_the_output_says_so_without_calling_aws(self):
        """A lab deployed before the identity was exported needs a redeploy, not a guess."""
        manifest = _manifest(
            {"phase": 1, "name": "Collect", "aws_actions": ["s3:GetObject"], "acting_as": "instance_role"},
            identities=LAB_ROLE,
        )
        iam = _RecordingIam()
        checked = self._check(manifest, {"some_other_output": "x"}, iam)
        self.assertEqual(iam.requests, [])
        self.assertEqual(checked["identities"][0]["status"], "not_exported")
        self.assertEqual(checked["phases"][0]["verdict"], NOT_CHECKED)


class AnonymousTests(SimpleTestCase):
    """A request with no identity is listed but never holds a phase back."""

    def _codefinger_like(self):
        """Phase 1 reads anonymously, then acts as a lab user the reader has not deployed."""
        return _manifest(
            {"phase": 1, "name": "Harvest", "aws_actions": ["s3:GetObject"], "acting_as": "anonymous"},
            identities={},
        )

    def test_an_anonymous_only_phase_reads_no_identity(self):
        """Nothing for an IAM rule to judge, so neither checked nor not checked."""
        with patch.dict("sys.modules", {"boto3": None}):
            checked = check_account(ROLE, "s", "sample", self._codefinger_like(), "us-east-1")
        self.assertEqual(checked["phases"][0]["verdict"], "no_identity")
        self.assertEqual(checked["summary"]["notChecked"], [])
        self.assertEqual(checked["summary"]["noIdentity"], ["s3:GetObject"])

    def test_an_anonymous_action_does_not_hold_back_a_checked_phase(self):
        """With the rest of the phase decided, the anonymous read must not keep it Not checked."""
        phase = {
            "phase": 1, "name": "Harvest", "aws_actions": ["s3:GetObject", "sts:GetCallerIdentity"],
            "acting_as": {"anonymous": ["s3:GetObject"], "connected_role": ["sts:GetCallerIdentity"]},
        }
        rows = [
            {"action": "s3:GetObject", "identity": "anonymous", "verdict": "no_identity", "deniedBy": None, "missingContext": []},
            {"action": "sts:GetCallerIdentity", "identity": "connected_role", "verdict": ALLOWED, "deniedBy": None, "missingContext": []},
        ]
        self.assertEqual(phase_verdicts([phase], rows)[0]["verdict"], ALLOWED)


class _ScopedIam:
    """
    Answers like a lab policy scoped to one bucket.

    Asked about "*" (no ResourceArns), it implicitly denies, as AWS does for a
    policy whose Resource names the bucket. Asked about the bucket, it allows.
    That difference is the bug the resource declarations exist to fix.
    """

    def __init__(self, allowed_arn, denied_by_org=None):
        """Store the one resource this policy covers, and any action an SCP refuses."""
        self.allowed_arn = allowed_arn
        self.denied_by_org = denied_by_org or set()
        self.requests = []

    def simulate_principal_policy(self, **kwargs):
        """Allow on the scoped resource only."""
        self.requests.append(kwargs)
        on = (kwargs.get("ResourceArns") or ["*"])[0]
        results = []
        for action in kwargs["ActionNames"]:
            if action in self.denied_by_org:
                results.append(result(action, "explicitDeny", organizations=False))
            elif on == self.allowed_arn:
                results.append(result(action, "allowed"))
            else:
                results.append(result(action, "implicitDeny", organizations=True, boundary=True))
        return page(*results)


@unittest.skipUnless(importlib.util.find_spec("boto3"), "boto3 is not installed")
class ResourceTests(SimpleTestCase):
    """Actions are judged against the resource the attack really targets."""

    BUCKET = "arn:aws:s3:::lab-target"

    def _manifest(self, resources):
        """Codefinger's shape: the stolen user reads objects of one bucket."""
        return _manifest(
            {"phase": 2, "name": "Collect", "aws_actions": ["s3:ListBucket"], "acting_as": "stolen_user",
             "aws_resources": resources},
            identities=STOLEN_USER,
        )

    def _check(self, manifest, iam, outputs=None):
        """Run the check with STS and IAM stubbed."""
        outputs = {"victim_user_name": "lab-victim", "target_bucket_name": "lab-target"} if outputs is None else outputs
        with patch("boto3.client", lambda service, **kwargs: _Sts() if service == "sts" else iam):
            return check_account(ROLE, "s", "sample", manifest, "us-east-1", outputs)

    def test_a_scoped_lab_policy_is_judged_on_its_own_resource(self):
        """The bug: asked about "*" the scoped policy says no; asked about the bucket it says yes."""
        iam = _ScopedIam(self.BUCKET)
        checked = self._check(self._manifest({"s3:ListBucket": "arn:aws:s3:::{target_bucket_name}"}), iam)
        self.assertEqual(iam.requests[0]["ResourceArns"], [self.BUCKET])
        self.assertEqual(checked["phases"][0]["verdict"], ALLOWED)
        self.assertEqual(checked["actions"][0]["resourceScope"], "specific")

    def test_an_scp_on_the_real_resource_is_still_prevention(self):
        """Naming the resource must not hide a guardrail; it makes resource-scoped SCPs visible."""
        iam = _ScopedIam(self.BUCKET, denied_by_org={"s3:ListBucket"})
        checked = self._check(self._manifest({"s3:ListBucket": "arn:aws:s3:::{target_bucket_name}"}), iam)
        self.assertEqual(checked["phases"][0]["verdict"], DENIED)

    def test_an_explicit_star_is_judged_against_all_resources(self):
        """For an action AWS only allows on everything, "*" is the right question."""
        iam = _ScopedIam(self.BUCKET)
        checked = self._check(self._manifest({"s3:ListBucket": "*"}), iam)
        self.assertNotIn("ResourceArns", iam.requests[0])
        self.assertEqual(checked["actions"][0]["resourceScope"], "all")

    def test_the_most_serious_answer_of_several_resources_stands(self):
        """A call refused on one of its resources is a call the attack cannot complete."""
        iam = _ScopedIam(self.BUCKET)
        checked = self._check(
            self._manifest({"s3:ListBucket": ["arn:aws:s3:::{target_bucket_name}", "arn:aws:s3:::other"]}), iam,
        )
        self.assertEqual(len(iam.requests), 2)
        self.assertEqual(checked["actions"][0]["deniedBy"], "identity_policy")

    def test_a_placeholder_the_lab_does_not_export_needs_a_redeploy(self):
        """An older lab that cannot fill the template is not guessed at."""
        iam = _ScopedIam(self.BUCKET)
        checked = self._check(
            self._manifest({"s3:ListBucket": "arn:aws:s3:::{target_bucket_name}"}), iam,
            outputs={"victim_user_name": "lab-victim"},
        )
        self.assertEqual(iam.requests, [])
        self.assertEqual(checked["identities"][0]["status"], "not_exported")

    def test_no_arn_or_account_id_reaches_the_result(self):
        """Resources are used to ask AWS, never returned: an ARN carries the account id."""
        iam = _ScopedIam(self.BUCKET)
        checked = self._check(self._manifest({"s3:ListBucket": "arn:aws:s3:::{target_bucket_name}"}), iam)
        self.assertNotIn("123456789012", json.dumps(checked))
        self.assertNotIn("lab-target", json.dumps(checked))

    def test_the_connected_role_falls_back_to_all_resources_with_no_lab(self):
        """
        Unlike a lab identity, the connected role exists before any lab, so an
        unfillable template is judged against all resources and labelled, rather
        than switching the role's check off.
        """
        iam = _ScopedIam(self.BUCKET)
        manifest = _manifest(
            {"phase": 1, "name": "Collect", "aws_actions": ["s3:GetObject"], "acting_as": "connected_role",
             "aws_resources": {"s3:GetObject": "arn:aws:s3:::{target_bucket_name}/*"}},
        )
        checked = self._check(manifest, iam, outputs={})
        self.assertNotIn("ResourceArns", iam.requests[0])
        self.assertEqual(checked["actions"][0]["identity"], "connected_role")
        self.assertEqual(checked["actions"][0]["resourceScope"], "fallback")
        self.assertEqual(checked["identities"][0]["status"], "checked")

    def test_the_connected_role_uses_the_real_resource_once_the_lab_is_deployed(self):
        """With the output present the fallback does not apply: the exact resource is asked about."""
        iam = _ScopedIam(self.BUCKET + "/object")
        manifest = _manifest(
            {"phase": 1, "name": "Collect", "aws_actions": ["s3:GetObject"], "acting_as": "connected_role",
             "aws_resources": {"s3:GetObject": "arn:aws:s3:::{target_bucket_name}/object"}},
        )
        checked = self._check(manifest, iam, outputs={"target_bucket_name": "lab-target"})
        self.assertEqual(iam.requests[0]["ResourceArns"], [self.BUCKET + "/object"])
        self.assertEqual(checked["actions"][0]["resourceScope"], "specific")
