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

from django.test import SimpleTestCase

from apps.guardrails.simulate import (
    ALLOWED,
    BY_IDENTITY_POLICY,
    BY_ORGANIZATION,
    BY_PERMISSIONS_BOUNDARY,
    DENIED,
    UNDECIDED,
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
