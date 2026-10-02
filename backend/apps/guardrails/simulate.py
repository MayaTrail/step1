"""
Ask AWS whether the caller's own policies would refuse an emulation's actions.

This is the middle of three confidence levels the Prevention lane shows:

    catalogue   a published sample policy would refuse this, if deployed.
    simulated   the caller's real policies, as AWS evaluates them, refuse it.
    observed    the attack ran and AWS actually refused it.

`iam:SimulatePrincipalPolicy` answers the middle one without performing
anything: AWS evaluates the identity's policies, its permissions boundary and
its organization's service control policies, and reports what would happen.

Two limits are structural and the wording of every result has to respect them:

  * The simulator does not evaluate resource control policies, and does not
    read a resource's own policy unless one is passed in. A deny living there
    is invisible here.
  * A policy whose Condition needs a value we did not supply cannot be
    decided. AWS reports those keys rather than guessing, and so do we, as the
    UNDECIDED verdict. Region is the common case: a deny outside approved
    regions cannot be judged for an emulation that has not been deployed yet.

The third limit is about who is asked. Only the identity named by
PolicySourceArn is evaluated, so a result describes the connected role, not
whatever identity an emulation steals partway through its attack.
"""

from __future__ import annotations

from typing import Any

# Verdicts, narrower than AWS's decision strings because the question here is
# "would a guardrail stop this", not "what does the policy say".
ALLOWED = "allowed"
DENIED = "denied"
UNDECIDED = "undecided"

# Who refused, when the verdict is DENIED. The distinction matters: an SCP
# denying an action is the organization's guardrail working, while the role
# simply lacking the permission is a setup problem that would fail the run for
# an unrelated reason, and must never be reported as prevention.
BY_ORGANIZATION = "organization_scp"
BY_PERMISSIONS_BOUNDARY = "permissions_boundary"
BY_IDENTITY_POLICY = "identity_policy"

# AWS caps a single response at 1000 evaluations and pages beyond that. No
# emulation declares anywhere near that many actions, but a page loop costs
# little and removes a silent truncation.
_MAX_ITEMS = 1000


def _decision(result: dict[str, Any]) -> tuple[str, str | None, list[str]]:
    """
    Read one EvaluationResult into a verdict, who refused, and missing keys.

    Args:
        result: One entry of the simulator's EvaluationResults.

    Returns:
        (verdict, denied_by, missing_context_keys). `denied_by` is None unless
        the verdict is DENIED.
    """
    missing = [str(key) for key in result.get("MissingContextValues") or []]
    decision = result.get("EvalDecision", "")

    if decision == "allowed":
        # A policy that needed a value we did not supply can flip an allow to
        # a deny once the value is known, so an allow with missing keys is not
        # an answer, it is an unanswered question.
        return (UNDECIDED, None, missing) if missing else (ALLOWED, None, missing)

    organizations = result.get("OrganizationsDecisionDetail") or {}
    boundary = result.get("PermissionsBoundaryDecisionDetail") or {}

    # A refusal by the organization or the boundary is decided even when
    # another policy left a key unsupplied: no later value reinstates an
    # action those layers have already denied.
    if organizations.get("AllowedByOrganizations") is False:
        return DENIED, BY_ORGANIZATION, missing
    if boundary.get("AllowedByPermissionsBoundary") is False:
        return DENIED, BY_PERMISSIONS_BOUNDARY, missing
    if missing:
        # Nothing allowed the action, but a policy that might have needed a
        # value we did not supply, so the deny may not hold in a real call.
        return UNDECIDED, None, missing
    # A deny that Organizations and the boundary both allowed, with every
    # condition decidable, came from the identity's own policies.
    return DENIED, BY_IDENTITY_POLICY, missing


def evaluate(client: Any, role_arn: str, actions: list[str], region: str | None) -> list[dict[str, Any]]:
    """
    Simulate one identity against a list of actions.

    Args:
        client:   A boto3 IAM client, already holding the caller's credentials.
        role_arn: ARN of the identity to evaluate, the caller's connected role.
        actions:  IAM action names, as the manifests declare them.
        region:   Region to supply as aws:RequestedRegion, or None to leave it
            unsupplied so a region-conditional policy reports as undecided
            rather than being judged against a guessed value.

    Returns:
        One dict per action: action, verdict, deniedBy, missingContext.
    """
    if not actions:
        return []

    request: dict[str, Any] = {
        "PolicySourceArn": role_arn,
        "ActionNames": sorted(set(actions)),
        "MaxItems": _MAX_ITEMS,
    }
    if region:
        request["ContextEntries"] = [{
            "ContextKeyName": "aws:RequestedRegion",
            "ContextKeyValues": [region],
            "ContextKeyType": "string",
        }]

    rows: list[dict[str, Any]] = []
    while True:
        response = client.simulate_principal_policy(**request)
        for result in response.get("EvaluationResults") or []:
            verdict, denied_by, missing = _decision(result)
            rows.append({
                "action": result.get("EvalActionName", ""),
                "verdict": verdict,
                "deniedBy": denied_by,
                "missingContext": missing,
            })
        if not response.get("IsTruncated"):
            return rows
        request["Marker"] = response["Marker"]


def summarise(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Reduce per-action verdicts to the figures the Prevention lane shows.

    `preventedBy` counts only an organization's service control policies. A
    role lacking a permission also stops the action, but reporting that as
    prevention would tell a reader their guardrails held when in fact their
    lab is misconfigured, which is the one mistake this feature must not make.

    Args:
        rows: The output of evaluate().

    Returns:
        Counts plus the two action lists a reader acts on.
    """
    prevented = [r["action"] for r in rows if r["deniedBy"] == BY_ORGANIZATION]
    boundary = [r["action"] for r in rows if r["deniedBy"] == BY_PERMISSIONS_BOUNDARY]
    unavailable = [r["action"] for r in rows if r["deniedBy"] == BY_IDENTITY_POLICY]
    undecided = [r["action"] for r in rows if r["verdict"] == UNDECIDED]
    return {
        "actionsChecked": len(rows),
        "prevented": sorted(prevented + boundary),
        "undecided": sorted(undecided),
        "roleCannotPerform": sorted(unavailable),
        "allowed": sorted(r["action"] for r in rows if r["verdict"] == ALLOWED),
    }


def phase_verdicts(
    attack_path: list[dict[str, Any]], rows: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """
    Fold per-action verdicts up to one verdict per attack phase.

    A phase counts as prevented when any action it needs is refused by the
    organization: an attacker who cannot make one of a phase's calls cannot
    complete it. Undecided outranks allowed for the same reason, so a phase is
    only reported as allowed when every one of its actions was decided.

    Args:
        attack_path: The emulation's phases, each carrying aws_actions.
        rows:        The output of evaluate().

    Returns:
        One dict per phase: phase, name, verdict, and the actions behind it.
    """
    by_action = {row["action"].lower(): row for row in rows}
    verdicts = []
    for phase in attack_path or []:
        actions = [a for a in phase.get("aws_actions") or [] if isinstance(a, str)]
        judged = [by_action[a.lower()] for a in actions if a.lower() in by_action]
        prevented = [r["action"] for r in judged if r["deniedBy"] in (BY_ORGANIZATION, BY_PERMISSIONS_BOUNDARY)]
        undecided = [r["action"] for r in judged if r["verdict"] == UNDECIDED]
        unavailable = [r["action"] for r in judged if r["deniedBy"] == BY_IDENTITY_POLICY]

        if not actions:
            # A phase with no IAM-authorised call, such as an exploit over
            # HTTP. No identity policy can refuse it, which is a finding
            # rather than an absence of one.
            verdict = "no_iam_call"
        elif prevented:
            verdict = DENIED
        elif undecided:
            verdict = UNDECIDED
        elif unavailable:
            verdict = "role_cannot_perform"
        else:
            verdict = ALLOWED

        verdicts.append({
            "phase": phase.get("phase"),
            "name": phase.get("name", ""),
            "verdict": verdict,
            "preventedActions": sorted(prevented),
            "undecidedActions": sorted(undecided),
            "roleCannotPerform": sorted(unavailable),
        })
    return verdicts
