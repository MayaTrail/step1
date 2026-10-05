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

Everything here works on a boto3 client handed in, so tests replay recorded
AWS responses, except `check_account`, which assumes the role and builds that
client itself. It is the one entry point the emulation page and the workflow
stage share, so both produce the same result.
"""

from __future__ import annotations

from typing import Any

from .matching import (
    ANONYMOUS,
    ATTACK_CREATED,
    CONNECTED_ROLE,
    LAB_ROLE,
    LAB_USER,
    acting_identities,
    declared_identities,
    phase_resources,
    placeholders,
)

# Verdicts, narrower than AWS's decision strings because the question here is
# "would a guardrail stop this", not "what does the policy say".
ALLOWED = "allowed"
DENIED = "denied"
UNDECIDED = "undecided"
# An action performed by an identity other than the connected role. Judging it
# against the connected role would describe the wrong identity, so it is not
# sent to AWS and carries no verdict about the reader's policies.
NOT_CHECKED = "not_checked"

# An action sent with no identity at all, such as a read of a public bucket. No
# IAM rule can judge it, so it is a fact about the phase rather than a gap in
# the check: it is listed, but left out of phase verdicts and of the not
# checked count.
NO_IDENTITY = "no_identity"

# Why an identity was or was not asked about. The frontend words each one.
CHECKED = "checked"
NOT_DEPLOYED = "not_deployed"
NOT_EXPORTED = "not_exported"

# Who performs a phase's actions when its MANIFEST does not say. The contract
# test forbids this for AWS emulations; the check still refuses to assume the
# connected role if one slips through.
UNDECLARED = "undeclared"

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


def evaluate(
    client: Any, role_arn: str, actions: list[str], region: str | None, resource: str | None = None
) -> list[dict[str, Any]]:
    """
    Simulate one identity against a list of actions, on one resource.

    Args:
        client:   A boto3 IAM client, already holding the caller's credentials.
        role_arn: ARN of the identity to evaluate, the caller's connected role.
        actions:  IAM action names, as the manifests declare them.
        region:   Region to supply as aws:RequestedRegion, or None to leave it
            unsupplied so a region-conditional policy reports as undecided
            rather than being judged against a guessed value.
        resource: The ARN the actions target, or None or "*" for all
            resources, which is what AWS assumes when none is given.

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
    if resource and resource != "*":
        request["ResourceArns"] = [resource]
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
        rows: The output of evaluate(), plus not-checked rows for actions
            another identity performs.

    Returns:
        Counts plus the action lists a reader acts on. `actionsChecked`
        counts only what AWS evaluated.
    """
    # A lab identity lacking a permission is the emulation's own setup, not
    # the reader's role, so it is reported apart from roleCannotPerform.
    connected = [r for r in rows if r.get("identity", CONNECTED_ROLE) == CONNECTED_ROLE]
    prevented = [r["action"] for r in rows if r["deniedBy"] == BY_ORGANIZATION]
    boundary = [r["action"] for r in rows if r["deniedBy"] == BY_PERMISSIONS_BOUNDARY]
    unavailable = [r["action"] for r in connected if r["deniedBy"] == BY_IDENTITY_POLICY]
    undecided = [r["action"] for r in rows if r["verdict"] == UNDECIDED]
    not_checked = [r["action"] for r in rows if r["verdict"] == NOT_CHECKED]
    no_identity = [r["action"] for r in rows if r["verdict"] == NO_IDENTITY]
    return {
        "actionsChecked": len(rows) - len(not_checked) - len(no_identity),
        "notChecked": sorted(not_checked),
        "noIdentity": sorted(no_identity),
        "labCannotPerform": sorted(
            r["action"] for r in rows
            if r["deniedBy"] == BY_IDENTITY_POLICY and r.get("identity", CONNECTED_ROLE) != CONNECTED_ROLE
        ),
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
    complete it, whoever makes the others. Otherwise a phase with an action
    nobody checked cannot be called allowed, so not-checked comes next.
    Undecided then outranks allowed for the same reason, so a phase is only
    reported as allowed when every one of its actions was decided.

    Rows are matched to a phase by identity and action, because one action
    can be made by two identities in the same emulation. A phase without an
    acting_as declaration is matched by action alone.

    Args:
        attack_path: The emulation's phases, each carrying aws_actions.
        rows:        Per-action rows, each with the identity that performs it.

    Returns:
        One dict per phase: phase, name, verdict, the actions behind it, and
        the (identity, action) rows it was judged on.
    """
    by_pair = {(row.get("identity", CONNECTED_ROLE), row["action"].lower()): row for row in rows}
    by_action: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_action.setdefault(row["action"].lower(), []).append(row)

    verdicts = []
    for phase in attack_path or []:
        actions = [a for a in phase.get("aws_actions") or [] if isinstance(a, str)]
        acting = acting_identities(phase)
        if rows and all("phases" in row for row in rows):
            # Rows built by check_account name the phases they belong to, which
            # keeps one action on two resources in two phases apart.
            judged = [row for row in rows if phase.get("phase") in row["phases"]]
        elif acting:
            judged = [
                by_pair[(who, action.lower())]
                for who, listed in acting.items()
                for action in listed
                if (who, action.lower()) in by_pair
            ]
        else:
            judged = [row for action in actions for row in by_action.get(action.lower(), [])]
        anonymous = [r for r in judged if r["verdict"] == NO_IDENTITY]
        rows_judged = judged
        judged = [r for r in judged if r["verdict"] != NO_IDENTITY]
        prevented = [r["action"] for r in judged if r["deniedBy"] in (BY_ORGANIZATION, BY_PERMISSIONS_BOUNDARY)]
        not_checked = [r for r in judged if r["verdict"] == NOT_CHECKED]
        undecided = [r["action"] for r in judged if r["verdict"] == UNDECIDED]
        unavailable = [r["action"] for r in judged if r["deniedBy"] == BY_IDENTITY_POLICY]

        if not actions:
            # A phase with no IAM-authorised call, such as an exploit over
            # HTTP. No identity policy can refuse it, which is a finding
            # rather than an absence of one.
            verdict = "no_iam_call"
        elif not judged and anonymous:
            verdict = NO_IDENTITY
        elif prevented:
            verdict = DENIED
        elif not_checked:
            verdict = NOT_CHECKED
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
            "notCheckedActions": sorted({r["action"] for r in not_checked}),
            "notCheckedIdentities": sorted({r.get("identity", "") for r in not_checked}),
            "rows": [{"identity": r.get("identity", CONNECTED_ROLE), "action": r["action"]} for r in rows_judged],
        })
    return verdicts


def _fill(template: str, values: dict[str, str]) -> str | None:
    """
    Fill a resource template's placeholders.

    Args:
        template: An ARN template, or "*".
        values:   Placeholder values: the lab's outputs, account_id and region.

    Returns:
        The ARN, or None when a placeholder has no value.
    """
    names = placeholders(template)
    if any(not values.get(name) for name in names):
        return None
    for name in names:
        template = template.replace("{" + name + "}", values[name])
    return template


def _scope(templates: tuple[str, ...]) -> str:
    """
    How precisely an action's resource was named, for the reader.

    Returns:
        "specific" for a named resource, "all" for a declared "*" (an action
        AWS only authorises against all resources), "unspecified" when the
        emulation names none and AWS judged it against all resources by default.
        The caller substitutes "fallback" for a connected-role resource it could
        not fill because no lab is deployed, judged against all resources for now.
    """
    if not templates:
        return "unspecified"
    return "all" if all(template == "*" for template in templates) else "specific"


# How serious one simulated answer is, lowest first: a guardrail's refusal, then
# a value AWS could not decide, then a missing permission, then an allow.
_SEVERITY = {BY_ORGANIZATION: 0, BY_PERMISSIONS_BOUNDARY: 1, BY_IDENTITY_POLICY: 3}


def _severity(row: dict[str, Any]) -> int:
    """Rank one answer so the most serious of several resources stands."""
    if row["deniedBy"] in _SEVERITY:
        return _SEVERITY[row["deniedBy"]]
    return 2 if row["verdict"] == UNDECIDED else 4


def _principal_arn(kind: str, value: str, account_id: str) -> str:
    """
    The ARN of a lab identity from the stack output that names it.

    An output may hold the ARN itself or just the name. A name is joined to
    the default IAM path, which every lab identity uses.

    Args:
        kind:       LAB_USER or LAB_ROLE.
        value:      The output's value.
        account_id: The account the lab was deployed to.

    Returns:
        The principal's ARN.
    """
    if value.startswith("arn:"):
        return value
    return f"arn:aws:iam::{account_id}:{'user' if kind == LAB_USER else 'role'}/{value}"


def check_account(
    role_arn: str,
    session_name: str,
    emulation_type: str,
    manifest: dict[str, Any],
    region: str,
    outputs: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Ask AWS about every action an identity it can find performs, and build the result.

    AWS's answer describes one identity, so each action is judged against the
    identity that performs it. The connected role is always asked about. A
    lab user or role is asked about once the lab exists, found through the
    stack output its declaration names. An identity the attack creates, or a
    request sent with no identity, cannot be asked about, and says so rather
    than borrowing an answer about someone else. When nothing can be asked
    about, no AWS call is made at all.

    The caller must have confirmed the emulation declares actions: an empty
    request would come back as "nothing refused", which reads as a finding.

    Args:
        role_arn:       The connected role to assume. Every simulation runs
                        through its session, whichever identity it evaluates.
        session_name:   STS session name, so CloudTrail shows who asked.
        emulation_type: Registry name of the emulation.
        manifest:       Its MANIFEST, carrying attack_path with aws_actions.
        region:         Supplied as aws:RequestedRegion to region conditions.
        outputs:        The deployed lab's stack outputs, or None when no lab
                        is deployed. Only the outputs that name an identity
                        are read; the rest, access keys among them, are not.

    Returns:
        The account check result: identity, region, summary, per-action rows
        (each naming its identity), per-phase verdicts, and the identities the
        attack acts as, each with its status.

    Raises:
        botocore ClientError or BotoCoreError when STS or IAM refuses. What a
        refusal means differs per caller, so it is theirs to interpret.
    """
    attack_path = manifest.get("attack_path") or []
    declared = declared_identities(manifest)
    account_id = role_arn.split(":")[4] if role_arn.count(":") >= 5 else ""

    # Who performs each action and against which resources, keyed by
    # (identity, action, resource templates), with the phases it appears in.
    # The same action can target different resources in different phases, so
    # the templates are part of the key. A phase that declares actions but not
    # who performs them is attributed to nobody rather than to the connected role.
    entries: dict[tuple[str, str, tuple[str, ...]], list[Any]] = {}
    for phase in attack_path:
        actions = [a for a in phase.get("aws_actions") or [] if isinstance(a, str)]
        targets = phase_resources(phase)
        for who, listed in (acting_identities(phase) or ({UNDECLARED: actions} if actions else {})).items():
            for action in listed:
                entries.setdefault((who, action, tuple(targets.get(action, ()))), []).append(phase.get("phase"))
    used: list[str] = []
    for who, _action, _targets in entries:
        if who not in used:
            used.append(who)

    # Which identities can be asked about, and as which principal.
    status: dict[str, str] = {}
    principal: dict[str, str] = {}
    for who in used:
        kind = declared.get(who, {}).get("kind", UNDECLARED)
        if kind == CONNECTED_ROLE:
            status[who], principal[who] = CHECKED, role_arn
        elif kind == ANONYMOUS:
            status[who] = NO_IDENTITY
        elif kind == ATTACK_CREATED:
            status[who] = ATTACK_CREATED
        elif kind in (LAB_USER, LAB_ROLE):
            value = (outputs or {}).get(declared[who].get("output", ""))
            if outputs is None:
                status[who] = NOT_DEPLOYED
            elif not isinstance(value, str) or not value:
                status[who] = NOT_EXPORTED
            else:
                status[who], principal[who] = CHECKED, _principal_arn(kind, value, account_id)
        else:
            status[who] = UNDECLARED

    # Fill each resource template. Only the outputs a template names are read.
    values = {key: value for key, value in (outputs or {}).items() if isinstance(value, str) and value}
    values.update({"account_id": account_id, "region": region})
    resolved: dict[tuple[str, str, tuple[str, ...]], list[str]] = {}
    # Connected-role actions whose resource named a lab output no lab has yet,
    # so they were judged against all resources and must say so to the reader.
    fallback: set[tuple[str, str, tuple[str, ...]]] = set()
    for key in entries:
        who, _action, templates = key
        if who not in principal:
            continue
        arns = [_fill(template, values) for template in templates] or ["*"]
        if any(arn is None for arn in arns):
            # The connected role always exists, so an unfillable template means
            # the lab that would name the resource is not deployed. Judge the
            # action against all resources and label it, rather than hiding the
            # role's other answers. A lab identity instead needs the output that
            # names it, so a missing one is a redeploy, not a fallback.
            if declared.get(who, {}).get("kind") == CONNECTED_ROLE:
                arns = ["*"]
                fallback.add(key)
            else:
                status[who] = NOT_EXPORTED
                del principal[who]
                continue
        resolved[key] = arns

    rows: list[dict[str, Any]] = []
    if principal:
        # Imported here so the pure functions above stay importable where boto3
        # is not installed, as in the CI test environment.
        import boto3

        # 900 seconds is the shortest session STS allows; the simulations need
        # a fraction of it, and the credentials are never stored.
        assumed = boto3.client("sts").assume_role(
            RoleArn=role_arn,
            RoleSessionName=session_name,
            DurationSeconds=900,
        )
        credentials = assumed["Credentials"]
        iam = boto3.client(
            "iam",
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
        )
        # AWS evaluates one principal at a time, and a list of resources as the
        # same question asked of each, so one simulation per (principal, resource).
        batches: dict[tuple[str, str], set[str]] = {}
        for (who, action, _templates), arns in resolved.items():
            if who in principal:
                for arn in arns:
                    batches.setdefault((who, arn), set()).add(action)
        answers: dict[tuple[str, str, str], dict[str, Any]] = {}
        for (who, arn), actions in batches.items():
            for row in evaluate(iam, principal[who], sorted(actions), region, arn):
                answers[(who, row["action"].lower(), arn)] = row
        for key, arns in resolved.items():
            who, action, templates = key
            if who not in principal:
                continue
            judged = [answers[(who, action.lower(), arn)] for arn in arns if (who, action.lower(), arn) in answers]
            if not judged:
                continue
            # Several resources: the most serious answer stands, because a call
            # refused on any one of them is a call the attack cannot complete.
            worst = min(judged, key=_severity)
            rows.append({
                **worst,
                "action": action,
                "identity": who,
                "phases": entries[key],
                "resourceScope": "fallback" if key in fallback else _scope(templates),
            })
    for (who, action, templates), phases in entries.items():
        if who in principal:
            continue
        verdict = NO_IDENTITY if status[who] == NO_IDENTITY else NOT_CHECKED
        rows.append({
            "action": action, "identity": who, "verdict": verdict, "deniedBy": None, "missingContext": [],
            "phases": phases, "resourceScope": _scope(templates),
        })

    identities = [
        {
            "key": who,
            "label": declared.get(who, {}).get("label", "Not declared by this emulation"),
            "kind": declared.get(who, {}).get("kind", UNDECLARED),
            "actions": len({action for owner, action, _templates in entries if owner == who}),
            "checked": status[who] == CHECKED,
            "status": status[who],
        }
        for who in used
    ]

    return {
        "emulationType": emulation_type,
        "displayName": manifest.get("display_name", emulation_type),
        "basis": "simulated",
        "region": region,
        # The role's name, not its ARN: the result has no need to carry an
        # account id. Lab identities are named by label only, for the same reason.
        "identity": role_arn.rsplit("/", 1)[-1],
        "summary": summarise(rows),
        "actions": rows,
        "phases": phase_verdicts(attack_path, rows),
        "identities": identities,
    }


def aws_error(exc: Exception) -> tuple[str, str]:
    """
    Read the error code and message out of a botocore exception.

    Args:
        exc: A ClientError, BotoCoreError or anything else raised by boto3.

    Returns:
        (code, message). The code is empty when AWS sent none, as with a
        network failure. The message can name the caller's ARN, account id
        included, so it is for logs and for the caller's own response only.
    """
    code = ""
    message = str(exc)
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        error = response.get("Error") or {}
        code = error.get("Code", "")
        message = error.get("Message", message)
    return code, message


def cannot_simulate(code: str, message: str) -> bool:
    """
    Tell whether an AWS refusal means the role lacks the simulate permission.

    That is a one-line policy addition for roles connected before this feature
    existed, not a fault, so callers offer the fix instead of an error.

    Args:
        code:    The AWS error code.
        message: The AWS error message.

    Returns:
        True when AWS denied iam:SimulatePrincipalPolicy itself.
    """
    return code == "AccessDenied" and "simulateprincipalpolicy" in message.lower()
