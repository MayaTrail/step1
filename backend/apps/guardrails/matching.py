"""
Which guardrail policies bear on an emulation's attack.

MayaTrail answers "did you detect it". This answers the question underneath:
could the action have been refused before detection ever mattered. A policy
that denies s3:PutBucketVersioning makes codefinger's version purge impossible,
which is a stronger outcome than catching it afterwards.

The verdict is three-valued on purpose, and that is the whole design:

    blocks              the policy denies the action with no condition attached
    blocks_conditional  it denies the action, but a Condition decides
    unrelated           no action in the policy touches the attack

The middle case is the common one. Of the statements in the shipped corpus, a
large minority carry a Condition such as aws:PrincipalOrgID or
aws:SourceVpce, and their values belong to the reader's organisation, not to
us. Collapsing those into "blocks" would tell a customer they are protected on
the strength of a condition we never evaluated, which is the one failure a
security product cannot afford.

Nothing here claims a policy is deployed. The library is a catalogue of
published AWS samples, so every result means "if you deployed this", and the
caller is responsible for saying so.
"""

from __future__ import annotations

import fnmatch
import json
import re
from typing import Any

BLOCKS = "blocks"
BLOCKS_CONDITIONAL = "blocks_conditional"
UNRELATED = "unrelated"

# Ordering for display: the rows a reader opened this for come first.
_RANK = {BLOCKS: 0, BLOCKS_CONDITIONAL: 1, UNRELATED: 2}

# How precisely a policy addresses this attack.
#
#   targeted  it names the actions, or a narrow prefix of them
#   broad     it matched through a service-wide wildcard such as "s3:*"
#
# The distinction decides ranking, and the first version got this backwards by
# sorting on how many actions a policy matched. A perimeter policy denying
# "s3:*" matches all eleven actions of an S3 attack and says only "tighten your
# perimeter"; the policy that denies SSE-C uploads matches one and names the
# exact mechanism codefinger uses to hold data to ransom. Breadth looked like
# strength and buried the recommendation worth reading.
TARGETED = "targeted"
BROAD = "broad"
_SCOPE_RANK = {TARGETED: 0, BROAD: 1}

# A statement whose Action is "*" denies everything, which is true but useless
# as a recommendation: it would match every emulation and tell nobody anything.
# Such statements are only reported when the policy also names a service
# explicitly somewhere, so a targeted policy that happens to use a broad
# statement is still surfaced.
_MATCH_ALL = "*"


def _as_list(value: Any) -> list[str]:
    """Normalise a policy field that may be a string or a list of strings."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return [item for item in value if isinstance(item, str)]


def _statements(document: dict[str, Any]) -> list[dict[str, Any]]:
    """The Statement entries of a policy document, whatever shape it came in."""
    statement = document.get("Statement")
    if isinstance(statement, dict):
        return [statement]
    if isinstance(statement, list):
        return [item for item in statement if isinstance(item, dict)]
    return []


def action_matches(pattern: str, action: str) -> bool:
    """
    Whether one policy Action entry covers one attack action.

    Case-insensitive because IAM is, and wildcard-aware because roughly a third
    of the corpus uses patterns such as "s3:Put*" or "s3:*".

    Args:
        pattern: An Action entry from a policy, e.g. "s3:Put*".
        action:  An action the attack performs, e.g. "s3:PutObject".

    Returns:
        True when the pattern covers the action.
    """
    return fnmatch.fnmatch(action.lower(), pattern.lower())


def _is_broad(pattern: str) -> bool:
    """
    Whether an Action pattern covers a whole service rather than named actions.

    "s3:*" and "*" are broad; "s3:Put*" is not, because it still selects a
    family of actions rather than everything the service offers.

    Args:
        pattern: An Action entry from a policy.

    Returns:
        True when the pattern is service-wide.
    """
    return pattern == _MATCH_ALL or pattern.endswith(":*")


def _statement_verdict(
    statement: dict[str, Any], actions: list[str]
) -> tuple[str, list[str], str]:
    """
    Judge one statement against the attack's actions.

    Only Deny statements can prevent anything, so an Allow is never reported as
    protection. NotAction is skipped rather than guessed at: a Deny on
    NotAction denies everything except what it lists, and treating that as
    coverage of the listed actions would invert its meaning.

    Args:
        statement: One Statement entry.
        actions:   The attack actions to test against.

    Returns:
        A (verdict, matched actions, scope) triple. Scope is TARGETED when any
        named pattern produced a match, because a policy that names the action
        is a more precise answer than one that happened to include it.
    """
    if statement.get("Effect") != "Deny":
        return UNRELATED, [], BROAD
    if statement.get("NotAction"):
        return UNRELATED, [], BROAD

    patterns = _as_list(statement.get("Action"))
    if not patterns:
        return UNRELATED, [], BROAD

    # A bare "*" is excluded: true of every attack, useful against none.
    specific = [p for p in patterns if p != _MATCH_ALL]
    if not specific:
        return UNRELATED, [], BROAD

    matched = set()
    scope = BROAD
    for pattern in specific:
        hits = {a for a in actions if action_matches(pattern, a)}
        if not hits:
            continue
        matched |= hits
        if not _is_broad(pattern):
            scope = TARGETED
    if not matched:
        return UNRELATED, [], BROAD

    verdict = BLOCKS_CONDITIONAL if statement.get("Condition") else BLOCKS
    return verdict, sorted(matched), scope


def match_policy(document: dict[str, Any], actions: list[str]) -> dict[str, Any]:
    """
    Judge one policy document against an attack's actions.

    A policy is only as strong as its strongest statement, so an unconditional
    Deny anywhere in it wins over a conditional one.

    Args:
        document: The parsed policy JSON.
        actions:  Every action the attack performs.

    Returns:
        {verdict, scope, actions, conditionKeys} where actions are the attack actions
        this policy covers and conditionKeys names the condition keys a reader
        has to check for themselves. Empty conditionKeys on a
        blocks_conditional result means the condition used an operator we did
        not recognise, which is still a condition.
    """
    best = UNRELATED
    scope = BROAD
    matched: set[str] = set()
    condition_keys: set[str] = set()

    for statement in _statements(document):
        verdict, actions_hit, statement_scope = _statement_verdict(statement, actions)
        if verdict == UNRELATED:
            continue
        matched.update(actions_hit)
        if statement_scope == TARGETED:
            scope = TARGETED
        if verdict == BLOCKS_CONDITIONAL:
            for operands in (statement.get("Condition") or {}).values():
                if isinstance(operands, dict):
                    condition_keys.update(operands.keys())
        if _RANK[verdict] < _RANK[best]:
            best = verdict

    return {
        "verdict": best,
        "scope": scope if best != UNRELATED else BROAD,
        "actions": sorted(matched),
        "conditionKeys": sorted(condition_keys),
    }


def emulation_actions(attack_path: list[dict[str, Any]]) -> list[str]:
    """
    Every AWS action an emulation's phases declare, de-duplicated.

    Args:
        attack_path: The manifest's attack_path entries.

    Returns:
        Sorted action names. Empty when no phase declares any, which means the
        emulation has not been analysed rather than that it performs none.
    """
    actions: set[str] = set()
    for phase in attack_path or []:
        actions.update(_as_list(phase.get("aws_actions")))
    return sorted(actions)


# An IAM action as policies spell it: a lower-case service prefix and an
# action name, "s3:DeleteObject". Wildcards are refused because a phase
# declares the calls it makes, and a call is never "s3:*".
_ACTION_RE = re.compile(r"[a-z0-9-]+:[A-Z][A-Za-z0-9]*")


def validate_aws_actions(entry: dict[str, Any]) -> list[str]:
    """
    Check that every phase of an AWS emulation declares its AWS actions.

    Prevention analysis, and the account check built on it, can only judge
    the actions a phase declares. A phase without the field is unanalysed, so
    the field is required on every phase of an AWS emulation. An empty list
    is valid: it records that the phase makes no IAM-authorised call, such as
    an exploit over HTTP or a read of instance metadata. Emulations on other
    platforms are not governed by AWS policies and are skipped.

    Never raises, so a caller can collect the errors of every emulation in one
    pass, as validate_readiness does.

    Args:
        entry: A registry catalogue entry or a MANIFEST dict.

    Returns:
        Human-readable error strings; empty when the emulation complies.
    """
    manifest = entry.get("manifest", entry) or {}
    if manifest.get("platform") != "aws":
        return []
    name = manifest.get("name") or "<unnamed>"
    errors: list[str] = []
    for index, phase in enumerate(manifest.get("attack_path") or [], start=1):
        label = f"{name}: phase {phase.get('phase', index)}"
        if "aws_actions" not in phase:
            errors.append(f"{label} has no 'aws_actions' (declare [] if it makes no IAM-authorised call)")
            continue
        actions = phase["aws_actions"]
        if not isinstance(actions, list):
            errors.append(f"{label}: 'aws_actions' must be a list (got {type(actions).__name__})")
            continue
        for action in actions:
            if not isinstance(action, str) or not _ACTION_RE.fullmatch(action):
                errors.append(f"{label}: {action!r} is not an IAM action like 's3:DeleteObject'")
    return errors


# Who performs an emulation's calls. Two identities exist for every emulation
# without being declared: the connected role, the only identity the account
# check can ask AWS about before an attack, and "anonymous", a request sent
# with no identity at all, to which no IAM policy applies.
CONNECTED_ROLE = "connected_role"
ANONYMOUS = "anonymous"
_BUILT_IN_IDENTITIES = {
    CONNECTED_ROLE: {"label": "Your connected role", "kind": CONNECTED_ROLE},
    ANONYMOUS: {"label": "No identity (anonymous request)", "kind": ANONYMOUS},
}

# Kinds an emulation declares for itself. A lab user or role is created by the
# emulation's infrastructure and named by one of its stack outputs, so it can
# be found once the lab is deployed. An attack-created identity only exists
# while the attack runs, so it can never be checked beforehand.
LAB_USER = "lab_user"
LAB_ROLE = "lab_role"
ATTACK_CREATED = "attack_created"
_DECLARABLE_KINDS = (LAB_USER, LAB_ROLE, ATTACK_CREATED)
_IDENTITY_KEY_RE = re.compile(r"[a-z][a-z0-9_]*")


def declared_identities(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """
    Every identity an emulation's phases may act as.

    Args:
        manifest: A MANIFEST dict.

    Returns:
        {key: {label, kind, ...}}: the built-in identities plus the
        emulation's own `identities` declarations.
    """
    identities = {key: dict(value) for key, value in _BUILT_IN_IDENTITIES.items()}
    for key, value in (manifest.get("identities") or {}).items():
        if isinstance(value, dict):
            identities[key] = dict(value)
    return identities


def acting_identities(phase: dict[str, Any]) -> dict[str, list[str]]:
    """
    Who performs each of a phase's actions.

    `acting_as` is either one identity, which performs every action of the
    phase, or a mapping of identity to the actions it performs, for a phase
    that switches identity partway.

    Args:
        phase: One attack_path entry.

    Returns:
        {identity: [actions]}. Empty when the phase declares no acting_as or
        makes no IAM-authorised call; a caller must then not assume anyone.
    """
    acting = phase.get("acting_as")
    if isinstance(acting, str):
        actions = _as_list(phase.get("aws_actions"))
        return {acting: actions} if actions else {}
    if isinstance(acting, dict):
        return {key: _as_list(value) for key, value in acting.items() if _as_list(value)}
    return {}


def validate_acting_as(entry: dict[str, Any]) -> list[str]:
    """
    Check that every action of an AWS emulation names the identity performing it.

    The account check judges an action against the identity that performs it.
    Asking about the wrong one gives a confident answer about someone else, so
    nothing is assumed: every phase that declares actions must say who
    performs them, and every identity it names must be built in or declared,
    with a label and, for a lab identity, the stack output that names it.

    Never raises, like validate_aws_actions, so one pass can collect the
    errors of every emulation.

    Args:
        entry: A registry catalogue entry or a MANIFEST dict.

    Returns:
        Human-readable error strings; empty when the emulation complies.
    """
    manifest = entry.get("manifest", entry) or {}
    if manifest.get("platform") != "aws":
        return []
    name = manifest.get("name") or "<unnamed>"
    errors: list[str] = []

    declared = manifest.get("identities") or {}
    if not isinstance(declared, dict):
        return [f"{name}: 'identities' must be a mapping of key to declaration"]
    for key, value in declared.items():
        label = f"{name}: identity {key!r}"
        if key in _BUILT_IN_IDENTITIES:
            errors.append(f"{label} is built in and must not be declared")
            continue
        if not isinstance(key, str) or not _IDENTITY_KEY_RE.fullmatch(key):
            errors.append(f"{label}: keys are lower-case words joined by underscores")
        if not isinstance(value, dict):
            errors.append(f"{label} must be a mapping with 'kind' and 'label'")
            continue
        if value.get("kind") not in _DECLARABLE_KINDS:
            errors.append(f"{label}: 'kind' must be one of {', '.join(_DECLARABLE_KINDS)}")
        if not isinstance(value.get("label"), str) or not value.get("label", "").strip():
            errors.append(f"{label} needs a 'label' a reader understands")
        output = value.get("output")
        if value.get("kind") in (LAB_USER, LAB_ROLE) and (not isinstance(output, str) or not output):
            errors.append(f"{label} needs the 'output' that names it once the lab is deployed")
        if value.get("kind") == ATTACK_CREATED and output is not None:
            errors.append(f"{label} is created by the attack, so no stack output can name it")

    known = set(_BUILT_IN_IDENTITIES) | set(declared)
    used: set[str] = set()
    for index, phase in enumerate(manifest.get("attack_path") or [], start=1):
        label = f"{name}: phase {phase.get('phase', index)}"
        actions = _as_list(phase.get("aws_actions"))
        acting = phase.get("acting_as")
        if not actions:
            continue
        if acting is None:
            errors.append(f"{label} declares actions but not 'acting_as' (who performs them)")
            continue
        if isinstance(acting, str):
            mapping = {acting: actions}
        elif isinstance(acting, dict):
            mapping = acting
        else:
            errors.append(f"{label}: 'acting_as' must be an identity or a mapping of identity to actions")
            continue
        covered: set[str] = set()
        for who, listed in mapping.items():
            used.add(who)
            if who not in known:
                errors.append(f"{label} acts as {who!r}, which is neither built in nor declared")
            if not isinstance(listed, list):
                errors.append(f"{label}: the actions of {who!r} must be a list")
                continue
            for action in listed:
                if action not in actions:
                    errors.append(f"{label}: {who!r} performs {action!r}, which 'aws_actions' does not declare")
                covered.add(action)
        for action in actions:
            if action not in covered:
                errors.append(f"{label}: no identity performs {action!r}")

    for key in declared:
        if key not in used:
            errors.append(f"{name}: identity {key!r} is declared but no phase acts as it")
    return errors


# A resource template: an ARN, optionally with {placeholders} filled from the
# lab's stack outputs, {account_id} and {region}; or "*" for an action AWS only
# authorises against all resources (sts:GetCallerIdentity, most List calls).
_PLACEHOLDER_RE = re.compile(r"\{([a-z0-9_]+)\}")
BUILT_IN_PLACEHOLDERS = ("account_id", "region")


def phase_resources(phase: dict[str, Any]) -> dict[str, list[str]]:
    """
    The resources each of a phase's actions targets, as declared.

    Without them AWS judges an action against "*", which asks a different
    question from the one the attack makes: a lab policy scoped to its own
    bucket says no to "*" and yes to the bucket.

    Args:
        phase: One attack_path entry.

    Returns:
        {action: [resource templates]}; an action not listed has no declaration.
    """
    declared = phase.get("aws_resources")
    if not isinstance(declared, dict):
        return {}
    return {action: _as_list(value) for action, value in declared.items() if _as_list(value)}


def placeholders(template: str) -> list[str]:
    """
    The {names} a resource template needs filled.

    Args:
        template: A resource template such as "arn:aws:s3:::{target_bucket_name}/*".

    Returns:
        The placeholder names, in order.
    """
    return _PLACEHOLDER_RE.findall(template)


def validate_resources(entry: dict[str, Any]) -> list[str]:
    """
    Check that every action the connected role or a lab identity performs names its resource.

    Their policies are scoped to specific resources, so judging an action
    against "*" reports a refusal the real attack never meets. Each such action
    must therefore declare its resource, or "*" when AWS only authorises it
    against all resources; leaving it out is what is refused. The connected
    role's resource is also what lets the emulation page fall back to a clearly
    labelled all-resources check before a lab exists. Declarations for the
    anonymous and attack-created identities are optional but must be well formed.

    Never raises, like the other contracts.

    Args:
        entry: A registry catalogue entry or a MANIFEST dict.

    Returns:
        Human-readable error strings; empty when the emulation complies.
    """
    manifest = entry.get("manifest", entry) or {}
    if manifest.get("platform") != "aws":
        return []
    name = manifest.get("name") or "<unnamed>"
    identities = declared_identities(manifest)
    errors: list[str] = []
    for index, phase in enumerate(manifest.get("attack_path") or [], start=1):
        label = f"{name}: phase {phase.get('phase', index)}"
        actions = set(_as_list(phase.get("aws_actions")))
        declared = phase.get("aws_resources")
        if declared is not None and not isinstance(declared, dict):
            errors.append(f"{label}: 'aws_resources' must map an action to its resource")
            continue
        resources = phase_resources(phase)
        for action, templates in resources.items():
            if action not in actions:
                errors.append(f"{label}: 'aws_resources' names {action!r}, which 'aws_actions' does not declare")
            for template in templates:
                if template != "*" and not template.startswith(("arn:", "{")):
                    errors.append(f"{label}: {template!r} for {action!r} is neither an ARN template nor \"*\"")
        for who, performed in acting_identities(phase).items():
            if identities.get(who, {}).get("kind") not in (CONNECTED_ROLE, LAB_USER, LAB_ROLE):
                continue
            for action in performed:
                if action not in resources:
                    errors.append(
                        f"{label}: {who!r} performs {action!r} with no 'aws_resources' entry "
                        "(name its resource, or \"*\" if AWS only authorises it against all resources)"
                    )
    return errors


def analyse(
    attack_path: list[dict[str, Any]], guardrails: list[dict[str, Any]]
) -> dict[str, Any]:
    """
    Match every guardrail in the catalogue against one emulation.

    Args:
        attack_path: The emulation's attack_path, carrying aws_actions.
        guardrails:  Catalogue entries from the guardrails registry, each with
            a `code` field holding the raw policy JSON.

    Returns:
        {analysed, actions, phases, policies, counts}. `analysed` is False when
        no phase declares actions: the page then says the emulation has not
        been analysed, rather than reporting that no policy applies, which a
        reader would take as "nothing can stop this".
    """
    actions = emulation_actions(attack_path)
    if not actions:
        return {
            "analysed": False,
            "actions": [],
            "phases": [],
            "policies": [],
            "counts": {BLOCKS: 0, BLOCKS_CONDITIONAL: 0},
        }

    policies = []
    for entry in guardrails:
        raw = entry.get("code")
        if not raw:
            continue
        try:
            document = json.loads(raw) if isinstance(raw, str) else raw
        except (ValueError, TypeError):
            continue
        result = match_policy(document, actions)
        if result["verdict"] == UNRELATED:
            continue
        policies.append({
            "id": entry.get("id"),
            "purpose": entry.get("purpose"),
            "type": entry.get("type"),
            "source": entry.get("source"),
            **result,
            # Which phases this policy would interrupt, so a reader can see
            # whether it stops the attack early or only limits the damage.
            #
            # Empty for a broad match: a policy denying "s3:*" touches every
            # phase of an S3 attack, which is a restatement of the wildcard
            # rather than a finding, and reads as analysis it has not done.
            "phases": [] if result["scope"] == BROAD else [
                phase.get("phase")
                for phase in attack_path or []
                if set(_as_list(phase.get("aws_actions"))) & set(result["actions"])
            ],
        })

    # Targeted policies lead, then the fewest actions matched. Sorting on the
    # most actions put "Block SSE-C uploads", which names codefinger's exact
    # ransom mechanism, last of nine behind perimeter policies that matched
    # everything by denying "s3:*".
    policies.sort(
        key=lambda p: (
            _RANK[p["verdict"]],
            _SCOPE_RANK[p["scope"]],
            len(p["actions"]),
            p["id"] or "",
        )
    )

    # A phase carrying aws_actions: [] is a verified finding, not a missing
    # annotation. SCARLETEEL's first two phases are container RCE over HTTP and
    # an IMDSv1 curl, neither of which is an IAM-authorised API call, so no
    # policy in any catalogue can refuse them. "Nothing denies these actions"
    # and "this phase performs no AWS actions" look identical without this.
    phase_rows = [
        {
            "phase": phase.get("phase"),
            "name": phase.get("name"),
            "annotated": "aws_actions" in phase,
            "actions": _as_list(phase.get("aws_actions")),
            "actingAs": acting_identities(phase),
            "blockedBy": [
                p["id"] for p in policies
                if phase.get("phase") in p["phases"] and p["verdict"] == BLOCKS
            ],
        }
        for phase in attack_path or []
    ]

    return {
        "analysed": True,
        "actions": actions,
        "phases": phase_rows,
        "policies": policies,
        "counts": {
            BLOCKS: sum(1 for p in policies if p["verdict"] == BLOCKS),
            BLOCKS_CONDITIONAL: sum(
                1 for p in policies if p["verdict"] == BLOCKS_CONDITIONAL
            ),
            # Broad matches are one recommendation ("tighten your perimeter")
            # wearing several names, so the page collapses them into one row.
            BROAD: sum(1 for p in policies if p["scope"] == BROAD),
            TARGETED: sum(1 for p in policies if p["scope"] == TARGETED),
        },
    }
