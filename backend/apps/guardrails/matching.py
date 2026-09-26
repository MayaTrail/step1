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

    phase_rows = [
        {
            "phase": phase.get("phase"),
            "name": phase.get("name"),
            "actions": _as_list(phase.get("aws_actions")),
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
