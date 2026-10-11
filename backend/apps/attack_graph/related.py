"""
Which MayaTrail emulations rehearse an attack path.

A path is linked to an emulation through the AWS calls both of them make, and
only through the calls that grant new access (the escalation calls). Matching
on MITRE technique ids was ruled out: Scout and the emulation MANIFESTs often
tag the same behaviour with different ids (iam:CreateAccessKey is T1098.001 in
one and T1528 in the other), so technique matching both misses real links and
makes loose ones.

Two kinds of call never count:

    reads   Get*, List*, Describe*, Head*. Every emulation reads before it
            acts, so a shared read says nothing about the technique.
    setup   sts:AssumeRole. Most atomics assume their lab role before the
            technique runs; as a match it would tie every role-assumption step
            to unrelated emulations (DNS logs, RDS, WAF, ...).

An atomic emulation matches when it performs at least one of the path's
escalation calls. A campaign performs many calls on its own, so it matches only
when it covers all of the path's escalation calls, or at least three of them on
a longer path. Matches are ranked by how many of the path's calls they cover.

Computed when a scan is read, never stored: the catalogue changes as
emulations are added, and a stored link would go stale.
"""

from __future__ import annotations

import re
from typing import Any

from apps.emulations.detections import list_detection_summaries
from apps.emulations.registry import list_emulations

_READ_PREFIXES = ("Get", "List", "Describe", "Head")
_SETUP_CALLS = frozenset({"sts:AssumeRole"})

# A campaign must cover every escalation call of the path, up to this many.
CAMPAIGN_MIN_COVERAGE = 3

# "iam:CreateAccessKey(UserName=x)" -> "iam:CreateAccessKey". Anchored at the
# start of an entry (or of a ";"-separated part of one), so ARNs and arguments
# such as "arn:aws:iam::..." inside the parentheses are never read as calls.
_CALL_RE = re.compile(r"^\s*([a-z][a-z0-9-]*:[A-Z][A-Za-z0-9]*)\b")

_TIER_LABEL = {"atomic": "atomic", "enterprise": "campaign"}


def _counts(action: str) -> bool:
    """Whether an AWS action counts towards a match: not a read, not setup."""
    verb = action.split(":", 1)[-1]
    return action not in _SETUP_CALLS and not verb.startswith(_READ_PREFIXES)


def escalation_calls(chain: dict[str, Any]) -> list[str]:
    """
    The calls of a path that grant new access, in the order the path makes them.

    Read from each step's concrete_api_sequence. Entries in angle brackets
    ("<read IMDS credentials ...>") and CLI or shell lines ("aws ssm ...",
    "curl ...") describe effects rather than API calls and are skipped.

    Args:
        chain: One chain of a scan envelope.

    Returns:
        Distinct escalation calls such as "iam:CreateAccessKey".
    """
    calls: list[str] = []
    for step in chain.get("steps") or []:
        for entry in step.get("concrete_api_sequence") or []:
            for part in str(entry).split(";"):
                found = _CALL_RE.match(part)
                if found and _counts(found.group(1)) and found.group(1) not in calls:
                    calls.append(found.group(1))
    return calls


def _emulation_calls(entry: dict[str, Any]) -> set[str]:
    """The escalation calls an emulation's attack path performs."""
    return {
        action
        for phase in entry.get("attack_path") or []
        for action in phase.get("aws_actions") or []
        if isinstance(action, str) and _counts(action)
    }


def _matches(tier: str, covered: int, wanted: int) -> bool:
    """Whether an emulation covering `covered` of a path's `wanted` calls is a link."""
    if covered == 0:
        return False
    if tier == "enterprise":
        return covered >= min(wanted, CAMPAIGN_MIN_COVERAGE)
    return True


def _detection_count(entry: dict[str, Any], cache: dict[str, int]) -> int:
    """How many detection rules ship with an emulation, read once per request."""
    name = entry.get("name", "")
    if name not in cache:
        cache[name] = len(list_detection_summaries(entry))
    return cache[name]


def related_emulations(envelope: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    """
    The emulations linked to each path of a scan, keyed by chain id.

    Args:
        envelope: A scan's stored result envelope.

    Returns:
        {chain_id: {"escalationCalls": [...], "emulations": [...]}} for every
        chain, best match first. An empty emulations list means no emulation
        rehearses the path yet. Only AWS emulations are considered.
    """
    if not envelope or envelope.get("state") != "findings":
        return {}

    catalogue = [
        (entry, _emulation_calls(entry))
        for entry in list_emulations()
        if entry.get("platform", "aws") == "aws"
    ]
    detections: dict[str, int] = {}

    related: dict[str, dict[str, Any]] = {}
    for chain in envelope.get("chains") or []:
        wanted = escalation_calls(chain)
        links = []
        for entry, performs in catalogue:
            shared = [call for call in wanted if call in performs]
            tier = entry.get("tier", "")
            if not _matches(tier, len(shared), len(wanted)):
                continue
            links.append({
                "id": entry.get("name"),
                "name": entry.get("display_name") or entry.get("name"),
                "platform": entry.get("platform", "aws"),
                "tier": _TIER_LABEL.get(tier, tier),
                "sharedCalls": shared,
                "detectionCount": _detection_count(entry, detections),
            })
        links.sort(key=lambda link: (-len(link["sharedCalls"]), link["name"]))
        related[chain.get("id", "")] = {"escalationCalls": wanted, "emulations": links}
    return related
