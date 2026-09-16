"""
Turn a real emulation run into a recording the marketing site can replay.

`site/run.html` currently ships a hand-authored simulation with an invented run
id and an invented fidelity score, on a page whose entire argument is "evidence
you can check". This replaces that fiction with a real run.

Safety model: allowlist, not scrub
----------------------------------
Every field in the output is constructed here by name. Nothing is copied from a
CloudTrail event wholesale, and no dict from the archive is ever passed through.
That matters because a CloudTrail record carries the account id, full ARNs, the
role session name (frequently a human's email), the source IP, user agents and
request parameters - and the destination for this file is a public website.

The player's own schema turns out to be exactly the right shape for this: an
event is only {eventSource, eventName, t_offset_s, note}. So the allowlist is
not an extra layer bolted on, it is what the page already consumes.

`scrub()` exists as a second line of defence for the free-text fields that come
from a MANIFEST rather than from CloudTrail - a human wrote those, and humans
paste account ids into descriptions.

Never record from a customer account, or from your own production one. Use a
dedicated account you are willing to burn: resource and role names leak org
structure even when every identifier is redacted.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)

# Patterns that must never reach a published recording. Ordered so the more
# specific ones (ARNs carry account ids) run first.
# AWS-managed policy ARNs carry the literal "aws" as the account segment, are
# identical in every account, and are unavoidable when describing a privilege
# escalation. Everything else that looks like an ARN stays flagged - including
# arn:aws:s3:::bucket, which has no account segment but names a bucket.
_AWS_MANAGED_ARN = re.compile(r"^arn:aws[a-z-]*:[a-z0-9-]+:[a-z0-9-]*:aws:")

_REDACTIONS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"arn:aws[a-z-]*:[^\s\"']+"), "<ARN>"),
    (re.compile(r"\b(?:AKIA|ASIA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{12,}\b"), "<AWS_KEY_ID>"),
    (re.compile(r"\b\d{12}\b"), "<ACCOUNT_ID>"),
    (re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"), "<EMAIL>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "<IP>"),
    (re.compile(r"\b(?:i-|vpc-|subnet-|sg-|vol-|ami-|eni-)[0-9a-f]{8,}\b"), "<RESOURCE_ID>"),
]


def _is_benign(value: str, placeholder: str) -> bool:
    """
    True when a match is public vocabulary rather than tenant data.

    Only two exemptions, both narrow: AWS-managed policy ARNs, and non-routable
    IP addresses. A private or link-local address identifies nothing outside
    the network it lives on, and 169.254.169.254 in particular is the instance
    metadata endpoint - the same constant in every AWS account, and something a
    cloud attack write-up has to be able to name.
    """
    if placeholder == "<ARN>":
        return bool(_AWS_MANAGED_ARN.match(value))
    if placeholder == "<IP>":
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return False
        return not address.is_global
    return False


def scrub(text: str) -> str:
    """
    Redact identifiers from free text destined for a public file.

    A backstop for MANIFEST-authored strings, not the primary defence - the
    primary defence is that nothing from CloudTrail is copied by value.

    Args:
        text: Free text.

    Returns:
        The text with known identifier shapes replaced by placeholders.
    """
    out = text or ""
    for pattern, placeholder in _REDACTIONS:
        out = pattern.sub(
            lambda m, p=placeholder: m.group(0) if _is_benign(m.group(0), p) else p,
            out,
        )
    return out


def find_leaks(payload: Any) -> list[str]:
    """
    Report identifier shapes surviving anywhere in a recording.

    Walks the assembled structure and matches every string. Used by the export
    command and by the website's CI check, so a recording cannot be published
    with an account id in a field nobody thought about.

    Args:
        payload: The recording, or any nested part of it.

    Returns:
        Human-readable descriptions of what was found, empty when clean.
    """
    found: list[str] = []

    def walk(node: Any, path: str) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                walk(value, f"{path}.{key}")
        elif isinstance(node, list):
            for index, value in enumerate(node):
                walk(value, f"{path}[{index}]")
        elif isinstance(node, str):
            for pattern, placeholder in _REDACTIONS:
                for match in pattern.finditer(node):
                    value = match.group(0)
                    if value in {p for _, p in _REDACTIONS}:
                        continue  # already redacted
                    if _is_benign(value, placeholder):
                        continue
                    found.append(f"{path}: {placeholder} shape -> {value[:48]}")
                    break

    walk(payload, "recording")
    return found


def _offset_seconds(event_time: str, origin: datetime | None) -> float:
    """Seconds between the run's first event and this one, floored at zero."""
    if origin is None or not event_time:
        return 0.0
    try:
        stamp = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
    except ValueError:
        return 0.0
    return max(0.0, round((stamp - origin).total_seconds(), 1))


def _origin(records: list[dict[str, Any]]) -> datetime | None:
    """The earliest event time in the archive slice, as the timeline's zero."""
    stamps: list[datetime] = []
    for record in records:
        raw = record.get("eventTime") or ""
        try:
            stamps.append(datetime.fromisoformat(raw.replace("Z", "+00:00")))
        except ValueError:
            continue
    return min(stamps) if stamps else None


def build_events(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Project CloudTrail records onto the player's event shape.

    Only four fields are constructed, by name. The source record is never
    copied: `eventSource` and `eventName` are AWS API vocabulary and carry no
    tenant data, `t_offset_s` is arithmetic, and no note is emitted at all for
    a real event because every candidate string for one (request parameters,
    resource names) is tenant data.

    Args:
        records: Normalised archive records, each {"event": {...}, "eventTime": ...}.

    Returns:
        Events in time order.
    """
    origin = _origin(records)
    events: list[dict[str, Any]] = []

    for record in records:
        event = record.get("event") or {}
        source = str(event.get("eventSource") or "").strip()
        name = str(event.get("eventName") or "").strip()
        if not source or not name:
            continue
        # Both are AWS's own vocabulary (ecs.amazonaws.com / RunTask). Anything
        # not matching that shape did not come from where we think it did, so
        # drop it rather than publish it.
        if not re.fullmatch(r"[a-z0-9.-]+\.amazonaws\.com", source):
            continue
        if not re.fullmatch(r"[A-Za-z0-9_]+", name):
            continue
        events.append(
            {
                "eventSource": source,
                "eventName": name,
                "t_offset_s": _offset_seconds(record.get("eventTime") or "", origin),
            }
        )

    events.sort(key=lambda e: e["t_offset_s"])
    return events


def _phases_from_manifest(manifest: dict) -> list[dict[str, Any]]:
    """Flatten a MANIFEST attack_path into ordered steps for the chain."""
    steps: list[dict[str, Any]] = []
    step_no = 0
    for phase in manifest.get("attack_path", []) or []:
        phase_no = phase.get("phase", len(steps) + 1)
        phase_name = scrub(str(phase.get("name", "")))
        for technique in phase.get("techniques", []) or []:
            step_no += 1
            steps.append(
                {
                    "step": step_no,
                    "phase": phase_no,
                    "technique": str(technique.get("id", "")),
                    "name": scrub(str(technique.get("name", ""))),
                    "tactic": phase_name,
                    "risk": "medium",
                    "simulated": False,
                    "documented": True,
                    "credential": None,
                    "services": [],
                    "duration_s": 0.0,
                    "events": [],
                    "detection": None,
                }
            )
    return steps


def _attach_events(steps: list[dict[str, Any]], events: list[dict[str, Any]]) -> None:
    """
    Spread the run's events across the chain in time order.

    CloudTrail does not say which attack phase produced an event, so this
    divides the timeline evenly rather than inventing a mapping it cannot
    justify. The result is honest about sequence - which is what the page
    shows - without claiming a precision the data does not support.
    """
    if not steps or not events:
        return
    per_step = max(1, len(events) // len(steps))
    cursor = 0
    for step in steps:
        slice_ = events[cursor : cursor + per_step]
        cursor += per_step
        step["events"] = slice_
        if slice_:
            step["duration_s"] = round(
                max(0.5, slice_[-1]["t_offset_s"] - slice_[0]["t_offset_s"]), 1
            )
    # Anything left over belongs to the final step rather than being dropped.
    if cursor < len(events) and steps:
        steps[-1]["events"] = steps[-1]["events"] + events[cursor:]


def _detection_registry(detection_check: dict | None) -> list[dict[str, Any]]:
    """Project the run's rule verdicts onto the player's registry shape."""
    if not detection_check or detection_check.get("status") != "ok":
        return []
    registry: list[dict[str, Any]] = []
    for rule in detection_check.get("rules", []) or []:
        technique = rule.get("technique") or {}
        registry.append(
            {
                "rule": str(rule.get("ruleId", "")),
                "technique": str(technique.get("id", "") if isinstance(technique, dict) else ""),
                "kind": "sigma",
                "severity": str(rule.get("severity", "")),
                "verdict": str(rule.get("verdict", "")),
                "title": scrub(str(rule.get("title", ""))),
            }
        )
    return registry


def build_recording(
    run,
    entry: dict,
    records: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """
    Assemble a publishable recording of one run.

    Args:
        run: The EmulationRun.
        entry: The emulation's registry catalogue entry.
        records: Normalised CloudTrail records for the run's window. Omit to
            produce a recording with the chain but no events.

    Returns:
        A dict in the shape site/run.html's player consumes.
    """
    manifest = entry.get("manifest", entry)
    events = build_events(records or [])
    steps = _phases_from_manifest(manifest)
    _attach_events(steps, events)

    check = run.detection_check or {}
    counts = check.get("counts") or {}
    rule_count = check.get("ruleCount") or 0
    fired = counts.get("fired", 0)

    duration_min = 0
    if run.started_at and run.completed_at:
        duration_min = max(1, round((run.completed_at - run.started_at).total_seconds() / 60))

    recording = {
        # Not the database id. A run's UUID is internal, and publishing it
        # invites someone to try it against the API.
        "run_id": run.started_at.strftime("%Y%m%d_%H%M%S") if run.started_at else "",
        "recorded": True,
        "threat_actor": scrub(str(manifest.get("display_name", ""))),
        "attribution": scrub(str(manifest.get("attribution", ""))),
        "source": "",
        "platform": str(manifest.get("platform", "aws")),
        "region": "us-east-1",
        "duration_real_min": duration_min,
        # Share of this run's rules that actually fired. A measured number,
        # unlike the 0.91 the hand-authored page asserted.
        "detection_rate": round(fired / rule_count, 2) if rule_count else None,
        "event_count": len(events),
        "chain": steps,
        "detection_registry": _detection_registry(check),
        "credentials": [],
        "narratives": {},
        "infra": {"resources": []},
    }

    references = manifest.get("references") or []
    if references and isinstance(references[0], dict):
        recording["source"] = str(references[0].get("url", ""))

    return recording
