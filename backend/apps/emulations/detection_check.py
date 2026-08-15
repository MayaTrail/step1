"""
Correlating an emulation run against the detection log archive.

After an attack finishes, the question a user actually has is "did my detections
catch that". Answering it needs three states, not two, because a rule that did
not alert means one of two very different things:

    fired    the rule matched events this run produced.
    silent   events for the rule's log source arrived, and none matched. Either
             the attack did not perform that action, or the rule needs tuning.
    no_logs  no events from that source reached the archive at all. The rule was
             never exercised, and the fix is in the log pipeline, not the rule.

Collapsing the last two into one number blames a rule for a gap in logging, and
hides the only finding an engineer can act on.

This module is a pure function over rules and records: no boto3, no settings, no
database. detection_logs.py owns the S3 half, the same split detections.py and
sigma_eval.py already use.
"""

from __future__ import annotations

import logging
from datetime import date, datetime, timedelta, timezone
from typing import Any

from .detections import parse_sigma_documents
from .sigma_eval import SigmaUnsupported, evaluate, is_evaluable

logger = logging.getLogger(__name__)

FIRED = "fired"
SILENT = "silent"
NO_LOGS = "no_logs"

# A run is minutes long, so its window can only touch a couple of date
# partitions. The cap stops a malformed window from listing the whole archive.
MAX_PARTITION_DAYS = 7

# Evidence is attached to a rule that fired, and to nothing else. Six empty
# blocks would bury the one that matters, so only the first match is kept.
_EVIDENCE_FIELDS = ("eventTime", "eventName", "eventSource", "sourceIPAddress")


def partition_prefixes(start: datetime, end: datetime, prefix: str) -> list[str]:
    """
    Build the archive key prefixes covering a run's date range.

    A run that crosses midnight UTC spans two date partitions, so the range is
    walked by day rather than assuming one.

    Args:
        start: Window start, UTC.
        end: Window end, UTC.
        prefix: Archive key prefix, ending in a slash, or empty.

    Returns:
        One prefix per day in the range, oldest first.
    """
    first: date = start.astimezone(timezone.utc).date()
    last: date = end.astimezone(timezone.utc).date()

    prefixes: list[str] = []
    current = first
    while current <= last and len(prefixes) < MAX_PARTITION_DAYS:
        prefixes.append(
            f"{prefix}year={current.year:04d}/month={current.month:02d}/day={current.day:02d}/"
        )
        current += timedelta(days=1)
    return prefixes


def normalise(document: dict[str, Any]) -> dict[str, Any] | None:
    """
    Reduce one archived object to the record shape the check consumes.

    The notifier writes a `detection` envelope wrapping the full `cloudtrail`
    event. The rules match on the CloudTrail half, and the envelope supplies the
    actor and is_emulation flag the evidence line needs.

    Args:
        document: Parsed contents of one archive object.

    Returns:
        A record, or None when the object carries no CloudTrail event.
    """
    event = document.get("cloudtrail")
    if not isinstance(event, dict):
        return None
    envelope = document.get("detection", {})
    return {
        "event": event,
        "actor": envelope.get("actor", ""),
        "isEmulation": bool(envelope.get("is_emulation")),
        "eventTime": event.get("eventTime", ""),
    }


def in_window(record: dict[str, Any], start: str, end: str) -> bool:
    """
    Decide whether a record falls inside the run's window.

    Compared as ISO strings, which sorts correctly for the Z-suffixed UTC
    timestamps CloudTrail writes and avoids parsing every event twice.

    Args:
        record: A normalised record.
        start: ISO-8601 window start.
        end: ISO-8601 window end.

    Returns:
        True to keep. Records with no eventTime are dropped: without a timestamp
        there is no evidence they belong to this run.
    """
    event_time = record.get("eventTime")
    return bool(event_time) and start <= event_time <= end


def evaluable_documents(sigma_text: str) -> list[dict[str, Any]]:
    """
    Parse a Sigma file and keep only the documents this evaluator can judge.

    A rule file may hold several documents: the standalone detections plus any
    correlation that ties them together. Correlations count events over a time
    window, which cannot be decided from a single event, so they are dropped
    here rather than guessed at. Their base rules remain and still carry the
    signal, which is why dropping them loses no coverage.

    Args:
        sigma_text: Raw contents of a sigma_*.yml file.

    Returns:
        The evaluable documents, possibly empty.
    """
    documents = []
    for document in parse_sigma_documents(sigma_text):
        supported, reason = is_evaluable(document)
        if supported:
            documents.append(document)
        else:
            logger.debug("Skipping non-evaluable Sigma document: %s", reason)
    return documents


def required_sources(documents: list[dict[str, Any]]) -> set[str]:
    """
    Collect the AWS event sources a rule needs in order to fire.

    Read from each document's `detection.selection.eventSource`, which may be a
    single string or a list. A rule that does not name one constrains no
    particular source, and returns an empty set meaning "cannot tell".

    Args:
        documents: Evaluable Sigma documents for one rule.

    Returns:
        Lowercased event source names, empty when undeclared.
    """
    sources: set[str] = set()
    for document in documents:
        selection = document.get("detection", {}).get("selection")
        if not isinstance(selection, dict):
            continue
        declared = selection.get("eventSource")
        if isinstance(declared, str):
            sources.add(declared.lower())
        elif isinstance(declared, list):
            sources.update(str(value).lower() for value in declared)
    return sources


def covered_sources(records: list[dict[str, Any]]) -> set[str]:
    """
    Collect the event sources actually present in the archived records.

    This is what separates "silent" from "no_logs": a rule can only be judged
    against a source the archive carries.

    Args:
        records: Normalised records as produced by detection_logs.read_records.

    Returns:
        Lowercased event source names seen in the window.
    """
    return {
        str(record["event"].get("eventSource", "")).lower()
        for record in records
        if record.get("event", {}).get("eventSource")
    }


def _matches(documents: list[dict[str, Any]], event: dict[str, Any]) -> bool:
    """
    Decide whether any of a rule's documents matches one event.

    Args:
        documents: Evaluable Sigma documents for one rule.
        event: A CloudTrail event.

    Returns:
        True when at least one document matches.
    """
    for document in documents:
        try:
            if evaluate(document, event).get("matched"):
                return True
        except SigmaUnsupported:
            # is_evaluable already filtered these out; a rule that still raises
            # is treated as not matching rather than failing the whole check.
            continue
    return False


def _evidence(record: dict[str, Any]) -> dict[str, Any]:
    """
    Reduce a matching record to the line the UI shows under a fired rule.

    Carries the actor and the archive's own is_emulation flag deliberately. The
    Phase 1 rule matches GetCallerIdentity from any assumed role outside the VPC,
    which includes an operator's own console session, so naming who triggered it
    is what stops a false positive being read as a win.

    Args:
        record: A normalised record that matched.

    Returns:
        Flat dict of display fields.
    """
    event = record.get("event", {})
    evidence = {field: event.get(field) for field in _EVIDENCE_FIELDS}
    evidence["actor"] = record.get("actor", "")
    evidence["isEmulation"] = record.get("isEmulation", False)
    return evidence


def check_rule(
    rule_id: str,
    sigma_text: str,
    records: list[dict[str, Any]],
    covered: set[str],
) -> dict[str, Any]:
    """
    Produce one rule's verdict against the archived records.

    Args:
        rule_id: Technique grouping key, e.g. "t1190".
        sigma_text: Raw contents of the rule's sigma file.
        records: Normalised records inside the run's window.
        covered: Event sources present in those records.

    Returns:
        Dict with the rule's verdict, match count, required sources and, when it
        fired, the first matching event as evidence.
    """
    documents = evaluable_documents(sigma_text)
    required = required_sources(documents)

    matched = [record for record in records if _matches(documents, record["event"])]

    if matched:
        verdict = FIRED
    elif required and not (required & covered):
        # None of the sources this rule needs reached the archive, so it was
        # never exercised. Reporting "silent" here would blame the rule.
        verdict = NO_LOGS
    else:
        verdict = SILENT

    return {
        "ruleId": rule_id,
        "verdict": verdict,
        "matchCount": len(matched),
        "requiredSources": sorted(required),
        "evaluableDocuments": len(documents),
        "evidence": _evidence(matched[0]) if matched else None,
    }


def build_report(
    rules: list[dict[str, Any]],
    records: list[dict[str, Any]],
    window: dict[str, str] | None = None,
) -> dict[str, Any]:
    """
    Assemble the full coverage report for one run.

    Args:
        rules: One dict per rule with ruleId, title, severity and sigma text.
               Rules that ship no Sigma rule are skipped: a KQL-only rule cannot
               be judged in process.
        records: Normalised records inside the run's window.
        window: Optional {"start", "end"} ISO timestamps, echoed for display.

    Returns:
        The report persisted on the run and rendered by the coverage page.
    """
    covered = covered_sources(records)

    checked: list[dict[str, Any]] = []
    for rule in rules:
        sigma_text = rule.get("sigma")
        if not sigma_text:
            continue
        outcome = check_rule(rule["ruleId"], sigma_text, records, covered)
        outcome["title"] = rule.get("title", "")
        outcome["severity"] = rule.get("severity", "")
        outcome["technique"] = rule.get("technique", {})
        checked.append(outcome)

    counts = {
        FIRED: sum(1 for rule in checked if rule["verdict"] == FIRED),
        SILENT: sum(1 for rule in checked if rule["verdict"] == SILENT),
        NO_LOGS: sum(1 for rule in checked if rule["verdict"] == NO_LOGS),
    }

    # Fired first, then the rules worth investigating, then the logging gaps.
    order = {FIRED: 0, SILENT: 1, NO_LOGS: 2}
    checked.sort(key=lambda rule: (order[rule["verdict"]], rule["ruleId"]))

    return {
        "status": "ok",
        "window": window or {},
        "eventCount": len(records),
        "coveredSources": sorted(covered),
        "ruleCount": len(checked),
        "counts": counts,
        "rules": checked,
    }
