"""
Building the list of detections an emulation expects its attack to trigger.

The detections app already discovers and parses an emulation's rules; this adds
the one thing correlation needs and that a summary does not carry: the Sigma
document ids. Every rule MayaTrail ships declares a unique Sigma UUID, and when
a client has deployed those rules into their SIEM the alert names that UUID, so
it is the only match in the ladder that is an identity rather than an inference.

Kept out of correlate.py so that module stays a pure function over dicts, and
out of detections.py so the emulations app gains nothing for a feature it does
not own.
"""

from __future__ import annotations

import logging
from typing import Any

from apps.emulations.detections import list_detection_summaries, parse_sigma_documents

logger = logging.getLogger(__name__)


def _sigma_ids(sigma_text: str) -> list[str]:
    """
    Read the Sigma document ids out of a rule file.

    A rule file may hold several documents, and a client's SIEM will name
    whichever one fired, so all of them are collected rather than the first.

    Args:
        sigma_text: The rule file's contents, possibly multi-document YAML.

    Returns:
        Lower-cased ids in file order. A file that fails to parse yields none
        rather than raising: a malformed rule should cost that one rule its
        exact-match tier, not fail the whole workflow.
    """
    try:
        documents = parse_sigma_documents(sigma_text or "")
    except Exception as exc:  # noqa: BLE001 - one bad rule must not stop a run
        logger.warning("Could not parse Sigma while collecting ids: %s", exc)
        return []

    ids = []
    for document in documents:
        value = document.get("id") if isinstance(document, dict) else None
        if value:
            ids.append(str(value).strip().lower())
    return ids


def expected_detections(entry: dict[str, Any]) -> list[dict[str, Any]]:
    """
    List the detections that should fire when this emulation runs.

    Args:
        entry: A registry catalogue entry for the emulation.

    Returns:
        One dict per rule carrying ruleId, title, severity, technique and the
        `sigmaIds` correlation needs. Empty when the emulation ships no rules,
        which scoring reports as nothing to validate rather than a zero score.
    """
    rules = []
    for summary in list_detection_summaries(entry):
        rules.append({
            "ruleId": summary.get("ruleId", ""),
            "title": summary.get("title", ""),
            "severity": summary.get("severity", ""),
            "technique": summary.get("technique", {}),
            "sigmaIds": _sigma_ids(summary.get("sigma", "")),
        })
    return rules
