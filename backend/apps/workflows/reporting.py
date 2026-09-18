"""
The evidence packet for one workflow run.

A run tells a client which of an emulation's expected detections their SIEM
reported. This assembles that into something they can hand to an auditor: the
per-rule verdicts, the alert behind each one, the techniques nobody is watching,
and the figures, with the wording that keeps each claim honest.

Pure assembly over data already stored. Verdicts come from `WorkflowRun.score`,
technique metadata from the emulation registry. Never a second opinion, so a
report can never disagree with the run page it came from.

Rewritten from the emulations app's version, which read
`EmulationRun.detection_check`: CloudTrail pulled out of a MayaTrail-owned S3
bucket and replayed against our own rules. That path was retired in September.
Verdicts now come from the client's own SIEM, which changes what the evidence
column means: not "N log documents matched this rule" but "this alert, from
your SIEM, at this time".
"""

from __future__ import annotations

from typing import Any

from apps.emulations.registry import get_emulation

from .correlate import FIRED, NOT_INTEGRATED, SILENT

# Findings a reader has to act on come first. A silent rule is the finding; a
# not_integrated rule is a setup task; a fired rule needs nothing.
_VERDICT_RANK = {SILENT: 0, NOT_INTEGRATED: 1, FIRED: 2}


def _rule_rows(score: dict[str, Any] | None) -> list[dict[str, Any]]:
    """
    One row per expected detection, with its verdict and evidence.

    Args:
        score: The run's stored score payload, or None before it settles.

    Returns:
        Rows sorted so silent rules lead, then not_integrated, then fired.
        Empty when the run has not settled.
    """
    if not score:
        return []

    rows = []
    for rule in score.get("rules", []) or []:
        evidence = rule.get("evidence") or None
        rows.append({
            "ruleId": rule.get("ruleId"),
            "title": rule.get("title") or rule.get("ruleId"),
            "verdict": rule.get("verdict"),
            "severity": rule.get("severity"),
            "technique": rule.get("technique"),
            # How confidently the alert was tied to this rule: an exact Sigma id
            # citation, or a technique match. Empty for a rule nothing reached.
            "matchTier": rule.get("matchTier") or "",
            # The alert itself, so a verdict can always be traced to the thing
            # the client's SIEM actually sent.
            "evidence": {
                "alertId": evidence.get("alertId"),
                "ruleId": evidence.get("ruleId"),
                "ruleName": evidence.get("ruleName"),
                "severity": evidence.get("severity"),
                "firedAt": evidence.get("firedAt"),
                "receivedAt": evidence.get("receivedAt"),
            } if evidence else None,
        })

    rows.sort(key=lambda row: (_VERDICT_RANK.get(row["verdict"], 9), row["ruleId"] or ""))
    return rows


def _uncovered(attack_path: list[dict], rule_rows: list[dict]) -> list[dict[str, Any]]:
    """
    Techniques the emulation executes that no rule in our pack looks for.

    The honest counterpart to the coverage figure. A run is scored against the
    rules that exist, so a technique with no rule never enters the score at all,
    and without this list an emulation could report full coverage while
    executing steps nothing was watching.

    This is a gap in MayaTrail's content, not in the client's detection stack,
    and the report has to say so in those words.

    Args:
        attack_path: The emulation's MANIFEST attack_path.
        rule_rows: Rows from _rule_rows.

    Returns:
        One entry per unwatched technique, in attack-path order.
    """
    judged = {str(row.get("technique") or "").upper() for row in rule_rows}
    # A rule id like "t1078.004" is the technique id lower-cased, so carry both
    # and a pack that omits technique metadata still matches.
    judged |= {str(row.get("ruleId") or "").upper() for row in rule_rows}
    judged.discard("")

    out: list[dict[str, Any]] = []
    for phase in attack_path or []:
        for technique in phase.get("techniques", []) or []:
            tid = str(technique.get("id") or "").upper()
            if not tid or tid in judged:
                continue
            out.append({
                "id": technique.get("id"),
                "name": technique.get("name"),
                "phase": phase.get("phase"),
                "phaseName": phase.get("name"),
            })
    return out


def coverage_sentence(score: dict[str, Any] | None, uncovered: list[dict]) -> str:
    """
    State the coverage figure in words that cannot be misread.

    Always "n of m rules evaluated", never a bare percentage, and always naming
    what the figure excludes. A bare "40%" invites a reader to believe it
    describes their whole exposure; it describes the rules that exist.

    Args:
        score: The run's score payload.
        uncovered: Techniques from _uncovered.

    Returns:
        A sentence, or an explanation of why there is no figure.
    """
    if not score:
        return "This run has not settled, so nothing has been measured yet."

    counts = score.get("counts") or {}
    fired = counts.get(FIRED, 0)
    total = score.get("ruleCount", 0)

    if score.get("status") == "no_endpoint":
        return (
            "No alert endpoint was configured, so none of these "
            f"{total} rules was exercised. This is a setup gap, not a detection gap."
        )
    if score.get("status") == "no_alerts":
        return (
            f"Your SIEM sent no alerts during this run, so none of these {total} "
            "rules could be judged. That is a question for your alert pipeline."
        )
    if not total:
        return "This emulation ships no detection rules, so there was nothing to evaluate."

    sentence = f"Your SIEM reported {fired} of {total} rules evaluated."
    if uncovered:
        sentence += (
            f" {len(uncovered)} technique{'s' if len(uncovered) != 1 else ''} this "
            "emulation executes are excluded from that figure, because MayaTrail "
            "ships no rule for them."
        )
    return sentence


def build_report(workflow: Any) -> dict[str, Any]:
    """
    Assemble the evidence packet for one workflow run.

    Args:
        workflow: A WorkflowRun, settled or otherwise.

    Returns:
        The packet: run identity, the figures, per-rule rows with evidence,
        unwatched techniques, and the sentences that qualify each claim.
    """
    entry = get_emulation(workflow.emulation_type) or {}
    manifest = entry.get("manifest", entry) or {}

    score = workflow.score or None
    rows = _rule_rows(score)
    uncovered = _uncovered(manifest.get("attack_path") or [], rows)

    return {
        "run": {
            "id": str(workflow.id),
            "emulationType": workflow.emulation_type,
            "displayName": manifest.get("display_name", workflow.emulation_type),
            "status": workflow.status,
            "failedStep": workflow.failed_step,
            "createdAt": workflow.created_at.isoformat() if workflow.created_at else None,
            "startedAt": workflow.started_at.isoformat() if workflow.started_at else None,
            "completedAt": workflow.completed_at.isoformat() if workflow.completed_at else None,
            "windowStart": workflow.window_start.isoformat() if workflow.window_start else None,
            "windowEnd": workflow.window_end.isoformat() if workflow.window_end else None,
            "stackName": workflow.stack.name if workflow.stack_id else None,
            "owner": workflow.owner.username,
        },
        "score": {
            "status": (score or {}).get("status"),
            "counts": (score or {}).get("counts") or {},
            "ruleCount": (score or {}).get("ruleCount", 0),
            "alertsReceived": (score or {}).get("alertsReceived", 0),
            # Null rather than zero when nothing was exercised: a zero reads as
            # "your detections failed", which is a different and worse claim.
            "detectionCoverage": (score or {}).get("detectionCoverage"),
            "integrationHealth": (score or {}).get("integrationHealth", False),
        },
        "rules": rows,
        "uncovered": uncovered,
        "unattributed": {
            "count": (score or {}).get("unattributedCount", 0),
            "truncated": (score or {}).get("unattributedTruncated", False),
            "alerts": (score or {}).get("unattributed") or [],
        },
        "coverageSentence": coverage_sentence(score, uncovered),
    }
