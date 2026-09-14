"""
Turning a run's match results into figures a client can act on.

Three separate numbers rather than one, because they measure different things
and blending them destroys the only signal worth having.

    detectionCoverage   of the detections that were genuinely exercised, how
                        many did the SIEM report.
    integrationHealth   did the SIEM report anything at all during the window.
    unattributed        alerts that arrived and matched no expected detection.

The distinction that matters most is between a detection that stayed silent and
one that was never exercised. A client whose webhook is not wired up has every
rule silent, and scoring that as nought percent tells their detection engineers
their rules are bad when the actual fault is a missing integration. Those are
different teams, different fixes, and a score that cannot tell them apart is
worse than no score.
"""

from __future__ import annotations

from typing import Any

from .correlate import FIRED, NOT_INTEGRATED, SILENT

# Unattributed alerts are kept as a sample, not in full. A busy SIEM can raise
# hundreds during a thirty minute window, and the report is stored as JSON on the
# run: keeping every one would grow a row without bound to show a reader rows
# they will not read. The true total is reported separately, so the count stays
# honest even when the list is trimmed.
MAX_UNATTRIBUTED_STORED = 25


def _percent(numerator: int, denominator: int) -> int | None:
    """
    Express a ratio as a whole percentage.

    Args:
        numerator: Count of the outcome being measured.
        denominator: Count it is measured against.

    Returns:
        A rounded percentage, or None when there is nothing to measure. None is
        deliberately not zero: "no detections were exercised" and "no detections
        fired" would otherwise render identically.
    """
    if denominator <= 0:
        return None
    return round(numerator * 100 / denominator)


def build_score(
    matched: dict[str, Any],
    *,
    endpoint_configured: bool,
    alerts_received: int,
) -> dict[str, Any]:
    """
    Assemble the workflow's result from its match outcome.

    Args:
        matched: The output of correlate.match_alerts.
        endpoint_configured: Whether the owner has an alert endpoint at all.
        alerts_received: How many alerts were attributed to the run's window.

    Returns:
        Dict with per-verdict counts, the figures above, and a `status`
        naming what the run established. Every rule is reported as
        `not_integrated` when no alert route exists, so a setup problem is
        never presented as a detection failure.
    """
    rules = matched.get("rules", [])
    unattributed = matched.get("unmatched", [])

    # With no endpoint, or no alert at all in the window, nothing was exercised.
    # Rewriting every verdict here rather than in correlate keeps that module a
    # pure function of rules and alerts, with no opinion about integration.
    integrated = endpoint_configured and alerts_received > 0
    if not integrated:
        rules = [{**rule, "verdict": NOT_INTEGRATED, "matchTier": "", "evidence": None}
                 for rule in rules]

    counts = {
        FIRED: sum(1 for rule in rules if rule["verdict"] == FIRED),
        SILENT: sum(1 for rule in rules if rule["verdict"] == SILENT),
        NOT_INTEGRATED: sum(1 for rule in rules if rule["verdict"] == NOT_INTEGRATED),
    }
    exercised = counts[FIRED] + counts[SILENT]

    if not endpoint_configured:
        status = "no_endpoint"
    elif alerts_received == 0:
        status = "no_alerts"
    elif not rules:
        status = "no_rules"
    else:
        status = "ok"

    return {
        "status": status,
        "counts": counts,
        "ruleCount": len(rules),
        "alertsReceived": alerts_received,
        "detectionCoverage": _percent(counts[FIRED], exercised),
        "integrationHealth": integrated,
        "unattributedCount": len(unattributed),
        "unattributedTruncated": len(unattributed) > MAX_UNATTRIBUTED_STORED,
        "rules": rules,
        "unattributed": unattributed[:MAX_UNATTRIBUTED_STORED],
    }


def headline(score: dict[str, Any]) -> str:
    """
    Describe a finished run in one sentence, for a list row or a notification.

    Args:
        score: The output of build_score.

    Returns:
        A sentence stating what the run established. Each unfinished state gets
        its own wording, because "0 of 7" and "we never heard from your SIEM"
        call for completely different actions from the reader.
    """
    counts = score.get("counts", {})
    if score.get("status") == "no_endpoint":
        return "No alert endpoint configured, so nothing could be validated."
    if score.get("status") == "no_alerts":
        return "Your SIEM sent no alerts during this run, so no detection was exercised."
    if score.get("status") == "no_rules":
        return "This emulation ships no detection rules to validate."
    return (
        f"Your SIEM reported {counts.get(FIRED, 0)} of "
        f"{counts.get(FIRED, 0) + counts.get(SILENT, 0)} expected detections."
    )
