"""
The evidence packet: everything one run proved, assembled in one payload.

A run already produces the facts a security team needs - which rules fired,
which stayed silent, which had no logs to judge, and what changed since last
time. Until now those facts were spread across four screens and could not
leave the product. This module gathers them into a single document a team can
read, export, and drop into the place they already keep evidence: the audit
folder, the ticket, the board pack.

Two deliberate choices:

  * **Nothing here is computed twice.** Verdicts come from the run's stored
    `detection_check`, the change report from `coverage_history`, and the
    technique metadata from the registry. The report is an assembly, not a
    second opinion, so it can never disagree with the run page.

  * **It names what was never looked for.** A campaign declares techniques in
    its attack path; the detection pack ships rules for some of them. Any
    declared technique with no rule is reported under `uncovered`, separately
    from rules that ran and stayed silent. Those are different failures - one
    is the customer's detection gap, the other is ours - and a coverage figure
    that quietly omits the second is the kind of number this product exists to
    disprove.

Pure functions over already-loaded objects, so they test without AWS, a worker,
or a live run.
"""

from __future__ import annotations

from typing import Any

from . import coverage_history

FIRED = coverage_history.FIRED
SILENT = coverage_history.SILENT
NO_LOGS = coverage_history.NO_LOGS


def _rule_rows(detection_check: dict | None) -> list[dict[str, Any]]:
    """
    One row per judged rule, carrying the verdict and the evidence behind it.

    Sorted by verdict severity first (silent, then no_logs, then fired) so the
    findings a reader must act on are at the top of the table rather than
    scattered through it.
    """
    if not detection_check or detection_check.get("status") != "ok":
        return []

    rank = {SILENT: 0, NO_LOGS: 1, FIRED: 2}
    rows = []
    for rule in detection_check.get("rules", []) or []:
        technique = rule.get("technique") or {}
        rows.append({
            "ruleId": rule.get("ruleId"),
            "title": rule.get("title") or rule.get("ruleId"),
            "verdict": rule.get("verdict"),
            "severity": rule.get("severity"),
            "matchCount": rule.get("matchCount"),
            "evaluableDocuments": rule.get("evaluableDocuments"),
            "requiredSources": rule.get("requiredSources") or [],
            "technique": {
                "id": technique.get("id"),
                "name": technique.get("name"),
                "tactic": technique.get("tactic"),
            },
        })
    rows.sort(key=lambda r: (rank.get(r["verdict"], 9), r["ruleId"] or ""))
    return rows


def _uncovered(attack_path: list[dict], rule_rows: list[dict]) -> list[dict[str, Any]]:
    """
    Techniques the campaign executes that no rule in the pack looks for.

    This is the honest counterpart to the coverage percentage. A run scores
    itself against the rules that exist; a technique with no rule never appears
    in that score at all, so without this list a campaign could report full
    coverage while executing steps nothing was watching.
    """
    judged = {
        (row["technique"].get("id") or "").upper()
        for row in rule_rows
        if row["technique"].get("id")
    }
    # A rule id like "t1059.009" is the technique id in lower case; carry both
    # so a pack that omits technique metadata still matches.
    judged |= {(row["ruleId"] or "").upper() for row in rule_rows}

    out: list[dict[str, Any]] = []
    for phase in attack_path or []:
        for technique in phase.get("techniques", []) or []:
            tid = (technique.get("id") or "").upper()
            if not tid or tid in judged:
                continue
            out.append({
                "id": technique.get("id"),
                "name": technique.get("name"),
                "phase": phase.get("phase"),
                "phaseName": phase.get("name"),
            })
    return out


def build_report(
    run,
    entry: dict | None,
    previous_run=None,
    trend_points: list[dict] | None = None,
) -> dict[str, Any]:
    """
    Assemble the evidence packet for one run.

    Args:
        run:          the EmulationRun being reported on.
        entry:        the registry entry for its emulation (display name, attack
                      path). May be None if the package is no longer installed -
                      the report still renders, minus the attack-path sections.
        previous_run: the most recent earlier completed run of the same
                      emulation, for the change report. Optional.
        trend_points: coverage_history.coverage_trend() output for this
                      emulation, so the report carries its own history.

    Returns:
        A dict the report page renders directly and the JSON export writes
        verbatim.
    """
    check = run.detection_check or {}
    counts = check.get("counts") or {}
    rule_count = check.get("ruleCount") or 0
    fired = counts.get(FIRED, 0)

    rows = _rule_rows(check)
    attack_path = (entry or {}).get("attack_path", []) or []
    uncovered = _uncovered(attack_path, rows)

    stack = getattr(run, "stack", None)

    return {
        "generatedAt": None,  # stamped by the view, which owns the clock
        "run": {
            "id": str(run.id),
            "emulationType": run.emulation_type,
            "displayName": (entry or {}).get("display_name", run.emulation_type),
            "status": run.status,
            "stackName": getattr(stack, "name", None),
            "region": getattr(stack, "region", None),
            "startedAt": run.started_at.isoformat() if run.started_at else None,
            "completedAt": run.completed_at.isoformat() if run.completed_at else None,
            "phaseCurrent": run.phase_current,
            "phaseTotal": run.phase_total,
            "operator": getattr(run.triggered_by, "email", None),
        },
        "coverage": {
            "fired": fired,
            "silent": counts.get(SILENT, 0),
            "noLogs": counts.get(NO_LOGS, 0),
            "ruleCount": rule_count,
            "fidelity": round(fired / rule_count, 3) if rule_count else None,
            "checkStatus": check.get("status"),
        },
        "findings": rows,
        "gaps": [r for r in rows if r["verdict"] != FIRED],
        "uncovered": uncovered,
        "attackPath": attack_path,
        "change": coverage_history.compare_to_previous(run, previous_run),
        "trend": trend_points or [],
    }
