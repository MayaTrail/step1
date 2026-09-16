"""
Coverage over time, and detection regressions between runs.

Everything here reads the `detection_check` payloads already stored on
EmulationRun - no new data is captured. A run records, per rule, whether it
fired / stayed silent / had no logs; lining those up across a user's runs gives
two things the product could not show before:

  * a coverage trend (is my detection posture improving or decaying?), and
  * regression detection (which rule that *used* to fire has gone silent?).

The second is the one that turns a one-time assessment into continuous
assurance: "T1496 fired last week and is silent today" is the alert a detection
team actually wants, and it is the difference between a report and a subscription.

Pure functions over querysets and dicts, so they test without AWS, a worker, or
a live run.
"""

from __future__ import annotations

from typing import Any

FIRED = "fired"
SILENT = "silent"
NO_LOGS = "no_logs"


def _verdict_map(detection_check: dict | None) -> dict[str, str]:
    """Map ruleId -> verdict from a stored detection_check, or {} if absent."""
    if not detection_check or detection_check.get("status") != "ok":
        return {}
    out: dict[str, str] = {}
    for rule in detection_check.get("rules", []) or []:
        rule_id = rule.get("ruleId")
        verdict = rule.get("verdict")
        if rule_id and verdict:
            out[rule_id] = verdict
    return out


def _titles(detection_check: dict | None) -> dict[str, str]:
    """Map ruleId -> title, for human-readable regression messages."""
    if not detection_check:
        return {}
    return {
        r["ruleId"]: r.get("title", r["ruleId"])
        for r in detection_check.get("rules", []) or []
        if r.get("ruleId")
    }


def snapshot(run) -> dict[str, Any]:
    """
    One point on the coverage trend for a completed run.

    fidelity is fired / rules-evaluated (0..1), the same "share that actually
    fired" the run page shows - not a fabricated score.
    """
    check = run.detection_check or {}
    counts = check.get("counts") or {}
    fired = counts.get(FIRED, 0)
    rule_count = check.get("ruleCount") or 0
    return {
        "runId": str(run.id),
        "emulationType": run.emulation_type,
        "completedAt": run.completed_at.isoformat() if run.completed_at else None,
        "counts": {
            FIRED: counts.get(FIRED, 0),
            SILENT: counts.get(SILENT, 0),
            NO_LOGS: counts.get(NO_LOGS, 0),
        },
        "ruleCount": rule_count,
        "fidelity": round(fired / rule_count, 3) if rule_count else None,
    }


def coverage_trend(runs) -> list[dict[str, Any]]:
    """
    Build the trend from an iterable of runs (oldest first for charting).

    Only runs whose detection check completed carry a coverage point; the rest
    are skipped rather than plotted as zero, which would read as a collapse.
    """
    points = [
        snapshot(run)
        for run in runs
        if (run.detection_check or {}).get("status") == "ok"
    ]
    points.sort(key=lambda p: p["completedAt"] or "")
    return points


def compare(previous_check: dict | None, current_check: dict | None) -> dict[str, Any]:
    """
    Diff two runs' verdicts.

    Args:
        previous_check: the earlier run's detection_check.
        current_check:  the later run's detection_check.

    Returns:
        {
          regressions: [{ruleId, title, from, to}],   # fired -> not fired
          improvements: [{ruleId, title, from, to}],  # not fired -> fired
          unchanged: int,
        }

    A regression is any rule that fired before and does not fire now - the
    finding a team must act on. no_logs -> silent is not a regression (the rule
    was never confirmed working); only a real loss of a working detection is.
    """
    prev = _verdict_map(previous_check)
    curr = _verdict_map(current_check)
    titles = {**_titles(previous_check), **_titles(current_check)}

    regressions: list[dict[str, Any]] = []
    improvements: list[dict[str, Any]] = []
    unchanged = 0

    for rule_id, curr_verdict in curr.items():
        prev_verdict = prev.get(rule_id)
        if prev_verdict is None:
            continue  # a newly added rule is not a regression or improvement
        if prev_verdict == curr_verdict:
            unchanged += 1
            continue
        entry = {
            "ruleId": rule_id,
            "title": titles.get(rule_id, rule_id),
            "from": prev_verdict,
            "to": curr_verdict,
        }
        if prev_verdict == FIRED and curr_verdict != FIRED:
            regressions.append(entry)
        elif prev_verdict != FIRED and curr_verdict == FIRED:
            improvements.append(entry)

    regressions.sort(key=lambda e: e["ruleId"])
    improvements.sort(key=lambda e: e["ruleId"])
    return {
        "regressions": regressions,
        "improvements": improvements,
        "unchanged": unchanged,
    }


def compare_to_previous(run, previous_run) -> dict[str, Any]:
    """
    Regression report for `run` against the run before it.

    Returns compare()'s shape plus the two run ids, or an empty report with
    `hasPrevious: False` when there is nothing to compare against.
    """
    if previous_run is None:
        return {"hasPrevious": False, "regressions": [], "improvements": [], "unchanged": 0}
    result = compare(previous_run.detection_check, run.detection_check)
    result["hasPrevious"] = True
    result["previousRunId"] = str(previous_run.id)
    result["currentRunId"] = str(run.id)
    result["previousCompletedAt"] = (
        previous_run.completed_at.isoformat() if previous_run.completed_at else None
    )
    return result


def compare_runs(earlier_run, later_run) -> dict[str, Any]:
    """
    A full side-by-side of two runs, not just what broke.

    `compare()` answers "what regressed since last time" and is what the
    banner and the assurance summary need. This answers a different question -
    "I changed something; did it work?" - which needs every rule on the table,
    including the ones that did not move, and the two runs' own figures beside
    each other.

    Args:
        earlier_run: the baseline run (the "before").
        later_run:   the run being judged (the "after").

    Returns:
        {
          a: snapshot(earlier), b: snapshot(later),
          fidelityDelta: float | None,      # b - a, in points of the 0..1 share
          rows: [{ruleId, title, a, b, change}],
          summary: {regressed, improved, unchanged, added, removed},
        }

    `change` is one of regressed / improved / changed / unchanged / added /
    removed. "changed" covers a move that is neither a loss nor a gain of a
    working detection (silent -> no_logs, say): worth showing, not worth
    alarming about. A rule present in only one run is added or removed rather
    than being scored as a regression, because the rule set itself moved.
    """
    a_check = earlier_run.detection_check if earlier_run else None
    b_check = later_run.detection_check if later_run else None

    a_verdicts = _verdict_map(a_check)
    b_verdicts = _verdict_map(b_check)
    titles = {**_titles(a_check), **_titles(b_check)}

    summary = {
        "regressed": 0, "improved": 0, "changed": 0,
        "unchanged": 0, "added": 0, "removed": 0,
    }
    rows: list[dict[str, Any]] = []

    for rule_id in sorted(set(a_verdicts) | set(b_verdicts)):
        before = a_verdicts.get(rule_id)
        after = b_verdicts.get(rule_id)

        if before is None:
            change = "added"
        elif after is None:
            change = "removed"
        elif before == after:
            change = "unchanged"
        elif before == FIRED:
            change = "regressed"
        elif after == FIRED:
            change = "improved"
        else:
            change = "changed"

        summary[change] += 1
        rows.append({
            "ruleId": rule_id,
            "title": titles.get(rule_id, rule_id),
            "a": before,
            "b": after,
            "change": change,
        })

    # Regressions first - the rows someone opened this page to find.
    order = {"regressed": 0, "improved": 1, "changed": 2, "removed": 3, "added": 4, "unchanged": 5}
    rows.sort(key=lambda r: (order[r["change"]], r["ruleId"]))

    a_snap = snapshot(earlier_run) if earlier_run else None
    b_snap = snapshot(later_run) if later_run else None
    delta = None
    if a_snap and b_snap and a_snap["fidelity"] is not None and b_snap["fidelity"] is not None:
        delta = round(b_snap["fidelity"] - a_snap["fidelity"], 3)

    return {
        "a": a_snap,
        "b": b_snap,
        "fidelityDelta": delta,
        "rows": rows,
        "summary": summary,
    }


def build_assurance(runs, schedules, now, failed_run_count: int = 0) -> dict[str, Any]:
    """
    A portfolio-level assurance summary for the dashboard.

    Answers the question the old dashboard could not: "is my detection posture
    holding right now?" Built from the latest completed run of each emulation
    (current coverage + what was missed), that run vs the one before it
    (regressions), and the user's schedules (what is coming).

    Args:
        runs: the user's COMPLETED EmulationRuns, any emulation, each with a
            detection_check. Order does not matter; grouped and sorted here.
        schedules: the user's enabled ScheduledRuns.
        now: reference time (UTC), for "next scheduled" ordering.
        failed_run_count: how many recent runs failed to complete - surfaced as
            an attention item, since a failed run is a blind spot too.

    Returns:
        A dict the dashboard's command-center renders directly.
    """
    from collections import defaultdict

    by_type: dict[str, list] = defaultdict(list)
    for run in runs:
        by_type[run.emulation_type].append(run)

    fired = 0
    total = 0
    missed = 0    # silent: activity happened, no rule caught it
    no_data = 0   # no_logs: the rule could not even be judged
    emulations_scored = 0
    regressions: list[dict[str, Any]] = []
    improvements = 0

    for emulation_type, group in by_type.items():
        group.sort(key=lambda r: r.completed_at or "")
        latest = group[-1]
        check = latest.detection_check or {}
        if check.get("status") == "ok":
            counts = check.get("counts") or {}
            fired += counts.get(FIRED, 0)
            missed += counts.get(SILENT, 0)
            no_data += counts.get(NO_LOGS, 0)
            total += check.get("ruleCount") or 0
            emulations_scored += 1

        if len(group) >= 2:
            diff = compare(group[-2].detection_check, latest.detection_check)
            improvements += len(diff["improvements"])
            for reg in diff["regressions"]:
                regressions.append({
                    "emulationType": emulation_type,
                    "runId": str(latest.id),
                    "ruleId": reg["ruleId"],
                    "title": reg["title"],
                    "from": reg["from"],
                    "to": reg["to"],
                })

    regressions.sort(key=lambda r: (r["emulationType"], r["ruleId"]))

    upcoming = sorted(
        (s for s in schedules if s.enabled),
        key=lambda s: s.next_run_at,
    )
    schedule_rows = [
        {
            "emulationType": s.emulation_type,
            "cadence": s.cadence,
            "nextRunAt": s.next_run_at.isoformat() if s.next_run_at else None,
        }
        for s in upcoming
    ]

    return {
        "hasRuns": bool(by_type),
        "coverage": {
            "fired": fired,
            "missed": missed,
            "noData": no_data,
            "total": total,
            "pct": round(fired / total, 3) if total else None,
            "emulationsScored": emulations_scored,
        },
        "regressions": regressions,
        "improvements": improvements,
        "failedRunCount": failed_run_count,
        "schedules": schedule_rows,
        "scheduleCount": len(schedule_rows),
    }
