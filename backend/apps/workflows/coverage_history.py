"""
Detection coverage across a user's runs of one emulation.

A single workflow answers "did your SIEM catch this attack today". Lining up
every run of the same emulation answers a different and more useful question:
which of these detections can you actually rely on.

The measure is reliability, the share of runs in which a rule fired, and the
denominator is the whole argument. Only runs that actually judged a rule count
toward it. A run where no alerts reached us never exercised the rule, so
counting it as a miss would report a detection failure where the real problem
was a missing connection, and would drag every rule on the page toward zero.

Everything here reads `WorkflowRun.score`, which the run already stored. No new
measurement is taken, so this view can never disagree with the run pages it is
built from. Pure functions over dicts and lists, so they test without AWS, a
worker or a live run.
"""

from __future__ import annotations

from typing import Any

from apps.emulations.registry import get_emulation

from .correlate import FIRED, NOT_INTEGRATED, SILENT

# A rule is judged in a run when that run reached it at all. not_integrated
# means no alert route existed, so the rule was never exercised.
_JUDGED = (FIRED, SILENT)

# Standing values, in the order a reader should care about them. A rule that has
# never fired and one that stopped firing are different problems, and an
# aggregate percentage hides both behind the same number.
NEVER_FIRED = "never_fired"
SILENT_NOW = "silent_now"
FLAKY = "flaky"
FIRING = "firing"
NO_DATA = "no_data"


def _verdicts(score: dict[str, Any] | None) -> dict[str, str]:
    """
    Map rule id to verdict for one run.

    Args:
        score: The run's stored score payload, or None when it never settled.

    Returns:
        Rule id to verdict, empty when the run has no usable score. A score
        whose own status is not "ok" still carries per-rule verdicts, and those
        verdicts are all not_integrated, so it is read rather than discarded:
        the run happened, and the page has to be able to say so.
    """
    if not score:
        return {}
    out: dict[str, str] = {}
    for rule in score.get("rules", []) or []:
        rule_id = rule.get("ruleId")
        verdict = rule.get("verdict")
        if rule_id and verdict:
            out[rule_id] = verdict
    return out


def _rule_meta(runs: list[Any]) -> dict[str, dict[str, str]]:
    """
    Collect each rule's title and severity, preferring the most recent run.

    The expected rule set can change between runs when an emulation's
    detections are edited, so this is a union rather than a read of the latest
    run. Without it a rule that has since been removed would lose its title and
    render as a bare technique id.

    Args:
        runs: Completed runs, oldest first.

    Returns:
        Rule id to {title, severity, technique}.
    """
    meta: dict[str, dict[str, str]] = {}
    for run in runs:
        for rule in (run.score or {}).get("rules", []) or []:
            rule_id = rule.get("ruleId")
            if not rule_id:
                continue
            meta[rule_id] = {
                "title": rule.get("title") or rule_id,
                "severity": rule.get("severity") or "",
                "technique": rule.get("technique") or "",
            }
    return meta


def _rule_order(runs: list[Any], meta: dict[str, dict[str, str]]) -> list[str]:
    """
    Order rules the way the newest run lists them, then any that have since gone.

    Args:
        runs: Completed runs, oldest first.
        meta: Output of _rule_meta, used to pick up rules no recent run carries.

    Returns:
        Rule ids in display order.
    """
    order: list[str] = []
    for run in reversed(runs):
        for rule in (run.score or {}).get("rules", []) or []:
            rule_id = rule.get("ruleId")
            if rule_id and rule_id not in order:
                order.append(rule_id)
    order.extend(sorted(r for r in meta if r not in order))
    return order


def sequence(runs: list[Any], rule_id: str) -> list[str]:
    """
    The judged verdicts for one rule, oldest first.

    Runs that never reached the rule are left out entirely rather than recorded
    as a miss, so this is the sequence reliability and standing are read from.

    Args:
        runs: Completed runs, oldest first.
        rule_id: The technique grouping key, for example "t1530".

    Returns:
        A list of FIRED and SILENT values, possibly empty.
    """
    out = []
    for run in runs:
        verdict = _verdicts(run.score).get(rule_id)
        if verdict in _JUDGED:
            out.append(verdict)
    return out


def reliability(runs: list[Any], rule_id: str) -> dict[str, Any] | None:
    """
    How often one rule fired in the runs that actually reached it.

    Args:
        runs: Completed runs, oldest first.
        rule_id: The technique grouping key.

    Returns:
        {pct, fired, judged} where pct is 0..100, or None when no run judged the
        rule. None rather than 0 on purpose: a rule nothing ever reached has no
        reliability, and reporting it as 0% would assert a failure that was
        never measured.
    """
    seq = sequence(runs, rule_id)
    if not seq:
        return None
    fired = seq.count(FIRED)
    return {
        "pct": round(fired / len(seq) * 100),
        "fired": fired,
        "judged": len(seq),
    }


def standing(seq: list[str]) -> dict[str, Any]:
    """
    Read a whole verdict sequence into one finding.

    Four outcomes a percentage cannot separate:

      * never_fired  the rule has no confirmed hit in any judged run
      * silent_now   it fired before and did not fire in the latest judged run
      * flaky        it fired, stopped, and came back at least once
      * firing       it is firing and has not dropped

    The streak is stated as a fact rather than as a quality claim. A rule whose
    last run passed is firing, which is not the same as being reliable, and the
    reliability percentage is what judges that.

    Args:
        seq: Judged verdicts, oldest first, from sequence().

    Returns:
        {state, streak, dips} where streak counts consecutive trailing fires
        and dips counts fired-to-not-fired transitions.
    """
    if not seq:
        return {"state": NO_DATA, "streak": 0, "dips": 0}

    dips = sum(
        1 for i in range(1, len(seq))
        if seq[i - 1] == FIRED and seq[i] != FIRED
    )

    if FIRED not in seq:
        return {"state": NEVER_FIRED, "streak": 0, "dips": dips}
    if seq[-1] != FIRED:
        return {"state": SILENT_NOW, "streak": 0, "dips": dips}

    streak = 0
    for verdict in reversed(seq):
        if verdict != FIRED:
            break
        streak += 1

    return {
        "state": FLAKY if dips else FIRING,
        "streak": streak,
        "dips": dips,
    }


def _outcomes(score: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    """
    Per-rule match tier and the alert behind each verdict.

    Carried separately from `verdicts` because the scrub only needs the verdict
    and reads it on every rule of every run, while this is read only when two
    runs are compared. Evidence is None for a rule nothing reported, which is
    what lets the comparison say "no alert arrived" rather than leaving a blank.

    Args:
        score: The run's stored score payload.

    Returns:
        Rule id to {matchTier, evidence}, empty when the run has no score.
    """
    if not score:
        return {}
    out: dict[str, dict[str, Any]] = {}
    for rule in score.get("rules", []) or []:
        rule_id = rule.get("ruleId")
        if not rule_id:
            continue
        evidence = rule.get("evidence") or None
        out[rule_id] = {
            "matchTier": rule.get("matchTier") or "",
            "evidence": {
                "ruleName": evidence.get("ruleName"),
                "severity": evidence.get("severity"),
                "firedAt": evidence.get("firedAt"),
                "receivedAt": evidence.get("receivedAt"),
            } if evidence else None,
        }
    return out


def run_gauge(run: Any) -> dict[str, Any]:
    """
    One run as a gauge: the numbers behind a single dial.

    Args:
        run: A completed WorkflowRun.

    Returns:
        A dict carrying the fired and silent shares, the coverage figure, and
        whether the run was judged at all. `coverage` is None for an unjudged
        run so the dial can draw an empty track instead of a zero, which would
        read as a total detection failure.

        `verdicts` carries this run's per-rule outcome so the page can
        recompute reliability over any window of runs without another request.
        Selecting a gauge is a scrub through history, and a round trip per
        click would make it feel broken.
    """
    score = run.score or {}
    counts = score.get("counts") or {}
    fired = counts.get(FIRED, 0)
    silent = counts.get(SILENT, 0)
    not_integrated = counts.get(NOT_INTEGRATED, 0)
    rule_count = score.get("ruleCount") or 0
    judged = fired + silent

    return {
        "runId": str(run.id),
        "completedAt": run.completed_at.isoformat() if run.completed_at else None,
        "status": score.get("status") or "unknown",
        "judged": bool(judged),
        "coverage": round(fired / rule_count * 100) if (judged and rule_count) else None,
        "fired": fired,
        "silent": silent,
        "notIntegrated": not_integrated,
        "ruleCount": rule_count,
        "alertsReceived": score.get("alertsReceived") or 0,
        "unattributedCount": score.get("unattributedCount") or 0,
        "integrationHealth": bool(score.get("integrationHealth")),
        "verdicts": _verdicts(score),
        "outcomes": _outcomes(score),
        # The alert window, for the comparison timeline. Alert latency is only
        # comparable across runs when measured from the end of the attack, and
        # the deadline is what decides whether a slow detection was still being
        # listened for.
        "windowStart": run.window_start.isoformat() if run.window_start else None,
        "windowEnd": run.window_end.isoformat() if run.window_end else None,
        "alertDeadline": run.alert_deadline.isoformat() if run.alert_deadline else None,
        # A run that reached completed without abandoning a step ran its attack:
        # the pipeline cannot produce a score without attacking first. The
        # emulation_run link is nullable and gets severed when that record is
        # removed, so reading it alone reported a finished attack as failed.
        "attackCompleted": run.status == "completed" and not run.failed_step,
    }


def build_history(
    runs: list[Any], emulation_type: str, target: int
) -> dict[str, Any]:
    """
    Assemble the coverage history payload for one emulation.

    Args:
        runs: The user's completed runs of this emulation, oldest first.
        emulation_type: Registry name of the emulation.
        target: Reliability percentage a detection is expected to meet.

    Returns:
        {emulationType, target, runs, rules, counts}. `rules` carries one row
        per expected detection with its reliability, its standing, and the
        reliability it had before the latest judged run, which is what lets the
        chart show direction without a second request.
    """
    gauges = [run_gauge(run) for run in runs]
    meta = _rule_meta(runs)

    rows = []
    for rule_id in _rule_order(runs, meta):
        seq = sequence(runs, rule_id)
        current = reliability(runs, rule_id)
        # Reliability as it stood before the most recent judged run, so the
        # chart can mark where the value moved from. Dropping the last element
        # of the judged sequence is not the same as dropping the last run: the
        # latest run may not have reached this rule at all.
        earlier = seq[:-1]
        previous = (
            {"pct": round(earlier.count(FIRED) / len(earlier) * 100)}
            if earlier else None
        )
        info = meta.get(rule_id, {})
        rows.append({
            "ruleId": rule_id,
            "title": info.get("title") or rule_id,
            "severity": info.get("severity") or "",
            "technique": info.get("technique") or "",
            "reliability": current["pct"] if current else None,
            "firedRuns": current["fired"] if current else 0,
            "judgedRuns": current["judged"] if current else 0,
            "previousReliability": previous["pct"] if previous else None,
            "meetsTarget": bool(current and current["pct"] >= target),
            **standing(seq),
        })

    judged = [g for g in gauges if g["judged"]]
    # The platform the emulation belongs to, so a rule row can link to its
    # detection page without the frontend assuming every emulation is AWS.
    platform = (get_emulation(emulation_type) or {}).get("platform", "aws")

    return {
        "emulationType": emulation_type,
        "platform": platform,
        "target": target,
        "runs": gauges,
        "rules": rows,
        "counts": {
            "runs": len(gauges),
            "judged": len(judged),
            "belowTarget": sum(
                1 for r in rows if r["reliability"] is not None and not r["meetsTarget"]
            ),
        },
    }
