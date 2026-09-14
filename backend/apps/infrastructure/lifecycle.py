"""
Reading a stack's recorded lifecycle, and what normal looks like for it.

Two things are derived here, both from `Stack.status_history`:

    phases      how long the stack spent in each status it entered, with the
                current one still counting.
    baselines   the median time other stacks of the same emulation spent in each
                status, so "6m 41s in Deploying" can be called slow or not.

The baseline is a median of that emulation's own past deploys, never a figure
from a MANIFEST. An authored estimate describes what someone expected; the
median describes what this emulation actually does in this account, which is the
only fair thing to measure a running deploy against.

Pure functions over history lists and durations: no querysets here beyond the
one the baseline builder is handed, so the arithmetic is testable without a
database.
"""

from __future__ import annotations

import statistics
from datetime import datetime
from typing import Any

from django.utils import timezone

# A status a stack rests in rather than passes through. Time spent here is not
# part of "how long did it take", so it is excluded from baselines: a stack left
# sitting in ready_for_attack overnight would otherwise make every later deploy
# look instant by comparison.
RESTING_STATUSES = frozenset({
    "ready", "ready_for_attack", "attack_complete", "destroyed", "failed",
})

# Below this many samples a median is noise dressed up as a number, so no
# baseline is reported and the UI simply shows the elapsed time.
MIN_SAMPLES_FOR_BASELINE = 3

# How much longer than the median counts as worth flagging. Deploys vary with
# AWS itself, so a small overshoot is normal and only a clear outlier is called
# slow.
SLOW_MULTIPLIER = 1.5


def _parse(value: str | None) -> datetime | None:
    """
    Read an ISO-8601 timestamp from a history entry.

    Args:
        value: The stored string, or None.

    Returns:
        An aware datetime, or None when the value is missing or unparseable. A
        bad entry drops that phase's duration rather than failing the page.
    """
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None


def phases(history: list[dict[str, Any]], *, now: datetime | None = None) -> list[dict[str, Any]]:
    """
    Turn a status history into measured phases.

    Args:
        history: The stack's status_history, oldest first.
        now: Override for the current time, for tests.

    Returns:
        One dict per entry with its status, when it was entered, how many
        seconds were spent in it, and whether it is still running. The last
        entry is open: its duration counts up from the moment it was entered,
        which is what makes a stuck deploy visible.
    """
    moment = now or timezone.now()
    result = []
    for index, entry in enumerate(history or []):
        entered = _parse(entry.get("at"))
        if entered is None:
            continue

        following = history[index + 1] if index + 1 < len(history) else None
        ended = _parse(following.get("at")) if following else None
        current = following is None

        seconds = None
        if ended is not None:
            seconds = max((ended - entered).total_seconds(), 0)
        elif current:
            seconds = max((moment - entered).total_seconds(), 0)

        result.append({
            "status": entry.get("status", ""),
            "at": entry.get("at"),
            "seconds": seconds,
            "current": current,
            "detail": entry.get("detail", ""),
        })
    return result


def baselines(histories: list[list[dict[str, Any]]]) -> dict[str, int]:
    """
    Compute the median seconds each status takes, across past stacks.

    Only completed phases count. An open phase has not finished, so folding its
    elapsed time into a median would drag the figure down every time a stack is
    mid-deploy, which is exactly when the baseline is being read.

    Args:
        histories: status_history lists from other stacks of the same emulation.

    Returns:
        Median seconds per status, omitting any status with fewer than
        MIN_SAMPLES_FOR_BASELINE completed samples.
    """
    samples: dict[str, list[float]] = {}
    for history in histories:
        for phase in phases(history):
            if phase["current"] or phase["seconds"] is None:
                continue
            if phase["status"] in RESTING_STATUSES:
                continue
            samples.setdefault(phase["status"], []).append(phase["seconds"])

    return {
        status: round(statistics.median(values))
        for status, values in samples.items()
        if len(values) >= MIN_SAMPLES_FOR_BASELINE
    }


def annotate(
    history: list[dict[str, Any]],
    baseline: dict[str, int] | None = None,
    *,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    """
    Build the phase list the UI renders, marking any phase running long.

    Args:
        history: The stack's status_history.
        baseline: Median seconds per status for this emulation, or None when
            there are not enough past runs to say.
        now: Override for the current time, for tests.

    Returns:
        Phases, each additionally carrying `baselineSeconds` and `slow`. `slow`
        is only ever True when a baseline exists: without past runs to compare
        against, a long phase is simply a long phase, not a problem.
    """
    reference = baseline or {}
    annotated = []
    for phase in phases(history, now=now):
        expected = reference.get(phase["status"])
        seconds = phase["seconds"]
        annotated.append({
            **phase,
            "baselineSeconds": expected,
            "slow": bool(
                expected and seconds is not None and seconds > expected * SLOW_MULTIPLIER
            ),
        })
    return annotated
