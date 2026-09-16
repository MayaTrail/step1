"""
When a scheduled emulation is next due, and how a cadence advances.

Pure date arithmetic, kept out of the Beat task and the model so it can be
tested without a database or a clock. The task decides *what to do* with a due
schedule; this decides *which* are due and *when* they run next.
"""

from __future__ import annotations

from datetime import datetime, timedelta

# Cadence -> the gap to the next run. Months are approximated as 30 days
# deliberately: a detection-regression cadence does not need calendar-exact
# month boundaries, and 30 days is predictable and drift-free.
_CADENCE_DELTA = {
    "daily": timedelta(days=1),
    "weekly": timedelta(weeks=1),
    "monthly": timedelta(days=30),
}


def next_after(cadence: str, now: datetime) -> datetime:
    """
    The next run time for a cadence, measured from `now`.

    Args:
        cadence: a ScheduledRun.Cadence value.
        now: reference time (UTC).

    Returns:
        now + the cadence interval. Unknown cadences fall back to weekly rather
        than raising, so a bad stored value cannot wedge the Beat task.
    """
    return now + _CADENCE_DELTA.get(cadence, _CADENCE_DELTA["weekly"])


def advance(current_next: datetime, cadence: str, now: datetime) -> datetime:
    """
    Advance a schedule's next_run_at past `now`.

    Stepping by the cadence rather than resetting to now + interval keeps runs
    on their original cadence phase (e.g. Mondays), and the loop catches a
    schedule up cleanly if the worker was down for several intervals instead of
    firing a burst of backlogged runs.

    Args:
        current_next: the schedule's current next_run_at.
        cadence: a ScheduledRun.Cadence value.
        now: reference time (UTC).

    Returns:
        The first cadence step strictly after `now`.
    """
    delta = _CADENCE_DELTA.get(cadence, _CADENCE_DELTA["weekly"])
    nxt = current_next
    # Bound the catch-up so a very stale schedule cannot spin forever.
    for _ in range(1000):
        if nxt > now:
            return nxt
        nxt = nxt + delta
    return now + delta


def is_due(next_run_at: datetime, now: datetime) -> bool:
    """True when a schedule's next_run_at has arrived."""
    return next_run_at <= now
