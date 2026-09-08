"""
Assembling one ingest run into the document that gets stored and served.

Kept free of boto3 and celery so the merge rules, which decide what a user
actually sees on the page, are testable under the CI settings, which install
neither.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from typing import Any

from .parser import dedupe_items, sort_items

# Size of the rolling window the API serves. Enough that a quiet week still
# fills a page, small enough that latest.json stays a few hundred KB.
MAX_WINDOW_ITEMS = 600

# Items older than this drop out of the rolling window. The per-day snapshots
# under daily/ remain the full record.
MAX_WINDOW_DAYS = 120


def within_window(item: dict[str, Any], cutoff: str) -> bool:
    """
    Decide whether an item is recent enough for the rolling window.

    Args:
        item: A normalised item.
        cutoff: ISO-8601 timestamp; items published before it are dropped.

    Returns:
        True to keep. Undated items are kept: a missing date is a feed quirk,
        not evidence that the post is old.
    """
    published = item.get("publishedAt")
    return published is None or published >= cutoff


def build_payload(
    fresh: list[dict[str, Any]],
    report: list[dict[str, Any]],
    previous: dict[str, Any] | None,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """
    Merge a fetch into the previous window and assemble the stored document.

    Fresh items are placed ahead of carried ones so that when the same id
    appears in both, the version just fetched wins, because a publisher may have
    corrected a title or summary since the last run.

    Args:
        fresh: Items from this run.
        report: Per-feed outcome for this run.
        previous: The last stored payload, or None on the first run.
        now: Override for the run timestamp; defaults to the current UTC time.

    Returns:
        The payload to persist and serve. `fetchedThisRun` is how many items the
        run downloaded; `newSinceLastRun` is how many of those had not been seen
        before, which is the only one of the two worth showing a reader.
    """
    moment = now or datetime.now(timezone.utc)
    carried = (previous or {}).get("items", [])
    cutoff = (moment - timedelta(days=MAX_WINDOW_DAYS)).isoformat()

    merged = dedupe_items(sort_items(fresh + carried))
    window = [item for item in merged if within_window(item, cutoff)][:MAX_WINDOW_ITEMS]

    # Most of what a run fetches is already in the window: publishers keep old
    # posts in their feed, so a fetch of 797 items can be entirely items we
    # already had. Diffing ids against the previous window is what makes this a
    # count of genuinely new posts rather than a count of everything downloaded.
    previous_ids = {item["id"] for item in carried}
    new_items = [item for item in window if item["id"] not in previous_ids]

    failed = [entry for entry in report if entry.get("status") == "error"]
    ok = [entry for entry in report if entry.get("status") == "ok"]

    return {
        "fetchedOn": moment.date().isoformat() if now else date.today().isoformat(),
        "fetchedAt": moment.isoformat(),
        "items": window,
        "itemCount": len(window),
        "fetchedThisRun": len(fresh),
        "newSinceLastRun": len(new_items),
        "feedCount": len(report),
        "feedsOk": len(ok),
        "feedsFailed": len(failed),
        "report": report,
    }
