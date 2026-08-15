"""
Assembling one ingest run into the document that gets stored and served.

Kept free of boto3 and celery so the merge rules — which decide what a user
actually sees on the page — are testable under the CI settings, which install
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
        True to keep. Undated items are kept — a missing date is a feed quirk,
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
    appears in both, the version just fetched wins — a publisher may have
    corrected a title or summary since the last run.

    Args:
        fresh: Items from this run.
        report: Per-feed outcome for this run.
        previous: The last stored payload, or None on the first run.
        now: Override for the run timestamp; defaults to the current UTC time.

    Returns:
        The payload to persist and serve.
    """
    moment = now or datetime.now(timezone.utc)
    carried = (previous or {}).get("items", [])
    cutoff = (moment - timedelta(days=MAX_WINDOW_DAYS)).isoformat()

    merged = dedupe_items(sort_items(fresh + carried))
    window = [item for item in merged if within_window(item, cutoff)][:MAX_WINDOW_ITEMS]

    failed = [entry for entry in report if entry.get("status") == "error"]
    ok = [entry for entry in report if entry.get("status") == "ok"]

    return {
        "fetchedOn": moment.date().isoformat() if now else date.today().isoformat(),
        "fetchedAt": moment.isoformat(),
        "items": window,
        "itemCount": len(window),
        "newThisRun": len(fresh),
        "feedCount": len(report),
        "feedsOk": len(ok),
        "feedsFailed": len(failed),
        "report": report,
    }
