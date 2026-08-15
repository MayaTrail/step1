"""
Celery task for the threat intel feed.

`refresh_threat_intel_feeds` polls every enabled subscription and writes the
merged result to disk. It is pinned to the `enterprise` queue because that is
the only queue any worker consumes (docker-compose.yml, worker_enterprise runs
`--queues=enterprise`); a task left on the default queue would be scheduled by
beat and then never picked up.

The merge rules live in window.py and the per-feed parsing in parser.py. This
module is orchestration and failure reporting only.
"""

from __future__ import annotations

import logging
from typing import Any

import requests
from celery import shared_task

from . import storage
from .feeds import enabled_feeds
from .parser import FeedFetchError, fetch_feed_bytes, parse_feed
from .window import build_payload

logger = logging.getLogger(__name__)


def _failure(feed: dict[str, Any], detail: str) -> dict[str, Any]:
    """
    Build one failed-feed report row.

    Args:
        feed: The catalogue entry that failed.
        detail: Human-readable reason.

    Returns:
        A report row with status "error".
    """
    return {
        "feedId": feed["id"],
        "feedTitle": feed["title"],
        "url": feed["url"],
        "status": "error",
        "detail": detail,
        "itemCount": 0,
    }


def collect_items() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """
    Fetch and parse every enabled feed.

    One feed's failure never aborts the run: each outcome is reported
    individually so an operator can see exactly which URLs are dead. Several
    subscriptions inherited from the older forum list point at products that
    have since been acquired or shut down, and this report is how they get
    identified rather than guessed at.

    Returns:
        Tuple of (items, report), with one report row per feed carrying its id,
        title, item count and either "ok"/"empty" or the failure reason.
    """
    items: list[dict[str, Any]] = []
    report: list[dict[str, Any]] = []

    with requests.Session() as session:
        for feed in enabled_feeds():
            try:
                body = fetch_feed_bytes(feed["url"], session=session)
                parsed = parse_feed(body, dict(feed))
            except FeedFetchError as exc:
                logger.warning("Threat intel feed %s (%s) failed: %s", feed["id"], feed["title"], exc)
                report.append(_failure(dict(feed), str(exc)))
                continue
            except Exception as exc:  # noqa: BLE001 - one bad feed must not stop the run
                logger.exception("Threat intel feed %s (%s) raised", feed["id"], feed["title"])
                report.append(_failure(dict(feed), f"{type(exc).__name__}: {exc}"))
                continue

            items.extend(parsed)
            report.append({
                "feedId": feed["id"],
                "feedTitle": feed["title"],
                "url": feed["url"],
                "status": "ok" if parsed else "empty",
                "detail": "",
                "itemCount": len(parsed),
            })

    return items, report


@shared_task(name="threatintel.refresh_threat_intel_feeds", queue="enterprise")
def refresh_threat_intel_feeds() -> dict[str, Any]:
    """
    Poll every subscription and store the merged result.

    Runs daily via CELERY_BEAT_SCHEDULE in settings/base.py, and can be invoked
    by hand to populate the feed immediately.

    Returns:
        Summary dict with item and feed counts plus the path written. When no
        storage directory is configured the fetch is skipped rather than run
        and thrown away.
    """
    if not storage.is_configured():
        logger.error(
            "refresh_threat_intel_feeds skipped: THREATINTEL_DIR is unset. "
            "Set it on the worker (and backend) to enable threat intel ingestion."
        )
        return {"skipped": "THREATINTEL_DIR unset"}

    fresh, report = collect_items()
    payload = build_payload(fresh, report, storage.read_latest())

    try:
        written = storage.write_latest(payload)
    except Exception as exc:  # noqa: BLE001 - surface the storage failure in the result
        logger.exception("Could not write the threat intel feed")
        return {"error": f"{type(exc).__name__}: {exc}", "itemCount": payload["itemCount"]}

    logger.info(
        "refresh_threat_intel_feeds: %d new item(s), %d in window, %d/%d feeds ok",
        payload["newThisRun"], payload["itemCount"], payload["feedsOk"], payload["feedCount"],
    )
    return {
        "itemCount": payload["itemCount"],
        "newThisRun": payload["newThisRun"],
        "feedsOk": payload["feedsOk"],
        "feedsFailed": payload["feedsFailed"],
        **written,
    }
