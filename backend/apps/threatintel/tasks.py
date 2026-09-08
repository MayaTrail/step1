"""
Celery task for the threat feed.

`refresh_threat_feeds` polls every enabled subscription, matches the result
against the emulation catalogue and writes the merged document to disk. It is
pinned to the `enterprise` queue because that is the only queue any worker
consumes (docker-compose.yml, worker_enterprise runs `--queues=enterprise`); a
task left on the default queue would be scheduled by beat and never picked up.

The merge rules live in window.py, the per-feed parsing in parser.py and the
matching in correlate.py. This module is orchestration and failure reporting
only.
"""

from __future__ import annotations

import logging
from typing import Any

import requests
from celery import shared_task

from . import correlate, storage
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
                logger.warning("Threat feed %s (%s) failed: %s", feed["id"], feed["title"], exc)
                report.append(_failure(dict(feed), str(exc)))
                continue
            except Exception as exc:  # noqa: BLE001 - one bad feed must not stop the run
                logger.exception("Threat feed %s (%s) raised", feed["id"], feed["title"])
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


def _emulation_index() -> correlate.EmulationIndex:
    """
    Build the catalogue index the window is matched against.

    The registry reads MANIFEST files from EMULATIONS_BASE_DIR. A deployment
    without that directory mounted gets an empty index and therefore an
    uncorrelated feed, which is the correct degradation: the feed itself is
    still worth reading.

    Returns:
        An EmulationIndex over whatever the registry could discover.
    """
    from apps.emulations.registry import list_emulations

    catalogue = list_emulations()
    if not catalogue:
        logger.warning("Threat feed correlation skipped: the emulation registry returned no entries.")
    return correlate.build_index(catalogue)


def refresh_feed() -> dict[str, Any]:
    """
    Poll every subscription, correlate the window and store the result.

    Shared by the Celery task and the refresh_threat_feed management command so
    both take the identical path.

    Returns:
        Summary dict with item and feed counts plus the path written, or a
        dict carrying `skipped` or `error` when the run could not complete.
    """
    if not storage.is_configured():
        logger.error(
            "Threat feed refresh skipped: THREATINTEL_DIR is unset. "
            "Set it on the worker (and backend) to enable threat feed ingestion."
        )
        return {"skipped": "THREATINTEL_DIR unset"}

    fresh, report = collect_items()
    payload = build_payload(fresh, report, storage.read_latest())
    payload["items"] = correlate.annotate(payload["items"], _emulation_index())
    payload["relatedCount"] = sum(1 for item in payload["items"] if item["matches"])

    try:
        written = storage.write_latest(payload)
    except Exception as exc:  # noqa: BLE001 - surface the storage failure in the result
        logger.exception("Could not write the threat feed")
        return {"error": f"{type(exc).__name__}: {exc}", "itemCount": payload["itemCount"]}

    logger.info(
        "Threat feed refreshed: %d fetched, %d new, %d in window, %d related, %d/%d feeds ok",
        payload["fetchedThisRun"], payload["newSinceLastRun"], payload["itemCount"],
        payload["relatedCount"], payload["feedsOk"], payload["feedCount"],
    )
    return {
        "itemCount": payload["itemCount"],
        "fetchedThisRun": payload["fetchedThisRun"],
        "newSinceLastRun": payload["newSinceLastRun"],
        "relatedCount": payload["relatedCount"],
        "feedsOk": payload["feedsOk"],
        "feedsFailed": payload["feedsFailed"],
        "report": report,
        **written,
    }


@shared_task(name="threatintel.refresh_threat_feeds", queue="enterprise")
def refresh_threat_feeds() -> dict[str, Any]:
    """
    Celery entry point for the daily refresh.

    Scheduled by CELERY_BEAT_SCHEDULE in settings/base.py.

    Returns:
        The summary from refresh_feed(), minus the per-feed report, which is
        too large to keep in the Celery result backend and is already stored in
        the written document.
    """
    result = refresh_feed()
    result.pop("report", None)
    return result
