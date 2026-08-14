"""
Views for the threatintel app.

All endpoints require IsEnterpriseUser.

GET /api/threat-intel/feed/       ThreatIntelFeedView
GET /api/threat-intel/sources/    ThreatIntelSourceListView
GET /api/threat-intel/advisories/ AdvisoryListView

The feed is read from the S3 snapshot the daily Celery task writes; these views
never fetch RSS themselves, so a slow publisher can never slow down a request.
A missing snapshot returns zero counts rather than an error, so the UI shows
its empty state instead of a failure.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.infrastructure.permissions import IsEnterpriseUser

from . import storage
from .feeds import public_sources

logger = logging.getLogger(__name__)

# The snapshot changes once a day, so re-reading it from S3 on every request is
# waste. Held in-process like the guardrails registry cache, but with a TTL so
# a long-lived gunicorn worker still picks up the new snapshot the same day.
#
# Only a *successful* read is cached. Caching the absence of a snapshot would
# mean that after the very first ingest completes, the page keeps showing its
# empty state for up to another TTL — and because gunicorn runs several worker
# processes each holding their own cache, a refresh would flip between empty
# and populated depending on which one answered. A missing object is one cheap
# S3 call, so re-checking every time is the better trade.
CACHE_TTL_SECONDS = 300

# Items returned when the caller does not ask for a specific page size.
DEFAULT_LIMIT = 100
MAX_LIMIT = 600

_cache: tuple[float, dict[str, Any] | None] | None = None


def reset_cache() -> None:
    """
    Clear the in-process snapshot cache so the next request re-reads S3.

    Use after an out-of-band ingest run, or in tests that need a clean state.
    """
    global _cache  # noqa: PLW0603
    _cache = None


def _snapshot() -> dict[str, Any] | None:
    """
    Return the current snapshot, reading successful results through a cache.

    Returns:
        The stored payload, or None when no run has completed or the bucket is
        unreadable. A None result is never cached, so the first snapshot to
        land is served immediately rather than after the TTL expires.
    """
    global _cache  # noqa: PLW0603
    now = time.monotonic()
    if _cache is not None and now - _cache[0] < CACHE_TTL_SECONDS:
        return _cache[1]

    payload = storage.read_latest()
    if payload is not None:
        _cache = (now, payload)
    return payload


def _limit(request: Request) -> int:
    """
    Read the `limit` query parameter.

    Args:
        request: DRF request.

    Returns:
        A page size clamped to [1, MAX_LIMIT]; DEFAULT_LIMIT when absent or
        not an integer.
    """
    raw = request.query_params.get("limit")
    if raw is None:
        return DEFAULT_LIMIT
    try:
        return max(1, min(MAX_LIMIT, int(raw)))
    except ValueError:
        return DEFAULT_LIMIT


class ThreatIntelFeedView(APIView):
    """
    Return the aggregated RSS items from the most recent ingest run.

    GET /api/threat-intel/feed/?limit=100&feedId=<id>

    `feedId` narrows the response to one publication; `limit` caps the number
    of items. Both are optional.
    """

    permission_classes = [IsEnterpriseUser]

    def get(self, request: Request) -> Response:
        """
        Read the stored snapshot and serialise its item window.

        Args:
            request: DRF request.

        Returns:
            200 with items, counts and the run's freshness metadata. An
            unavailable snapshot returns the same shape with zero counts and
            `fetchedAt: null`.
        """
        snapshot = _snapshot()
        if snapshot is None:
            return Response({
                "items": [],
                "itemCount": 0,
                "totalCount": 0,
                "sourceCount": 0,
                "fetchedAt": None,
                "feedsOk": 0,
                "feedsFailed": 0,
            })

        items: list[dict[str, Any]] = snapshot.get("items", [])

        feed_id = request.query_params.get("feedId")
        if feed_id:
            items = [item for item in items if item.get("feedId") == feed_id]

        total = len(items)
        items = items[: _limit(request)]

        return Response({
            "items": items,
            "itemCount": len(items),
            "totalCount": total,
            "sourceCount": len({item.get("feedId") for item in snapshot.get("items", [])}),
            "fetchedAt": snapshot.get("fetchedAt"),
            "feedsOk": snapshot.get("feedsOk", 0),
            "feedsFailed": snapshot.get("feedsFailed", 0),
        })


class ThreatIntelSourceListView(APIView):
    """
    Return the subscription list backing the feed.

    GET /api/threat-intel/sources/

    Served from the catalogue in feeds.py rather than the snapshot, so the
    sources are listed even before the first ingest run. Where a snapshot
    exists, each source carries that run's outcome for it.
    """

    permission_classes = [IsEnterpriseUser]

    def get(self, request: Request) -> Response:
        """
        Merge the static catalogue with the latest run's per-feed report.

        Args:
            request: DRF request.

        Returns:
            200 with one entry per subscribed feed.
        """
        snapshot = _snapshot() or {}
        report = {entry["feedId"]: entry for entry in snapshot.get("report", [])}

        sources = []
        for source in public_sources():
            outcome = report.get(source["id"], {})
            sources.append({
                **source,
                "status": outcome.get("status", "unknown"),
                "itemCount": outcome.get("itemCount", 0),
                "detail": outcome.get("detail", ""),
            })

        return Response({
            "sources": sources,
            "totalCount": len(sources),
            "fetchedAt": snapshot.get("fetchedAt"),
        })


class AdvisoryListView(APIView):
    """
    Return the advisory library.

    GET /api/threat-intel/advisories/

    Advisories are MayaTrail-authored notices tying an active threat to the
    emulations, detections and guardrails that cover it. No advisory content
    exists yet, so this returns an empty library and the UI renders its
    placeholder — the same treatment Guardrails had before its library landed.
    """

    permission_classes = [IsEnterpriseUser]

    def get(self, request: Request) -> Response:
        """
        Return the (currently empty) advisory list.

        Args:
            request: DRF request.

        Returns:
            200 with an empty advisories list and a zero count.
        """
        return Response({"advisories": [], "totalCount": 0})
