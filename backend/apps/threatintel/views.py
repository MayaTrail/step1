"""
Views for the threatintel app.

All endpoints require IsEnterpriseUser.

GET /api/threat-intel/feed/              ThreatIntelFeedView
GET /api/threat-intel/sources/           ThreatIntelSourceListView
GET /api/threat-intel/advisories/        AdvisoryListView
GET /api/threat-intel/advisories/<id>/   AdvisoryDetailView

The feed is read from the S3 snapshot the daily Celery task writes; these views
never fetch RSS themselves, so a slow publisher can never slow down a request.
A missing snapshot returns zero counts rather than an error, so the UI shows
its empty state instead of a failure.

Advisories work the same way: `manage.py sync_advisories` writes the dossiers
and their index, and these views only read.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from rest_framework import status
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.infrastructure.permissions import IsEnterpriseUser

from . import advisories, storage
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
_advisory_cache: tuple[float, dict[str, Any] | None] | None = None


def reset_cache() -> None:
    """
    Clear the in-process caches so the next request re-reads S3.

    Use after an out-of-band ingest or advisory sync, or in tests that need a
    clean state.
    """
    global _cache, _advisory_cache  # noqa: PLW0603
    _cache = None
    _advisory_cache = None


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


def _advisory_index() -> dict[str, Any] | None:
    """
    Return the advisory index, reading successful results through a cache.

    The index changes only when someone runs `sync_advisories`, so it is held
    on the same terms as the feed snapshot: successes cached for the TTL, a
    missing index never cached so the first sync shows up immediately.

    Returns:
        The index payload, or None when no sync has run or S3 is unreadable.
    """
    global _advisory_cache  # noqa: PLW0603
    now = time.monotonic()
    if _advisory_cache is not None and now - _advisory_cache[0] < CACHE_TTL_SECONDS:
        return _advisory_cache[1]

    payload = advisories.read_index()
    if payload is not None:
        _advisory_cache = (now, payload)
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

    Advisories are APT threat-actor dossiers — one markdown document per actor,
    merged from MITRE ATT&CK, CISA KEV and MISP galaxy. This serves the index
    written by `manage.py sync_advisories`, so the response is one S3 read
    regardless of how many dossiers the library holds.
    """

    permission_classes = [IsEnterpriseUser]

    def get(self, request: Request) -> Response:
        """
        Return every advisory's card metadata.

        Args:
            request: DRF request.

        Returns:
            200 with the advisory list. An unsynced or unreadable library
            returns the same shape with zero counts, so the UI shows its empty
            state rather than an error.
        """
        index = _advisory_index()
        if index is None:
            return Response({"advisories": [], "totalCount": 0})

        entries = index.get("advisories", [])
        return Response({
            "advisories": [_card(entry) for entry in entries],
            "totalCount": index.get("totalCount", len(entries)),
        })


class AdvisoryDetailView(APIView):
    """
    Return one advisory's full dossier.

    GET /api/threat-intel/advisories/<advisory_id>/

    The object key comes from the index entry, never from the URL, so a
    traversal attempt in `advisory_id` resolves to no entry and 404s rather
    than reaching an arbitrary key in the bucket.
    """

    permission_classes = [IsEnterpriseUser]

    def get(self, request: Request, advisory_id: str) -> Response:
        """
        Read one dossier and return it with its card metadata.

        Args:
            request: DRF request.
            advisory_id: URL path parameter — the index entry's id.

        Returns:
            200 with the entry's metadata plus raw markdown in `content`;
            404 when no entry has that id or its object is unreadable.
        """
        index = _advisory_index()
        entries = (index or {}).get("advisories", [])
        entry = next((item for item in entries if item.get("id") == advisory_id), None)
        if entry is None:
            return Response(
                {"detail": f"Unknown advisory '{advisory_id}'."},
                status=status.HTTP_404_NOT_FOUND,
            )

        # An entry without `file` means the index was written by something other
        # than sync_advisories. 404 rather than raising: the client asked for a
        # document this server cannot locate, which is the same answer.
        file_name = entry.get("file")
        content = advisories.read_dossier(file_name) if file_name else None
        if content is None:
            logger.error("Advisory %s is indexed but its object could not be read", advisory_id)
            return Response(
                {"detail": f"Advisory '{advisory_id}' could not be read."},
                status=status.HTTP_404_NOT_FOUND,
            )

        return Response({**_card(entry), "content": content})


def _card(entry: dict[str, Any]) -> dict[str, Any]:
    """
    Strip an index entry down to what the API exposes.

    Args:
        entry: One record from index.json.

    Returns:
        The entry without `file` — the S3 object name is an internal detail
        the client has no use for and should not be invited to guess at.
    """
    return {key: value for key, value in entry.items() if key != "file"}
