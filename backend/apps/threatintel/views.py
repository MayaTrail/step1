"""
Views for the threatintel app.

GET /api/threat-intel/feed/      ThreatFeedView
GET /api/threat-intel/sources/   ThreatFeedSourceListView

Both require IsAuthenticated rather than HasAWSConnection. The feed is public
security blog content and the source list is a set of public RSS URLs; neither
reads anything from the user's AWS account, so a verified cloud connection is
not a meaningful gate on them. The emulation names carried by an item's
`matches` are public catalogue metadata: a reader who has not connected an
account can see that an emulation exists, and is still stopped from running it
by the gate on the emulations app.

Nothing is fetched during a request. The daily ingest writes one document and
these views read it back, so a slow or failing publisher can never slow down or
break the page.
"""

from __future__ import annotations

import logging
from typing import Any

from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from . import storage
from .feeds import feed_index, public_sources

logger = logging.getLogger(__name__)

# Items returned when the caller does not ask for a page size.
DEFAULT_LIMIT = 100
MAX_LIMIT = 600

# Reported for a feed the stored run report does not mention, which is the case
# before the first ingest and for a feed added since the last one.
UNKNOWN_STATUS = "unknown"

# Used for an item whose feed has since been removed from the catalogue. Such an
# item stays in the window until it ages out, and grouping it with original
# writing is the least misleading of the three.
FALLBACK_KIND = "research"


def _limit(request: Request) -> int:
    """
    Read the requested page size, clamped to a sane range.

    Args:
        request: DRF request; reads the `limit` query parameter.

    Returns:
        The number of items to return.
    """
    raw = request.query_params.get("limit")
    if not raw:
        return DEFAULT_LIMIT
    try:
        return max(1, min(int(raw), MAX_LIMIT))
    except ValueError:
        return DEFAULT_LIMIT


def _is_true(value: str | None) -> bool:
    """
    Interpret a query parameter as a boolean flag.

    Args:
        value: The raw parameter value, or None when absent.

    Returns:
        True for "1", "true" and "yes", case-insensitively.
    """
    return (value or "").strip().lower() in {"1", "true", "yes"}


def _with_kind(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Attach each item's content kind, resolved from the feed catalogue.

    Resolved on read rather than stored on the item. The window carries items
    forward across runs, so stamping the kind at ingest would leave every item
    written before this field existed unclassified until it aged out, and
    reclassifying a publication would need a full re-ingest to take effect.

    Args:
        items: Stored items.

    Returns:
        New item dicts carrying `kind`. An item whose feed has left the
        catalogue falls back to FALLBACK_KIND rather than being dropped.

    """
    catalogue = feed_index()
    return [
        {**item, "kind": catalogue.get(item.get("feedId", ""), {}).get("kind", FALLBACK_KIND)}
        for item in items
    ]


class ThreatFeedView(APIView):
    """
    Return the stored rolling window of feed items.

    GET /api/threat-intel/feed/?limit=<n>&feed=<feedId>&kind=<kind>&related=true
    """

    permission_classes = [IsAuthenticated]

    def get(self, request: Request) -> Response:
        """
        Read the stored feed, optionally narrowed by kind, publication or relevance.

        Args:
            request: DRF request.

        Returns:
            200 with items and counts, including a per-kind breakdown taken
            before the kind filter is applied so the UI can label every tab.
            Before the first ingest, or when storage is unreadable, returns an
            empty feed rather than an error so the UI shows its empty state.
        """
        payload: dict[str, Any] = storage.read_latest() or {}
        items = _with_kind(payload.get("items", []))

        feed_id = request.query_params.get("feed")
        if feed_id:
            items = [item for item in items if item.get("feedId") == feed_id]

        if _is_true(request.query_params.get("related")):
            items = [item for item in items if item.get("matches")]

        # Counted before the kind filter, so a tab still shows its size while a
        # different tab is selected.
        kind_counts: dict[str, int] = {}
        for item in items:
            kind_counts[item["kind"]] = kind_counts.get(item["kind"], 0) + 1

        kind = request.query_params.get("kind")
        if kind:
            items = [item for item in items if item["kind"] == kind]

        limit = _limit(request)
        return Response({
            "items": items[:limit],
            "itemCount": len(items),
            "totalCount": payload.get("itemCount", 0),
            "relatedCount": sum(1 for item in items if item.get("matches")),
            "kindCounts": kind_counts,
            "fetchedOn": payload.get("fetchedOn"),
            "fetchedAt": payload.get("fetchedAt"),
            "newSinceLastRun": payload.get("newSinceLastRun", 0),
            "feedsOk": payload.get("feedsOk", 0),
            "feedsFailed": payload.get("feedsFailed", 0),
            "feedCount": payload.get("feedCount", 0),
        })


class ThreatFeedSourceListView(APIView):
    """
    Return the subscription list behind the feed, with each feed's last outcome.

    GET /api/threat-intel/sources/

    Lets a reader see which publications are polled and which of them are
    currently failing. The ingest already records a per-feed report in the
    stored document; merging it here is what puts a dead subscription in front
    of a human instead of leaving it in the worker's logs.
    """

    permission_classes = [IsAuthenticated]

    def get(self, request: Request) -> Response:
        """
        List the enabled subscriptions with their most recent ingest outcome.

        Args:
            request: DRF request.

        Returns:
            200 with one entry per feed. Sources carry the UNKNOWN_STATUS
            placeholder when no run has reported on them yet.
        """
        payload: dict[str, Any] = storage.read_latest() or {}
        report = {
            row.get("feedId"): row
            for row in payload.get("report", [])
            if row.get("feedId")
        }

        sources = []
        for source in public_sources():
            outcome = report.get(source["id"], {})
            sources.append({
                **source,
                "status": outcome.get("status", UNKNOWN_STATUS),
                "itemCount": outcome.get("itemCount", 0),
                "detail": outcome.get("detail", ""),
            })

        failing = sum(1 for source in sources if source["status"] == "error")
        return Response({
            "sources": sources,
            "totalCount": len(sources),
            "failingCount": failing,
            "fetchedAt": payload.get("fetchedAt"),
        })
