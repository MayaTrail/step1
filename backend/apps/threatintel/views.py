"""
Views for the threatintel app.

GET /api/threat-intel/feed/      ThreatIntelFeedView
GET /api/threat-intel/sources/   ThreatIntelSourceListView

Both require IsAuthenticated rather than IsEnterpriseUser. The feed is public
security blog content and the source list is a set of public RSS URLs; neither
reads anything from the user's AWS account, so a verified connection is not a
meaningful gate on them.

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
from .feeds import public_sources

logger = logging.getLogger(__name__)

# Items returned when the caller does not ask for a page size.
DEFAULT_LIMIT = 100
MAX_LIMIT = 600


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


class ThreatIntelFeedView(APIView):
    """
    Return the stored rolling window of feed items.

    GET /api/threat-intel/feed/?limit=<n>&feed=<feedId>
    """

    permission_classes = [IsAuthenticated]

    def get(self, request: Request) -> Response:
        """
        Read the stored feed, optionally filtered to one publication.

        Args:
            request: DRF request.

        Returns:
            200 with items and counts. Before the first ingest, or when storage
            is unreadable, returns an empty feed rather than an error so the UI
            shows its empty state.
        """
        payload: dict[str, Any] = storage.read_latest() or {}
        items = payload.get("items", [])

        feed_id = request.query_params.get("feed")
        if feed_id:
            items = [item for item in items if item.get("feedId") == feed_id]

        limit = _limit(request)
        return Response({
            "items": items[:limit],
            "itemCount": len(items),
            "totalCount": payload.get("itemCount", 0),
            "fetchedOn": payload.get("fetchedOn"),
            "fetchedAt": payload.get("fetchedAt"),
            "feedsOk": payload.get("feedsOk", 0),
            "feedsFailed": payload.get("feedsFailed", 0),
            "feedCount": payload.get("feedCount", 0),
        })


class ThreatIntelSourceListView(APIView):
    """
    Return the subscription list behind the feed.

    GET /api/threat-intel/sources/

    Lets a reader see which publications are polled, and drives the filter on
    the Threat Intel page.
    """

    permission_classes = [IsAuthenticated]

    def get(self, request: Request) -> Response:
        """
        List the enabled subscriptions.

        Args:
            request: DRF request.

        Returns:
            200 with one entry per feed.
        """
        sources = public_sources()
        return Response({"sources": sources, "totalCount": len(sources)})
