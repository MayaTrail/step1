"""
Fetching and normalising RSS/Atom feeds.

Split from tasks.py so the parsing half is a pure function over bytes: the
tests feed it checked-in fixture XML and never touch the network.

The subscription list mixes RSS 2.0, Atom, a GitHub releases atom feed and
several Substack/beehiiv variants, so parsing is delegated to feedparser rather
than hand-rolled — the date formats and namespace prefixes alone are not worth
reimplementing. feedparser also sanitises item HTML by default; on top of that
`_to_text` strips the markup entirely, because the UI renders summaries as
plain text and must never be handed raw feed HTML.
"""

from __future__ import annotations

import hashlib
import logging
import re
from datetime import datetime, timezone
from typing import Any

import feedparser
import requests

logger = logging.getLogger(__name__)

# A feed that has not answered in 20s is treated as down for this run; the next
# run picks it up again. Total per-run cost is bounded by the worker's own
# time limit, not by the slowest publisher.
FETCH_TIMEOUT_SECONDS = 20

# Refuse bodies larger than this. Protects the worker from a feed that streams
# without end; the largest real feed in the list is under 2 MB.
MAX_FEED_BYTES = 8 * 1024 * 1024

# Several publishers reject requests without a recognisable agent string.
USER_AGENT = "MayaTrail-ThreatIntel/1.0 (+https://mayatrail.tech)"

# A feed that has moved is normally one or two hops away. Abandoned marketing
# sites, by contrast, redirect in a loop; capping the chain turns that into a
# fast, clearly-reported failure instead of 30 wasted round trips.
MAX_REDIRECTS = 5

# Item summaries are teasers in the UI; the full post is one click away.
SUMMARY_MAX_CHARS = 400

_TAG_RE = re.compile(r"<[^>]+>")
_WHITESPACE_RE = re.compile(r"\s+")


class FeedFetchError(Exception):
    """A feed could not be retrieved. Carries the reason for the run report."""


def fetch_feed_bytes(url: str, *, session: requests.Session | None = None) -> bytes:
    """
    Download one feed body.

    Args:
        url: The feed endpoint.
        session: Optional shared session so a run reuses connections.

    Returns:
        The raw response body.

    Raises:
        FeedFetchError: On any transport error, non-2xx status, or a body that
            exceeds MAX_FEED_BYTES.
    """
    client = session if session is not None else requests.Session()
    owns_client = session is None
    client.max_redirects = MAX_REDIRECTS

    try:
        try:
            response = client.get(
                url,
                timeout=FETCH_TIMEOUT_SECONDS,
                headers={
                    "User-Agent": USER_AGENT,
                    "Accept": "application/rss+xml, application/atom+xml, application/xml;q=0.9, */*;q=0.8",
                },
                stream=True,
            )
        except requests.RequestException as exc:
            raise FeedFetchError(f"request failed: {exc}") from exc

        with response:
            if response.status_code >= 400:
                raise FeedFetchError(f"HTTP {response.status_code}")

            chunks: list[bytes] = []
            total = 0
            try:
                for chunk in response.iter_content(chunk_size=64 * 1024):
                    if not chunk:
                        continue
                    total += len(chunk)
                    if total > MAX_FEED_BYTES:
                        raise FeedFetchError(f"body exceeded {MAX_FEED_BYTES} bytes")
                    chunks.append(chunk)
            except requests.RequestException as exc:
                # The body can fail mid-stream after a clean set of headers.
                raise FeedFetchError(f"read failed: {exc}") from exc

        return b"".join(chunks)
    finally:
        # Only close a session this call created; a caller's shared session
        # must survive for the rest of the run.
        if owns_client:
            client.close()


def _to_text(value: str | None) -> str:
    """
    Reduce a feed field to single-spaced plain text.

    Item descriptions are HTML in most feeds and the UI renders them as text,
    so the markup is stripped here rather than at render time.

    Args:
        value: Raw field value, possibly None or HTML.

    Returns:
        Plain text with runs of whitespace collapsed; empty string for None.
    """
    if not value:
        return ""
    return _WHITESPACE_RE.sub(" ", _TAG_RE.sub(" ", value)).strip()


def _published_at(entry: Any) -> str | None:
    """
    Resolve an entry's publication timestamp as a UTC ISO-8601 string.

    Prefers `published`, falls back to `updated`. feedparser has already parsed
    the many date formats in play into a time tuple.

    Args:
        entry: A feedparser entry.

    Returns:
        ISO-8601 string ending in "+00:00", or None when the feed gives no
        usable date (the item is still kept, just undated).
    """
    for attr in ("published_parsed", "updated_parsed"):
        parsed = getattr(entry, attr, None)
        if parsed:
            try:
                return datetime(*parsed[:6], tzinfo=timezone.utc).isoformat()
            except (TypeError, ValueError):
                continue
    return None


def _item_id(feed_id: str, link: str, title: str) -> str:
    """
    Derive a stable id for an item so re-ingesting a feed does not duplicate it.

    Keyed on the link where there is one, since that is what publishers keep
    stable; titles change after an edit. Scoped by feed id so two publications
    syndicating the same URL stay distinguishable.

    Args:
        feed_id: The owning feed's id.
        link: The item's canonical link.
        title: The item's title, used only when there is no link.

    Returns:
        A 16-character hex digest.
    """
    basis = f"{feed_id}|{link or title}"
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


def parse_feed(body: bytes, feed: dict[str, Any], *, limit: int = 50) -> list[dict[str, Any]]:
    """
    Turn one feed body into normalised item dicts.

    Args:
        body: Raw XML from fetch_feed_bytes.
        feed: The catalogue entry, for id/title/official attribution.
        limit: Keep at most this many of the feed's most recent entries.

    Returns:
        List of item dicts. Entries with neither a title nor a link are
        dropped; a malformed document yields an empty list rather than raising,
        because feedparser's lenient mode still returns whatever it recovered.
    """
    parsed = feedparser.parse(body)

    if parsed.bozo and not parsed.entries:
        reason = getattr(parsed, "bozo_exception", "unknown error")
        logger.warning("Feed %s (%s) did not parse: %s", feed.get("id"), feed.get("title"), reason)
        return []

    items: list[dict[str, Any]] = []
    for entry in parsed.entries[:limit]:
        title = _to_text(getattr(entry, "title", ""))
        link = (getattr(entry, "link", "") or "").strip()
        if not title and not link:
            continue

        summary = _to_text(getattr(entry, "summary", "") or getattr(entry, "description", ""))
        if len(summary) > SUMMARY_MAX_CHARS:
            summary = summary[:SUMMARY_MAX_CHARS].rstrip() + "…"

        items.append({
            "id": _item_id(feed["id"], link, title),
            "feedId": feed["id"],
            "feedTitle": feed["title"],
            "official": feed.get("official", False),
            "curated": feed.get("curated", False),
            "title": title or link,
            "link": link,
            "summary": summary,
            "author": _to_text(getattr(entry, "author", "")),
            "publishedAt": _published_at(entry),
            "tags": [
                _to_text(tag.get("term"))
                for tag in getattr(entry, "tags", [])[:6]
                if isinstance(tag, dict) and tag.get("term")
            ],
        })

    return items


def sort_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Order items newest first, with undated items last.

    Args:
        items: Normalised items from any number of feeds.

    Returns:
        A new list in display order.
    """
    return sorted(
        items,
        key=lambda item: (item.get("publishedAt") is not None, item.get("publishedAt") or ""),
        reverse=True,
    )


def dedupe_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Drop repeat items, keeping the first occurrence.

    Args:
        items: Normalised items, typically today's fetch concatenated with the
            previous snapshot.

    Returns:
        A new list with each item id appearing once.
    """
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for item in items:
        if item["id"] in seen:
            continue
        seen.add(item["id"])
        unique.append(item)
    return unique
