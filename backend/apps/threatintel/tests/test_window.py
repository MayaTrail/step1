"""
Tests for the rolling-window merge.

These cover what a reader sees after the second and subsequent ingest runs:
yesterday's items are still there, today's corrections win over the stored
copy, and the window neither grows without bound nor silently drops posts a
feed simply forgot to date.
"""

from datetime import datetime, timedelta, timezone

from django.test import SimpleTestCase

from apps.threatintel.window import (
    MAX_WINDOW_DAYS,
    MAX_WINDOW_ITEMS,
    build_payload,
    within_window,
)

NOW = datetime(2025, 8, 15, 3, 0, 0, tzinfo=timezone.utc)


def item(item_id: str, *, days_ago: int | None = 0, title: str = "post") -> dict:
    """
    Build a minimal normalised item.

    Args:
        item_id: The item id.
        days_ago: Age in days, or None for an undated item.
        title: Item title, used to tell two versions of one item apart.

    Returns:
        An item dict of the shape parse_feed produces.
    """
    published = None if days_ago is None else (NOW - timedelta(days=days_ago)).isoformat()
    return {"id": item_id, "title": title, "publishedAt": published}


def ok(feed_id: str) -> dict:
    """Build one successful report row."""
    return {"feedId": feed_id, "status": "ok", "itemCount": 1}


def failed(feed_id: str) -> dict:
    """Build one failed report row."""
    return {"feedId": feed_id, "status": "error", "itemCount": 0}


class WindowMembershipTests(SimpleTestCase):
    """What the age cutoff does and does not exclude."""

    def setUp(self):
        self.cutoff = (NOW - timedelta(days=MAX_WINDOW_DAYS)).isoformat()

    def test_recent_item_is_kept(self):
        self.assertTrue(within_window(item("a", days_ago=1), self.cutoff))

    def test_item_older_than_the_cutoff_is_dropped(self):
        self.assertFalse(within_window(item("a", days_ago=MAX_WINDOW_DAYS + 5), self.cutoff))

    def test_undated_item_is_kept(self):
        """A missing date is a feed quirk, not evidence the post is old."""
        self.assertTrue(within_window(item("a", days_ago=None), self.cutoff))


class FirstRunTests(SimpleTestCase):
    """The run that has no previous snapshot to merge against."""

    def test_all_fresh_items_are_stored(self):
        payload = build_payload([item("a"), item("b")], [ok("1")], None, now=NOW)
        self.assertEqual(payload["itemCount"], 2)
        self.assertEqual(payload["newThisRun"], 2)

    def test_run_metadata_is_recorded(self):
        payload = build_payload([item("a")], [ok("1"), failed("2")], None, now=NOW)
        self.assertEqual(payload["fetchedAt"], NOW.isoformat())
        self.assertEqual(payload["fetchedOn"], "2025-08-15")
        self.assertEqual(payload["feedCount"], 2)
        self.assertEqual(payload["feedsOk"], 1)
        self.assertEqual(payload["feedsFailed"], 1)

    def test_the_per_feed_report_is_stored_verbatim(self):
        report = [ok("1"), failed("2")]
        self.assertEqual(build_payload([], report, None, now=NOW)["report"], report)


class MergeTests(SimpleTestCase):
    """Merging a fetch into the previous window."""

    def test_previous_items_are_carried_forward(self):
        previous = {"items": [item("old", days_ago=3)]}
        payload = build_payload([item("new")], [ok("1")], previous, now=NOW)
        self.assertEqual({i["id"] for i in payload["items"]}, {"new", "old"})

    def test_new_this_run_counts_only_the_fetch(self):
        previous = {"items": [item("old", days_ago=3)]}
        payload = build_payload([item("new")], [ok("1")], previous, now=NOW)
        self.assertEqual(payload["newThisRun"], 1)
        self.assertEqual(payload["itemCount"], 2)

    def test_an_item_is_never_duplicated_across_runs(self):
        """Re-fetching the same post must not produce a second row."""
        previous = {"items": [item("a")]}
        payload = build_payload([item("a")], [ok("1")], previous, now=NOW)
        self.assertEqual(payload["itemCount"], 1)

    def test_the_freshly_fetched_version_wins(self):
        """A publisher correcting a title should reach the page."""
        previous = {"items": [item("a", title="typo in tilte")]}
        payload = build_payload([item("a", title="typo in title")], [ok("1")], previous, now=NOW)
        self.assertEqual(payload["items"][0]["title"], "typo in title")

    def test_a_failed_run_still_serves_the_previous_items(self):
        """Every feed being down must not blank the page."""
        previous = {"items": [item("old", days_ago=2)]}
        payload = build_payload([], [failed("1"), failed("2")], previous, now=NOW)
        self.assertEqual(payload["itemCount"], 1)
        self.assertEqual(payload["feedsFailed"], 2)


class WindowBoundTests(SimpleTestCase):
    """The stored window stays bounded in both size and age."""

    def test_items_are_ordered_newest_first(self):
        payload = build_payload(
            [item("older", days_ago=10), item("newer", days_ago=1)],
            [ok("1")],
            None,
            now=NOW,
        )
        self.assertEqual([i["id"] for i in payload["items"]], ["newer", "older"])

    def test_items_past_the_age_cutoff_are_dropped(self):
        previous = {"items": [item("ancient", days_ago=MAX_WINDOW_DAYS + 10)]}
        payload = build_payload([item("fresh")], [ok("1")], previous, now=NOW)
        self.assertEqual([i["id"] for i in payload["items"]], ["fresh"])

    def test_the_window_is_capped(self):
        many = [item(f"i{n}", days_ago=n % 30) for n in range(MAX_WINDOW_ITEMS + 50)]
        payload = build_payload(many, [ok("1")], None, now=NOW)
        self.assertEqual(payload["itemCount"], MAX_WINDOW_ITEMS)
