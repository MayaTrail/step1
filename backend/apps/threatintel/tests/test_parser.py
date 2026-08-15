"""
Tests for RSS/Atom normalisation.

Every case runs against checked-in fixture XML — the parser is a pure function
over bytes, so no test here touches the network. The properties guarded are the
ones the feed page depends on: item HTML never reaches the UI as markup, ids
stay stable across runs so a daily merge does not duplicate posts, and a
malformed feed degrades to nothing rather than raising.
"""

from pathlib import Path

from django.test import SimpleTestCase

from apps.threatintel.parser import (
    SUMMARY_MAX_CHARS,
    dedupe_items,
    parse_feed,
    sort_items,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"

RSS_FEED = {"id": "1001", "title": "Example Cloud Security Blog", "curated": True, "official": False}
ATOM_FEED = {"id": "2002", "title": "Example Releases", "curated": True, "official": True}


def load(name: str) -> bytes:
    """
    Read one fixture feed.

    Args:
        name: File name inside tests/fixtures.

    Returns:
        Raw bytes, as fetch_feed_bytes would return them.
    """
    return (FIXTURES / name).read_bytes()


class Rss20Tests(SimpleTestCase):
    """RSS 2.0, the majority format in the subscription list."""

    def setUp(self):
        self.items = parse_feed(load("rss20.xml"), RSS_FEED)

    def test_every_item_is_kept(self):
        """Three items in, three out — including the undated and link-less ones."""
        self.assertEqual(len(self.items), 3)

    def test_item_carries_its_feed_attribution(self):
        for item in self.items:
            self.assertEqual(item["feedId"], "1001")
            self.assertEqual(item["feedTitle"], "Example Cloud Security Blog")
            self.assertFalse(item["official"])

    def test_html_is_stripped_from_the_summary(self):
        """Descriptions are HTML in most feeds; the UI renders text."""
        summary = self.items[0]["summary"]
        self.assertNotIn("<", summary)
        self.assertNotIn(">", summary)
        self.assertIn("role chain", summary)

    def test_whitespace_is_collapsed(self):
        undated = next(i for i in self.items if i["link"].endswith("s3-policies"))
        self.assertEqual(
            undated["summary"],
            "Plain text description with irregular whitespace.",
        )

    def test_published_date_is_utc_iso(self):
        self.assertEqual(self.items[0]["publishedAt"], "2025-08-12T09:30:00+00:00")

    def test_missing_date_is_none_not_a_guess(self):
        undated = next(i for i in self.items if i["link"].endswith("s3-policies"))
        self.assertIsNone(undated["publishedAt"])

    def test_categories_become_tags(self):
        self.assertEqual(self.items[0]["tags"], ["iam", "detection"])

    def test_item_without_a_link_falls_back_to_its_title(self):
        linkless = next(i for i in self.items if not i["link"])
        self.assertEqual(linkless["title"], "An item with no link at all")
        self.assertTrue(linkless["id"])


class AtomTests(SimpleTestCase):
    """Atom, used by the GitHub releases feed and several static-site blogs."""

    def setUp(self):
        self.items = parse_feed(load("atom.xml"), ATOM_FEED)

    def test_entries_are_parsed(self):
        self.assertEqual(len(self.items), 2)
        self.assertEqual(self.items[0]["link"], "https://example.test/releases/v2.4.0")

    def test_updated_is_used_when_there_is_no_published_date(self):
        self.assertEqual(self.items[0]["publishedAt"], "2025-08-13T18:00:00+00:00")

    def test_official_flag_propagates_from_the_catalogue(self):
        self.assertTrue(all(item["official"] for item in self.items))


class ItemIdentityTests(SimpleTestCase):
    """Ids must be stable across runs, and distinct across feeds."""

    def test_reparsing_yields_the_same_ids(self):
        first = parse_feed(load("rss20.xml"), RSS_FEED)
        second = parse_feed(load("rss20.xml"), RSS_FEED)
        self.assertEqual([i["id"] for i in first], [i["id"] for i in second])

    def test_same_post_under_two_feeds_gets_distinct_ids(self):
        """Two publications syndicating one URL stay separately attributable."""
        mine = parse_feed(load("rss20.xml"), RSS_FEED)
        theirs = parse_feed(load("rss20.xml"), {**RSS_FEED, "id": "9999"})
        self.assertNotEqual(mine[0]["id"], theirs[0]["id"])


class MalformedFeedTests(SimpleTestCase):
    """A broken publisher must not take the page down."""

    def test_garbage_input_yields_no_items(self):
        self.assertEqual(parse_feed(b"this is not xml at all", RSS_FEED), [])

    def test_empty_input_yields_no_items(self):
        self.assertEqual(parse_feed(b"", RSS_FEED), [])

    def test_truncated_xml_yields_no_items(self):
        self.assertEqual(parse_feed(b"<rss version='2.0'><channel><item>", RSS_FEED), [])


class SummaryTruncationTests(SimpleTestCase):
    """Summaries are teasers; the full post is one click away."""

    def test_long_summary_is_truncated_with_an_ellipsis(self):
        body = "word " * 400
        feed_xml = (
            "<?xml version='1.0'?><rss version='2.0'><channel><title>t</title>"
            f"<item><title>Long</title><link>https://example.test/l</link>"
            f"<description>{body}</description></item></channel></rss>"
        ).encode()
        item = parse_feed(feed_xml, RSS_FEED)[0]
        self.assertLessEqual(len(item["summary"]), SUMMARY_MAX_CHARS + 1)
        self.assertTrue(item["summary"].endswith("…"))


class OrderingTests(SimpleTestCase):
    """Newest first, undated last, one row per item."""

    def test_sort_puts_newest_first(self):
        items = [
            {"id": "a", "publishedAt": "2025-01-01T00:00:00+00:00"},
            {"id": "b", "publishedAt": "2025-06-01T00:00:00+00:00"},
        ]
        self.assertEqual([i["id"] for i in sort_items(items)], ["b", "a"])

    def test_undated_items_sort_last(self):
        items = [
            {"id": "undated", "publishedAt": None},
            {"id": "dated", "publishedAt": "2020-01-01T00:00:00+00:00"},
        ]
        self.assertEqual([i["id"] for i in sort_items(items)], ["dated", "undated"])

    def test_dedupe_keeps_the_first_occurrence(self):
        items = [
            {"id": "x", "title": "fresh"},
            {"id": "x", "title": "stale"},
            {"id": "y", "title": "other"},
        ]
        deduped = dedupe_items(items)
        self.assertEqual([i["id"] for i in deduped], ["x", "y"])
        self.assertEqual(deduped[0]["title"], "fresh")
