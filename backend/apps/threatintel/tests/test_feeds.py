"""
Tests for the threat intel subscription catalogue.

The catalogue was produced by merging two overlapping pastes of the Cloud
Security Forum feed list. These guard the property that merge was for: one
entry per publication, keyed consistently, with no URL subscribed twice under
two different ids.
"""

from django.test import SimpleTestCase

from apps.threatintel.feeds import FEEDS, enabled_feeds, feed_index, public_sources

# The merge of the two provided lists: 64 raw entries, 24 duplicates removed.
EXPECTED_FEED_COUNT = 40

# The subset that appears in the current curated list rather than only in the
# year-old one.
EXPECTED_CURATED_COUNT = 26


def _normalise(url: str) -> str:
    """
    Reduce a URL the way the dedupe did, so near-duplicates are comparable.

    Args:
        url: A feed URL.

    Returns:
        Lowercased host+path with scheme, leading "www." and any trailing
        slash removed.
    """
    stripped = url.strip().lower()
    for scheme in ("https://", "http://"):
        if stripped.startswith(scheme):
            stripped = stripped[len(scheme):]
    if stripped.startswith("www."):
        stripped = stripped[4:]
    return stripped.rstrip("/")


class CatalogueShapeTests(SimpleTestCase):
    """The merged list is the right size and every entry is well-formed."""

    def test_catalogue_size_matches_the_dedupe(self):
        """40 unique feeds survive the merge of the two provided lists."""
        self.assertEqual(len(FEEDS), EXPECTED_FEED_COUNT)

    def test_curated_subset_matches_the_current_list(self):
        """26 of the 40 come from the current list; the rest are legacy-only."""
        self.assertEqual(len([f for f in FEEDS if f["curated"]]), EXPECTED_CURATED_COUNT)

    def test_every_entry_has_the_required_fields(self):
        """Missing metadata would break attribution on the feed page."""
        for feed in FEEDS:
            self.assertTrue(feed["id"], f"{feed} has no id")
            self.assertTrue(feed["title"], f"{feed['id']} has no title")
            self.assertTrue(feed["url"].startswith(("http://", "https://")), feed["url"])
            self.assertIsInstance(feed["curated"], bool)
            self.assertIsInstance(feed["official"], bool)
            self.assertIsInstance(feed["enabled"], bool)

    def test_the_official_feeds_are_the_aws_run_ones(self):
        """Only AWS's own bulletins and breaking-changes feed are 'official'."""
        official = {feed["id"] for feed in FEEDS if feed["official"]}
        self.assertEqual(official, {"3619513265698", "3629421140308"})


class DeduplicationTests(SimpleTestCase):
    """No publication is subscribed twice."""

    def test_feed_ids_are_unique(self):
        ids = [feed["id"] for feed in FEEDS]
        self.assertEqual(len(ids), len(set(ids)), "duplicate feed id in the catalogue")

    def test_feed_urls_are_unique_after_normalisation(self):
        """http/https and trailing-slash variants must not both be present."""
        urls = [_normalise(feed["url"]) for feed in FEEDS]
        duplicates = {url for url in urls if urls.count(url) > 1}
        self.assertEqual(duplicates, set(), f"duplicate feed URL(s): {duplicates}")

    def test_titles_are_unique(self):
        """Two entries sharing a title would be indistinguishable in the UI."""
        titles = [feed["title"] for feed in FEEDS]
        self.assertEqual(len(titles), len(set(titles)))


class AccessorTests(SimpleTestCase):
    """The helpers the task and views rely on."""

    def test_enabled_feeds_is_the_polled_subset(self):
        enabled = enabled_feeds()
        self.assertTrue(enabled)
        self.assertTrue(all(feed["enabled"] for feed in enabled))
        self.assertLessEqual(len(enabled), len(FEEDS))

    def test_feed_index_covers_the_whole_catalogue(self):
        """Disabled feeds stay resolvable so old items keep their attribution."""
        index = feed_index()
        self.assertEqual(len(index), len(FEEDS))
        for feed in FEEDS:
            self.assertEqual(index[feed["id"]]["title"], feed["title"])

    def test_public_sources_drops_the_enabled_flag(self):
        """The API describes subscriptions, not the polling plumbing."""
        for source in public_sources():
            self.assertNotIn("enabled", source)
            self.assertEqual(
                set(source),
                {"id", "title", "url", "curated", "official"},
            )
