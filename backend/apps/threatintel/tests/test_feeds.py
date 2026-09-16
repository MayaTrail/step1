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

# The content-shape axis the Threat Feed page groups by.
VALID_KINDS = {"advisory", "newsletter", "research"}


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
            self.assertIn(feed["kind"], VALID_KINDS, f"{feed['id']} has kind {feed['kind']}")

    def test_the_official_feeds_are_the_aws_run_ones(self):
        """Only AWS's own bulletins and breaking-changes feed are 'official'."""
        official = {feed["id"] for feed in FEEDS if feed["official"]}
        self.assertEqual(official, {"3619513265698", "3629421140308"})


class ClassificationTests(SimpleTestCase):
    """
    The `kind` axis the Threat Feed page groups by.

    Chosen because it is what the corpus actually divides along. A live ingest
    over 294 items found no ATT&CK technique id anywhere and summaries
    averaging 219 characters, so grouping by technique or by emulation
    relevance would leave almost every item in one bucket.
    """

    def test_every_kind_is_represented(self):
        """A tab with nothing behind it should not exist."""
        kinds = {feed["kind"] for feed in FEEDS}
        self.assertEqual(kinds, VALID_KINDS)

    def test_advisories_are_exactly_the_official_feeds(self):
        """
        The two axes agree today, and the test records that they may not later.

        `official` is about who publishes, `kind` about what they publish. A
        provider that started a roundup would be official and a newsletter, and
        this assertion is where that divergence gets noticed.
        """
        advisory = {feed["id"] for feed in FEEDS if feed["kind"] == "advisory"}
        official = {feed["id"] for feed in FEEDS if feed["official"]}
        self.assertEqual(advisory, official)

    def test_roundups_are_classified_as_newsletters(self):
        """
        These aggregate other people's writing, so they read differently.

        Named explicitly rather than counted, because the failure worth
        catching is one of them being reclassified by accident.
        """
        newsletters = {feed["title"] for feed in FEEDS if feed["kind"] == "newsletter"}
        self.assertEqual(newsletters, {
            "Cloud Security Newsletter",
            "AWS Security Digest",
            "AWS Cloud Security Weekly",
            "Cloud Security Lab a Week (S.L.A.W)",
            "CloudSecList",
            "tl;dr sec",
            "Detection Engineering",
        })

    def test_research_is_the_remainder(self):
        """Original writing is the default and the largest group."""
        research = [feed for feed in FEEDS if feed["kind"] == "research"]
        self.assertEqual(len(research), len(FEEDS) - 2 - 7)


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
                {"id", "title", "url", "curated", "official", "kind"},
            )
