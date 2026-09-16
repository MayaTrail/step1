"""
Tests for matching feed items against the emulation catalogue.

The index is fabricated here rather than read from the real registry, so these
run without EMULATIONS_BASE_DIR and stay stable as emulations are added.

The cases that matter are the ones that guard precision. A correlation engine
that over-matches is worse than none: every wrong chip teaches the reader to
ignore the right ones.
"""

from django.test import SimpleTestCase

from apps.threatintel.correlate import (
    MATCH_CAMPAIGN,
    MATCH_CITED,
    MATCH_TECHNIQUE,
    MAX_MATCHES_PER_ITEM,
    annotate,
    build_index,
    match_item,
    normalise_url,
)

CATALOGUE = [
    {
        "name": "scarleteel",
        "display_name": "SCARLETEEL 2.0",
        "platform": "aws",
        "severity": "CRITICAL",
        "aliases": "SCARLETEEL 2.0 · Cloud Container Attack",
        "services": ["IAM", "EC2", "CloudTrail"],
        "mitre_mappings": [
            {"id": "T1552.005", "name": "Cloud Instance Metadata API"},
            {"id": "T1190", "name": "Exploit Public-Facing Application"},
        ],
        "references": [
            {"url": "https://sysdig.com/blog/scarleteel-2-0/", "type": "REFERENCE"},
        ],
    },
    {
        "name": "aws_persistence_iam_backdoor_user",
        "display_name": "Backdoor IAM User with Additional Access Key",
        "platform": "aws",
        "severity": "MEDIUM",
        "aliases": "aws.persistence.iam-backdoor-user",
        "services": ["IAM"],
        "mitre_mappings": [{"id": "T1098.001", "name": "Additional Cloud Credentials"}],
        "references": [],
    },
    {
        "name": "shell_parent",
        "display_name": "Command and Scripting Interpreter",
        "platform": "aws",
        "severity": "HIGH",
        "aliases": "",
        "services": [],
        "mitre_mappings": [{"id": "T1059", "name": "Command and Scripting Interpreter"}],
        "references": [],
    },
    {
        "name": "shell_child",
        "display_name": "Cloud API Abuse",
        "platform": "aws",
        "severity": "HIGH",
        "aliases": "",
        "services": [],
        "mitre_mappings": [{"id": "T1059.009", "name": "Cloud API"}],
        "references": [],
    },
]


def item(**overrides):
    """
    Build a normalised feed item for a test case.

    Args:
        **overrides: Fields to replace on the default item.

    Returns:
        An item dict shaped like the ones parser.py produces.
    """
    base = {
        "id": "abc123",
        "feedId": "1",
        "feedTitle": "Test Feed",
        "title": "",
        "link": "",
        "summary": "",
        "tags": [],
    }
    base.update(overrides)
    return base


class NormaliseUrlTests(SimpleTestCase):
    """URL reduction used to compare an item link against a MANIFEST citation."""

    def test_strips_scheme_www_slash_and_query(self):
        """The four ways the same article is written all reduce to one key."""
        variants = [
            "https://sysdig.com/blog/scarleteel-2-0/",
            "http://www.sysdig.com/blog/scarleteel-2-0",
            "https://sysdig.com/blog/scarleteel-2-0?utm_source=rss",
            "https://SysDig.com/blog/scarleteel-2-0/#intro",
        ]
        keys = {normalise_url(url) for url in variants}
        self.assertEqual(keys, {"sysdig.com/blog/scarleteel-2-0"})

    def test_empty_and_relative_urls_yield_no_key(self):
        """A value with no host must not collide with other hostless values."""
        self.assertEqual(normalise_url(""), "")
        self.assertEqual(normalise_url("/blog/post"), "")


class BuildIndexTests(SimpleTestCase):
    """Construction of the lookup tables."""

    def setUp(self):
        """Build the index once per test."""
        self.index = build_index(CATALOGUE)

    def test_indexes_references_techniques_and_campaigns(self):
        """Each join key lands in its own table."""
        self.assertIn("sysdig.com/blog/scarleteel-2-0", self.index.by_reference)
        self.assertIn("T1552.005", self.index.by_technique)
        self.assertIn("scarleteel", self.index.by_campaign)

    def test_multi_word_names_are_not_campaign_tokens(self):
        """A descriptive title never appears verbatim in an article."""
        self.assertNotIn("backdoor iam user with additional access key", self.index.by_campaign)

    def test_upstream_technique_ids_are_campaign_tokens(self):
        """A Stratus id does appear in security writing, so it is indexed."""
        self.assertIn("aws.persistence.iam-backdoor-user", self.index.by_campaign)

    def test_service_names_are_excluded_from_campaign_tokens(self):
        """
        An emulation named after a service must not match every post about it.

        "CloudTrail" is a single token long enough to qualify, so only the
        exclusion derived from the catalogue's own services keeps it out.
        """
        self.assertNotIn("cloudtrail", self.index.by_campaign)

    def test_entry_without_a_name_is_skipped(self):
        """A malformed entry is dropped rather than indexed under an empty key."""
        index = build_index([{"display_name": "No id"}])
        self.assertEqual(index.meta, {})


class TechniqueMatchTests(SimpleTestCase):
    """Technique matching, including the sub-technique boundary case."""

    def setUp(self):
        """Build the index once per test."""
        self.index = build_index(CATALOGUE)

    def test_matches_a_technique_named_in_the_summary(self):
        """The id is found in body text, not only in the title."""
        matches = match_item(
            item(title="IMDS attacks", summary="The actor used T1552.005 to steal creds."),
            self.index,
        )
        self.assertEqual([m["emulationId"] for m in matches], ["scarleteel"])
        self.assertEqual(matches[0]["kind"], MATCH_TECHNIQUE)
        self.assertEqual(matches[0]["evidence"], "T1552.005")

    def test_sub_technique_does_not_match_its_parent(self):
        """
        The regression this module is shaped around.

        A pattern built per catalogue id would match "T1059" inside the string
        "T1059.009", because "." is a word boundary, and a post about the cloud
        sub-technique would wrongly surface the parent's emulation.
        """
        matches = match_item(item(title="Abuse of T1059.009 in the wild"), self.index)
        self.assertEqual([m["emulationId"] for m in matches], ["shell_child"])

    def test_parent_technique_matches_only_the_parent(self):
        """The reverse direction stays correct too."""
        matches = match_item(item(title="Interpreter abuse, T1059 explained"), self.index)
        self.assertEqual([m["emulationId"] for m in matches], ["shell_parent"])

    def test_lower_case_technique_ids_are_found(self):
        """Authors write ids inconsistently; the lookup is case-insensitive."""
        matches = match_item(item(summary="mapped to t1098.001 in att&ck"), self.index)
        self.assertEqual([m["emulationId"] for m in matches], ["aws_persistence_iam_backdoor_user"])

    def test_unknown_technique_matches_nothing(self):
        """An id the catalogue does not cover yields no match, not a guess."""
        self.assertEqual(match_item(item(title="About T1666"), self.index), [])


class CampaignMatchTests(SimpleTestCase):
    """Campaign-name matching and its word boundaries."""

    def setUp(self):
        """Build the index once per test."""
        self.index = build_index(CATALOGUE)

    def test_matches_a_campaign_named_in_the_title(self):
        """A rare proper noun is strong evidence on its own."""
        matches = match_item(item(title="Inside the SCARLETEEL campaign"), self.index)
        self.assertEqual([m["emulationId"] for m in matches], ["scarleteel"])
        self.assertEqual(matches[0]["kind"], MATCH_CAMPAIGN)

    def test_word_shaped_tokens_do_not_match_inside_longer_words(self):
        """Set intersection over word tokens, not a substring scan."""
        self.assertEqual(match_item(item(title="scarleteels are fictional"), self.index), [])

    def test_dotted_upstream_ids_match_as_substrings(self):
        """These survive word splitting, so they are compared whole."""
        matches = match_item(
            item(summary="Run aws.persistence.iam-backdoor-user to reproduce."),
            self.index,
        )
        self.assertEqual([m["emulationId"] for m in matches], ["aws_persistence_iam_backdoor_user"])

    def test_tags_are_searched_alongside_title_and_summary(self):
        """Some publishers put the campaign name only in the categories."""
        matches = match_item(item(title="Weekly roundup", tags=["cloud", "scarleteel"]), self.index)
        self.assertEqual([m["emulationId"] for m in matches], ["scarleteel"])


class CitedMatchTests(SimpleTestCase):
    """The exact match, where an emulation already references the article."""

    def setUp(self):
        """Build the index once per test."""
        self.index = build_index(CATALOGUE)

    def test_link_already_referenced_by_an_emulation(self):
        """The item's own link is the highest-precision signal available."""
        matches = match_item(
            item(title="Something else entirely", link="https://sysdig.com/blog/scarleteel-2-0"),
            self.index,
        )
        self.assertEqual(matches[0]["kind"], MATCH_CITED)

    def test_citation_outranks_a_weaker_route_to_the_same_emulation(self):
        """
        One emulation reached two ways is reported once, at its best kind.

        This item both cites the reference URL and names the campaign, and must
        not produce two chips for one emulation.
        """
        matches = match_item(
            item(title="SCARLETEEL revisited", link="https://sysdig.com/blog/scarleteel-2-0/"),
            self.index,
        )
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["kind"], MATCH_CITED)


class MatchShapeTests(SimpleTestCase):
    """Ordering, capping and the payload each match carries."""

    def setUp(self):
        """Build the index once per test."""
        self.index = build_index(CATALOGUE)

    def test_match_carries_display_metadata_and_evidence(self):
        """The UI renders the name and shows why the match was made."""
        match = match_item(item(title="T1190 exploited"), self.index)[0]
        self.assertEqual(match["displayName"], "SCARLETEEL 2.0")
        self.assertEqual(match["platform"], "aws")
        self.assertEqual(match["severity"], "CRITICAL")
        self.assertEqual(match["evidence"], "T1190")

    def test_matches_are_ordered_by_precision_then_name(self):
        """Stable output keeps the stored document from churning each run."""
        matches = match_item(
            item(
                title="T1098.001 and T1059.009 both seen",
                link="https://sysdig.com/blog/scarleteel-2-0",
            ),
            self.index,
        )
        self.assertEqual(
            [(m["kind"], m["displayName"]) for m in matches],
            [
                (MATCH_CITED, "SCARLETEEL 2.0"),
                (MATCH_TECHNIQUE, "Backdoor IAM User with Additional Access Key"),
                (MATCH_TECHNIQUE, "Cloud API Abuse"),
            ],
        )

    def test_evidence_is_stable_when_one_emulation_has_several_tokens(self):
        """
        Two campaign tokens for one emulation must resolve the same way always.

        Tokens come out of a set, whose iteration order varies with string
        hashing between processes, so without a total order the stored evidence
        flips between runs on input that has not changed. The longer token also
        tells the reader more.
        """
        index = build_index([
            {
                "name": "dangerdev",
                "display_name": "DangerDev",
                "aliases": "DangerDev@protonmail.me",
            }
        ])
        match = match_item(item(title="The DangerDev@protonmail.me investigation"), index)[0]
        self.assertEqual(match["evidence"], "dangerdev@protonmail.me")

    def test_match_count_is_capped(self):
        """A roundup post listing many ids must not bloat the document."""
        catalogue = [
            {
                "name": f"em{n}",
                "display_name": f"Emulation {n}",
                "mitre_mappings": [{"id": f"T20{n:02d}"}],
            }
            for n in range(MAX_MATCHES_PER_ITEM + 3)
        ]
        index = build_index(catalogue)
        text = " ".join(f"T20{n:02d}" for n in range(MAX_MATCHES_PER_ITEM + 3))
        self.assertEqual(len(match_item(item(title=text), index)), MAX_MATCHES_PER_ITEM)


class AnnotateTests(SimpleTestCase):
    """Applying the matcher across the rolling window."""

    def setUp(self):
        """Build the index once per test."""
        self.index = build_index(CATALOGUE)

    def test_every_item_gains_a_matches_field(self):
        """An unrelated item carries an empty list, never a missing key."""
        annotated = annotate(
            [item(id="a", title="SCARLETEEL"), item(id="b", title="Unrelated post")],
            self.index,
        )
        self.assertEqual(len(annotated[0]["matches"]), 1)
        self.assertEqual(annotated[1]["matches"], [])

    def test_original_items_are_not_mutated(self):
        """
        The caller's window is left alone.

        build_payload carries items forward from the previous run, so mutating
        in place would accumulate stale matches across runs.
        """
        items = [item(title="SCARLETEEL")]
        annotate(items, self.index)
        self.assertNotIn("matches", items[0])

    def test_an_empty_index_yields_an_uncorrelated_feed(self):
        """
        A deployment without the emulations volume degrades, it does not break.

        The feed is still worth reading with no matches attached.
        """
        annotated = annotate([item(title="SCARLETEEL")], build_index([]))
        self.assertEqual(annotated[0]["matches"], [])
