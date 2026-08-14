"""
Tests for dossier parsing and library indexing.

`parse_dossier` is a pure function over markdown, so nothing here touches S3 —
and dossier.py imports no boto3, so this module stays importable under the lean
requirements-test.txt the CI job installs.

The properties guarded are the ones the advisory library depends on: the two H1
spellings the generator emits both yield a name, a dossier missing half its
sections still produces a card, the filter axes are canonicalised so one country
does not appear twice in a dropdown, and ids stay URL-safe.
"""

from pathlib import Path

from django.test import SimpleTestCase

from apps.threatintel.dossier import build_index, parse_dossier, slugify

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def load(name: str) -> str:
    """
    Read one fixture dossier.

    Args:
        name: File name inside tests/fixtures.

    Returns:
        The markdown, as read_dossier would return it.
    """
    return (FIXTURES / name).read_text(encoding="utf-8")


class FullDossierTests(SimpleTestCase):
    """A dossier carrying every section the generator can emit."""

    def setUp(self):
        self.entry = parse_dossier("apt29", load("dossier_full.md"))

    def test_identity_comes_from_the_heading_and_the_filename(self):
        self.assertEqual(self.entry["id"], "apt29")
        self.assertEqual(self.entry["file"], "apt29.md")
        self.assertEqual(self.entry["name"], "APT29")
        self.assertEqual(self.entry["reference"], "APT29")

    def test_group_id_is_read(self):
        self.assertEqual(self.entry["groupId"], "G0016")

    def test_summary_is_the_overview_prose_without_the_generated_line(self):
        self.assertTrue(self.entry["summary"].startswith("APT29 is a state-sponsored"))
        self.assertNotIn("Generated:", self.entry["summary"])
        self.assertNotIn("\n", self.entry["summary"])

    def test_tactics_are_unique_and_in_first_seen_order(self):
        self.assertEqual(self.entry["tactics"], ["Credential Access", "Collection", "Stealth"])

    def test_counts_come_from_table_rows_excluding_headers(self):
        self.assertEqual(self.entry["techniqueCount"], 4)
        self.assertEqual(self.entry["cveCount"], 2)
        self.assertEqual(self.entry["malwareCount"], 3)

    def test_overview_fields_are_read(self):
        self.assertEqual(self.entry["firstSeen"], "2008")
        self.assertEqual(self.entry["aliases"], ["Cozy Bear", "NOBELIUM", "The Dukes"])

    def test_filter_axes_are_canonicalised(self):
        """"Russian Federation" and "financial" are spellings, not distinct values."""
        self.assertEqual(self.entry["origin"], "Russia")
        self.assertEqual(self.entry["motivations"], ["espionage", "financial crime"])

    def test_sectors_and_provenance_are_read(self):
        self.assertEqual(self.entry["sectors"], ["Government", "Think Tanks"])
        self.assertEqual(self.entry["generatedAt"], "2026-08-14 21:54 UTC")
        self.assertEqual(self.entry["sources"], ["cisa", "mitre_attack", "cisa_kev"])


class SparseDossierTests(SimpleTestCase):
    """Five section headings are absent from at least one real dossier."""

    def setUp(self):
        self.entry = parse_dossier("killnet", load("dossier_sparse.md"))

    def test_the_dossier_heading_spelling_also_yields_a_name(self):
        """"# Threat Actor Dossier: KillNet" carries a different separator."""
        self.assertEqual(self.entry["name"], "KillNet")

    def test_missing_sections_produce_empty_values_not_errors(self):
        self.assertEqual(self.entry["groupId"], "")
        self.assertEqual(self.entry["tactics"], [])
        self.assertEqual(self.entry["techniqueCount"], 0)
        self.assertEqual(self.entry["cveCount"], 0)
        self.assertEqual(self.entry["sectors"], [])

    def test_placeholder_cells_are_dropped(self):
        """The generator writes "Unknown" and "—" for an unpopulated cell."""
        self.assertEqual(self.entry["origin"], "")
        self.assertEqual(self.entry["firstSeen"], "")
        self.assertEqual(self.entry["aliases"], [])

    def test_the_detection_resources_table_is_not_counted_as_malware(self):
        """Section extraction must stop at the next H2, not run to end of file."""
        self.assertEqual(self.entry["malwareCount"], 0)


class FirstSeenTests(SimpleTestCase):
    """
    Nineteen dossiers carry the same run-adjacent ISO timestamp as their first
    seen date. It is a placeholder, and putting a precise wrong date on a card
    is worse than showing none.
    """

    def parse(self, cell: str) -> str:
        """
        Parse a minimal dossier carrying one First Seen cell.

        Args:
            cell: Raw cell text to put in the Overview table.

        Returns:
            The entry's `firstSeen` value.
        """
        return parse_dossier(
            "actor",
            f"# Threat Actor : Actor\n\n## Overview\n\n| Field | Value |\n|---|---|\n| **First Seen** | {cell} |\n",
        )["firstSeen"]

    def test_a_bare_year_is_kept(self):
        self.assertEqual(self.parse("2008"), "2008")

    def test_a_year_range_is_kept(self):
        self.assertEqual(self.parse("2009-2012"), "2009-2012")

    def test_an_iso_timestamp_is_dropped(self):
        self.assertEqual(self.parse("2026-08-20T00:00:00+00:00"), "")


class SlugTests(SimpleTestCase):
    """Ids reach the API as a URL path segment, so they must be path-safe."""

    def test_punctuation_and_underscores_are_normalised(self):
        self.assertEqual(slugify("lapsus$"), "lapsus")
        self.assertEqual(slugify("lazarus_group"), "lazarus-group")
        self.assertEqual(slugify("apt29"), "apt29")

    def test_slug_contains_only_url_safe_characters(self):
        for stem in ("lapsus$", "anonymous_sudan", "Earth Lusca"):
            self.assertRegex(slugify(stem), r"^[a-z0-9-]+$")


class IndexTests(SimpleTestCase):
    """The index is what the list endpoint serves; ordering is its contract."""

    def test_entries_are_sorted_by_display_name(self):
        index = build_index([
            parse_dossier("killnet", load("dossier_sparse.md")),
            parse_dossier("apt29", load("dossier_full.md")),
        ])
        self.assertEqual([entry["name"] for entry in index["advisories"]], ["APT29", "KillNet"])
        self.assertEqual(index["totalCount"], 2)


class ReferenceTests(SimpleTestCase):
    """
    Six dossiers are titled with a MITRE-canonical name that is not the name the
    file is filed under (apt10.md is titled "menuPass"). Both must survive, or
    searching the library for "apt10" finds nothing.
    """

    def test_reference_keeps_the_filename_identity(self):
        entry = parse_dossier("apt10", "# Threat Actor : menuPass\n\n## Overview\n")
        self.assertEqual(entry["name"], "menuPass")
        self.assertEqual(entry["reference"], "APT10")
        self.assertEqual(entry["id"], "apt10")

    def test_reference_is_the_fallback_name_when_there_is_no_heading(self):
        entry = parse_dossier("lazarus_group", "## Overview\n")
        self.assertEqual(entry["name"], "LAZARUS GROUP")
