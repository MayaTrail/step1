"""
Tests for the bundled MITRE ATT&CK catalogue and its normalisation helpers.

These guard the two things the coverage score depends on: a sane denominator
and correct sub-technique roll-up / revoked-ID forward resolution.
"""

from django.test import SimpleTestCase

from apps.metrics.mitre import catalog


class CatalogStructureTests(SimpleTestCase):
    """The shipped catalog.json is well-formed and plausibly sized."""

    def test_denominator_is_plausible(self):
        """Enterprise technique-level count should sit in the expected band."""
        count = catalog.technique_count()
        self.assertGreater(count, 150)
        self.assertLess(count, 300)

    def test_tactics_present_and_ordered(self):
        """Tactics are non-empty and each carries a shortname used by the heatmap."""
        tactics = catalog.tactics()
        self.assertGreater(len(tactics), 10)
        for tactic in tactics:
            self.assertTrue(tactic.get("shortname"))
            self.assertTrue(tactic.get("name"))

    def test_attack_version_is_reported(self):
        """The catalogue records which ATT&CK release it was generated from."""
        self.assertNotEqual(catalog.attack_version(), "unknown")


class NormalisationTests(SimpleTestCase):
    """normalize_technique handles roll-up and revocation in one place."""

    def test_subtechnique_rolls_up_to_parent(self):
        self.assertEqual(catalog.normalize_technique("T1552.005"), "T1552")

    def test_whitespace_is_tolerated(self):
        self.assertEqual(catalog.normalize_technique("  T1190 "), "T1190")

    def test_revoked_id_forwards_to_replacement(self):
        """T1562 was revoked in favour of T1685 in ATT&CK v19."""
        self.assertEqual(catalog.normalize_technique("T1562.008"), "T1685")

    def test_known_technique_is_recognised(self):
        self.assertTrue(catalog.is_known("T1190"))

    def test_revoked_technique_still_resolves_as_known(self):
        self.assertTrue(catalog.is_known("T1562.008"))

    def test_unknown_technique_is_not_known(self):
        self.assertFalse(catalog.is_known("T9999"))

    def test_tactics_for_uses_catalogue_not_label(self):
        """Tactic placement comes from the catalogue, so it is always populated."""
        self.assertIn("initial-access", catalog.tactics_for("T1190"))
