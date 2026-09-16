"""
Tests for locating the PLAYBOOK.md that ships with an emulation package.

These run against the real emulations/ tree in the repository rather than a
fixture, so they fail if the packaging layout changes under the fork endpoint.
They skip when the tree is not present (a checkout without it, or a container
where EMULATIONS_BASE_DIR points elsewhere).
"""

from __future__ import annotations

import unittest
from pathlib import Path
from unittest import mock

from django.test import SimpleTestCase

from apps.playbooks.sources import PlaybookSourceError, load_shipped_playbook

# backend/apps/playbooks/tests/ -> repository root -> emulations/
EMULATIONS_DIR = Path(__file__).resolve().parents[4] / "emulations"
HAVE_EMULATIONS = (EMULATIONS_DIR / "ambersquid" / "PLAYBOOK.md").exists()


@unittest.skipUnless(HAVE_EMULATIONS, "emulations/ tree not available")
class LoadShippedPlaybookTests(SimpleTestCase):
    """Reading a real shipped playbook off disk."""

    def test_reads_the_ambersquid_playbook(self):
        """The AMBERSQUID package's playbook comes back whole."""
        entry = {"display_name": "AMBERSQUID"}
        with mock.patch("apps.playbooks.sources.get_emulation", return_value=entry), \
                mock.patch.dict("os.environ", {"EMULATIONS_BASE_DIR": str(EMULATIONS_DIR)}):
            display_name, markdown = load_shipped_playbook("ambersquid")

        self.assertEqual(display_name, "AMBERSQUID")
        self.assertIn("IR Playbook: AMBERSQUID", markdown)
        self.assertIn("## 3. Containment", markdown)
        # The real file is substantial; a truncated read would pass a mere
        # "is not empty" assertion.
        self.assertGreater(len(markdown), 20_000)

    def test_unknown_emulation_raises(self):
        """An emulation the registry does not know is an error, not an empty doc."""
        with mock.patch("apps.playbooks.sources.get_emulation", return_value=None):
            with self.assertRaises(PlaybookSourceError):
                load_shipped_playbook("no-such-emulation")

    def test_package_without_a_playbook_raises(self):
        """A package that ships no PLAYBOOK.md reports that, rather than 500ing."""
        entry = {"display_name": "Nothing here"}
        with mock.patch("apps.playbooks.sources.get_emulation", return_value=entry), \
                mock.patch.dict("os.environ", {"EMULATIONS_BASE_DIR": str(EMULATIONS_DIR)}):
            with self.assertRaises(PlaybookSourceError) as ctx:
                load_shipped_playbook("__definitely_not_a_package__")
        self.assertIn("does not ship a playbook", str(ctx.exception))

    def test_missing_base_dir_raises(self):
        """Without EMULATIONS_BASE_DIR there is nowhere to look."""
        entry = {"display_name": "AMBERSQUID"}
        with mock.patch("apps.playbooks.sources.get_emulation", return_value=entry), \
                mock.patch.dict("os.environ", {"EMULATIONS_BASE_DIR": ""}):
            with self.assertRaises(PlaybookSourceError) as ctx:
                load_shipped_playbook("ambersquid")
        self.assertIn("EMULATIONS_BASE_DIR", str(ctx.exception))

    def test_detections_path_takes_precedence(self):
        """
        When the registry entry carries detections_path, the package directory is
        derived from it and EMULATIONS_BASE_DIR is not consulted.
        """
        entry = {
            "display_name": "AMBERSQUID",
            "detections_path": str(EMULATIONS_DIR / "ambersquid" / "detections"),
        }
        with mock.patch("apps.playbooks.sources.get_emulation", return_value=entry), \
                mock.patch.dict("os.environ", {"EMULATIONS_BASE_DIR": "/nonexistent"}):
            _, markdown = load_shipped_playbook("ambersquid")
        self.assertIn("IR Playbook: AMBERSQUID", markdown)
