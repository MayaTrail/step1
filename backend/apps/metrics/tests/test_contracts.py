"""
Contract tests for emulation manifests.

This is the forward-compatibility safety net: every emulation discovered by the
registry must satisfy the dashboard contract (apps/metrics/contracts.py).  If a
future emulation is added without the fields the dashboard needs — a platform,
a valid mitre_mappings list, threat-actor metadata — these tests fail in CI
rather than the dashboard silently miscounting.

The registry loads from the EMULATIONS_BASE_DIR environment variable, which the
Docker images set to /opt/emulations.  To work both inside the container and in
a local checkout, the test honours that variable when it points at a real
directory and otherwise falls back to the repository's emulations/ directory,
computed relative to this file.
"""

import os
from pathlib import Path

from django.test import SimpleTestCase

from apps.emulations import registry as registry_wrapper
from apps.metrics.contracts import validate_manifest

# backend/apps/metrics/tests/test_contracts.py -> repo root (step1) is parents[4].
_REPO_ROOT = Path(__file__).resolve().parents[4]
_FALLBACK_EMULATIONS_DIR = _REPO_ROOT / "emulations"


def _resolve_emulations_dir() -> Path:
    """
    Return the emulations directory to discover from.

    Prefers EMULATIONS_BASE_DIR (set to /opt/emulations in Docker); falls back
    to the repo-relative emulations/ directory for a bare local checkout.
    """
    env_dir = os.environ.get("EMULATIONS_BASE_DIR", "")
    if env_dir and Path(env_dir).is_dir():
        return Path(env_dir)
    return _FALLBACK_EMULATIONS_DIR


def _load_emulations(base_dir: Path):
    """Point the registry at base_dir and return the discovered catalogue."""
    os.environ["EMULATIONS_BASE_DIR"] = str(base_dir)
    registry_wrapper.reset_cache()
    return registry_wrapper.list_emulations()


class ManifestContractTests(SimpleTestCase):
    """Every registered emulation is dashboard-compliant."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.emulations_dir = _resolve_emulations_dir()
        cls.emulations = _load_emulations(cls.emulations_dir)

    def test_emulations_directory_exists(self):
        """Sanity: the resolved emulations directory exists."""
        self.assertTrue(
            self.emulations_dir.is_dir(),
            f"emulations directory not found at {self.emulations_dir}",
        )

    def test_at_least_one_emulation_discovered(self):
        """The registry must actually load content, or the contract check is vacuous."""
        self.assertGreater(
            len(self.emulations),
            0,
            "No emulations discovered — contract validation would be meaningless",
        )

    def test_all_emulations_satisfy_dashboard_contract(self):
        """Each discovered manifest passes validate_manifest with zero errors."""
        all_errors: list[str] = []
        for entry in self.emulations:
            all_errors.extend(validate_manifest(entry))

        self.assertEqual(
            all_errors,
            [],
            "Emulation manifest(s) violate the dashboard contract:\n  - "
            + "\n  - ".join(all_errors),
        )

    def _base_valid_entry(self) -> dict:
        """A minimal manifest entry that satisfies the contract — for negative tests."""
        return {
            "schema_version": 3,
            "name": "ref-contract-fixture",
            "display_name": "Fixture",
            "origin": "test",
            "attribution": "test",
            "severity": "HIGH",
            "platform": "aws",
            "mitre_mappings": [{"id": "T1078", "name": "Valid Accounts"}],
            "references": [
                {"title": "Linked", "type": "REPORT", "url": "https://example.com/report"},
            ],
        }

    def test_valid_reference_passes(self):
        """A reference with a proper http url produces no contract error."""
        self.assertEqual(validate_manifest(self._base_valid_entry()), [])

    def test_reference_without_url_is_rejected(self):
        """A reference missing a url fails the contract (the enforced rule)."""
        entry = self._base_valid_entry()
        entry["references"] = [{"title": "No link", "type": "REPORT"}]
        errors = validate_manifest(entry)
        self.assertTrue(any("url" in e for e in errors), errors)

    def test_reference_with_non_http_url_is_rejected(self):
        """A reference whose url is not an http(s) link fails the contract."""
        entry = self._base_valid_entry()
        entry["references"] = [{"title": "Bad", "type": "REPORT", "url": "ftp://x"}]
        errors = validate_manifest(entry)
        self.assertTrue(any("http" in e for e in errors), errors)

    def test_empty_references_is_rejected(self):
        """An emulation with no references fails the contract."""
        entry = self._base_valid_entry()
        entry["references"] = []
        errors = validate_manifest(entry)
        self.assertTrue(any("references" in e for e in errors), errors)
