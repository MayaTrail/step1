"""
Tests for the manifest-driven readiness contract (apps/emulations/readiness.py).

Two layers:

  * Unit tests for resolve_readiness / requires_http_probe / validate_readiness —
    pure, no Django DB.
  * A discovery test that folds validate_readiness over every emulation the
    registry discovers, so a real emulation shipping a missing or malformed
    readiness block fails CI at PR time rather than as a FAILED stack at deploy
    time.  Mirrors apps/metrics/tests/test_contracts.py.
"""

import os
from pathlib import Path

from django.test import SimpleTestCase

from apps.emulations import registry as registry_wrapper
from apps.emulations.readiness import (
    DEFAULT_READINESS,
    requires_http_probe,
    resolve_readiness,
    validate_readiness,
)

# backend/apps/emulations/tests/test_readiness.py -> repo root (step1) is parents[4].
_REPO_ROOT = Path(__file__).resolve().parents[4]
_FALLBACK_EMULATIONS_DIR = _REPO_ROOT / "emulations"


def _resolve_emulations_dir() -> Path:
    """Prefer EMULATIONS_BASE_DIR (Docker); fall back to the repo emulations/ dir."""
    env_dir = os.environ.get("EMULATIONS_BASE_DIR", "")
    if env_dir and Path(env_dir).is_dir():
        return Path(env_dir)
    return _FALLBACK_EMULATIONS_DIR


def _load_emulations(base_dir: Path):
    """Point the registry at base_dir and return the discovered catalogue."""
    os.environ["EMULATIONS_BASE_DIR"] = str(base_dir)
    registry_wrapper.reset_cache()
    return registry_wrapper.list_emulations()


class ResolveReadinessTests(SimpleTestCase):
    """resolve_readiness / requires_http_probe behaviour."""

    def test_absent_readiness_falls_back_to_default(self):
        r = resolve_readiness({})
        self.assertEqual(r, DEFAULT_READINESS)
        self.assertEqual(r["ip_output"], "vuln_instance_ip")
        self.assertTrue(requires_http_probe(r))

    def test_none_readiness_skips_probe(self):
        r = resolve_readiness({"readiness": {"type": "none"}})
        self.assertEqual(r["type"], "none")
        self.assertFalse(requires_http_probe(r))

    def test_custom_ec2_http_readiness_passthrough(self):
        custom = {"type": "ec2_http", "ip_output": "web_ip", "port": 9000, "path": "/ready"}
        r = resolve_readiness({"readiness": custom})
        self.assertEqual(r, custom)
        self.assertTrue(requires_http_probe(r))

    def test_unknown_type_does_not_trigger_probe(self):
        # Positive dispatch: only ec2_http probes; an unknown type never silently
        # routes into the poll path (validation rejects it separately).
        self.assertFalse(requires_http_probe({"type": "tcp"}))


class ValidateReadinessTests(SimpleTestCase):
    """validate_readiness contract enforcement."""

    def test_none_block_is_valid(self):
        self.assertEqual(validate_readiness({"name": "x", "readiness": {"type": "none"}}), [])

    def test_full_ec2_http_block_is_valid(self):
        manifest = {
            "name": "x",
            "readiness": {"type": "ec2_http", "ip_output": "vuln_instance_ip", "port": 8080, "path": "/health"},
        }
        self.assertEqual(validate_readiness(manifest), [])

    def test_missing_readiness_field_is_rejected(self):
        errors = validate_readiness({"name": "x"})
        self.assertEqual(len(errors), 1)
        self.assertIn("'readiness' is required", errors[0])

    def test_unknown_type_is_rejected(self):
        errors = validate_readiness({"name": "x", "readiness": {"type": "non"}})
        self.assertEqual(len(errors), 1)
        self.assertIn("readiness.type must be one of", errors[0])

    def test_ec2_http_missing_keys_is_rejected(self):
        errors = validate_readiness({"name": "x", "readiness": {"type": "ec2_http"}})
        # ip_output, port and path are all required for ec2_http.
        self.assertEqual(len(errors), 3)
        joined = "\n".join(errors)
        self.assertIn("readiness.ip_output is required", joined)
        self.assertIn("readiness.port is required", joined)
        self.assertIn("readiness.path is required", joined)

    def test_ec2_http_bad_shapes_are_rejected(self):
        manifest = {
            "name": "x",
            "readiness": {"type": "ec2_http", "ip_output": "", "port": "8080", "path": "health"},
        }
        errors = validate_readiness(manifest)
        joined = "\n".join(errors)
        self.assertIn("readiness.ip_output must be a non-empty string", joined)
        self.assertIn("readiness.port must be an int", joined)
        self.assertIn("readiness.path must be a string beginning with '/'", joined)

    def test_non_dict_readiness_is_rejected(self):
        errors = validate_readiness({"name": "x", "readiness": "none"})
        self.assertEqual(len(errors), 1)
        self.assertIn("must be an object", errors[0])


class DiscoveredEmulationsReadinessTests(SimpleTestCase):
    """Every registered emulation declares a contract-compliant readiness block."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.emulations_dir = _resolve_emulations_dir()
        cls.emulations = _load_emulations(cls.emulations_dir)

    def test_at_least_one_emulation_discovered(self):
        self.assertGreater(
            len(self.emulations),
            0,
            "No emulations discovered — readiness validation would be meaningless",
        )

    def test_all_emulations_declare_valid_readiness(self):
        all_errors: list[str] = []
        for entry in self.emulations:
            all_errors.extend(validate_readiness(entry))

        self.assertEqual(
            all_errors,
            [],
            "Emulation(s) violate the readiness contract:\n  - " + "\n  - ".join(all_errors),
        )
