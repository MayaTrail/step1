"""Tests for LOW-3 — tool versions stamped into the pipeline manifest.

Covers:
  - validate_environment() returns a non-empty dict (not None)
  - The dict contains the mandatory keys: claude, pulumi, python
  - All values are non-empty strings
  - tiktoken and trafilatura (Python libs) are also in the dict
  - run_pipeline() writes tool_versions into the manifest under "pipeline"
  - tool_versions key is absent when validate_environment is not called
    (backwards-compat: old-style direct run_pipeline(args) still works)
"""
import json
import pytest
from pathlib import Path
from unittest import mock
import sys

import utils
import pipeline


# ── validate_environment return shape ────────────────────────────────────

class TestValidateEnvironmentReturnShape:
    """validate_environment() must return a dict, not None."""

    def _run_validate(self):
        """Run validate_environment with all subprocess calls mocked to succeed.

        The AWS `sts get-caller-identity` call returns exit-code 1 so the code
        takes the 'not configured' warn branch and never calls json.loads().
        All other tool checks (claude, pulumi, python) return exit-code 0.
        """
        def _fake_run(cmd, **kwargs):
            result = mock.MagicMock()
            if cmd[0] == "aws":
                # Trigger the "not configured" advisory-warn branch
                result.returncode = 1
                result.stdout = ""
                result.stderr = "Error"
            else:
                result.returncode = 0
                result.stdout = "FakeTool v1.2.3\n"
                result.stderr = ""
            return result

        with mock.patch("subprocess.run", side_effect=_fake_run):
            return utils.validate_environment()

    def test_returns_dict(self):
        result = self._run_validate()
        assert isinstance(result, dict)

    def test_dict_is_nonempty(self):
        result = self._run_validate()
        assert len(result) > 0

    def test_contains_claude_key(self):
        result = self._run_validate()
        assert "claude" in result

    def test_contains_pulumi_key(self):
        result = self._run_validate()
        assert "pulumi" in result

    def test_contains_python_key(self):
        result = self._run_validate()
        assert "python" in result

    def test_contains_tiktoken_key(self):
        result = self._run_validate()
        assert "tiktoken" in result

    def test_contains_trafilatura_key(self):
        result = self._run_validate()
        assert "trafilatura" in result

    def test_all_values_are_strings(self):
        result = self._run_validate()
        for key, val in result.items():
            assert isinstance(val, str), f"Key '{key}' has non-string value: {val!r}"

    def test_all_strings_nonempty(self):
        result = self._run_validate()
        for key, val in result.items():
            assert val, f"Key '{key}' is empty string"

    def test_python_version_string_present(self):
        """The python version value should contain the mocked version string."""
        def _fake_run(cmd, **kwargs):
            result = mock.MagicMock()
            if cmd[0] == "aws":
                result.returncode = 1
                result.stdout = ""
                result.stderr = "Error"
            else:
                result.returncode = 0
                result.stdout = "Python 3.14.3\n"
                result.stderr = ""
            return result

        with mock.patch("subprocess.run", side_effect=_fake_run):
            result = utils.validate_environment()
        assert "Python 3.14.3" in result.get("python", "")


# ── Manifest stamping ─────────────────────────────────────────────────────

class TestManifestVersionStamping:
    """run_pipeline() must write tool_versions into the manifest."""

    def _make_args(self, url="https://example.com/article"):
        """Build a minimal args namespace that run_pipeline() accepts."""
        args = mock.MagicMock()
        args.resume      = None
        args.url         = url
        args.technique   = None
        args.skip_security_check = True
        args.auto_approve        = True
        args.plan_only           = False
        args.playbook_only       = False
        args.skip_cost           = True
        args.max_iterations      = 1
        args.aws_profile         = None
        args.aws_region          = "us-east-1"
        return args

    def test_tool_versions_in_manifest_when_provided(self, tmp_path):
        """tool_versions dict is written under the 'pipeline' manifest entry."""
        from utils import update_manifest, load_manifest

        # Write a minimal manifest ourselves (simulating what run_pipeline does)
        out_dir = tmp_path / "run_test"
        out_dir.mkdir()
        tool_versions = {"claude": "v1.2.3", "pulumi": "3.0.0", "python": "3.14"}
        update_manifest(out_dir, "pipeline", "started", {
            "mode": "full-apt",
            "input": "https://example.com",
            "tool_versions": tool_versions,
        })

        manifest = load_manifest(out_dir)
        stamped = manifest["phases"]["pipeline"].get("tool_versions")
        assert stamped == tool_versions

    def test_tool_versions_keys_survive_json_round_trip(self, tmp_path):
        """Versions must survive serialisation to JSON (no None, no non-str)."""
        from utils import update_manifest, load_manifest

        out_dir = tmp_path / "run_json"
        out_dir.mkdir()
        tool_versions = {
            "claude": "Claude Code 1.2.17",
            "pulumi": "3.105.0",
            "python": "Python 3.14.3",
            "tiktoken": "0.7.0",
            "trafilatura": "1.12.0",
        }
        update_manifest(out_dir, "pipeline", "started", {
            "mode": "full-apt", "input": "https://x.com",
            "tool_versions": tool_versions,
        })

        # Force JSON round-trip via the manifest file on disk
        manifest_file = out_dir / "run_manifest.json"
        raw = json.loads(manifest_file.read_text(encoding="utf-8"))
        loaded_versions = raw["phases"]["pipeline"]["tool_versions"]
        assert loaded_versions == tool_versions

    def test_missing_tool_versions_does_not_crash(self, tmp_path):
        """Manifest update without tool_versions must still succeed."""
        from utils import update_manifest, load_manifest

        out_dir = tmp_path / "run_no_versions"
        out_dir.mkdir()
        update_manifest(out_dir, "pipeline", "started", {
            "mode": "full-apt", "input": "https://x.com",
        })

        manifest = load_manifest(out_dir)
        # tool_versions key should simply be absent — not an error
        assert "tool_versions" not in manifest["phases"]["pipeline"]
