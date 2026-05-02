"""
CRIT-1 regression tests.

The bug: when a rate limit hits during phase 5 or 6, the pipeline marks the
phase as "complete" with 0 files.  The next --resume sees status=="complete"
and skips the phase, producing a pipeline that says "DONE" with no attack.py
and no detections.

The fix: any phase that exits due to a rate limit must be written to the
manifest with a non-"complete" status so that done() returns False and the
resume re-runs it.
"""

import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pipeline import phase_5_code_generation, phase_6_detections_and_content
from utils import PipelineError, load_manifest


# ── Fixtures ────────────────────────────────────────────────────────────────

MINIMAL_TI = {
    "platform": "aws",
    "threat_actor": {"name": "TEST"},
    "techniques": [{"mitre_id": "T1078.004", "execution_plane": "control_plane"}],
    "credential_chain": [],
    "targeted_services": [],
    "iocs": {},
    "operational_notes": {},
}

MINIMAL_INFRA = {
    "resources": [],
    "resource_dependency_order": [],
}

MINIMAL_ATTACK = {
    "attack_chain": [],
    "credential_chain": [],
    "script_manifest": {},
}

RATE_LIMIT_MSG = "RATE_LIMIT_EXIT: resets at 6:40pm (~13766s). Re-run the pipeline after that time."


# ── Unit tests: _rate_limit_aware_status helper ──────────────────────────────

class TestRateLimitAwareStatus:
    """The helper must exist in pipeline and return the right status string."""

    def test_no_errors_returns_complete(self):
        from pipeline import _rate_limit_aware_status
        assert _rate_limit_aware_status([]) == "complete"

    def test_rate_limit_error_returns_incomplete(self):
        from pipeline import _rate_limit_aware_status
        errors = [f"PHASE-5B: {RATE_LIMIT_MSG}"]
        assert _rate_limit_aware_status(errors) == "incomplete_rate_limit"

    def test_non_rate_limit_error_returns_complete(self):
        """Non-rate-limit partial failures (e.g. 5A timeout) still mark complete
        so the pipeline doesn't loop on transient errors — only rate limits get
        the special incomplete status."""
        from pipeline import _rate_limit_aware_status
        errors = ["PHASE-5A: Timeout after 1500s"]
        assert _rate_limit_aware_status(errors) == "complete"

    def test_mixed_errors_rate_limit_wins(self):
        from pipeline import _rate_limit_aware_status
        errors = ["PHASE-5A: Timeout after 1500s", f"PHASE-5B: {RATE_LIMIT_MSG}"]
        assert _rate_limit_aware_status(errors) == "incomplete_rate_limit"


# ── Integration tests: manifest status after phase 5 rate-limit ─────────────

class TestPhase5ManifestStatusOnRateLimit:

    def test_manifest_not_marked_complete_when_5b_rate_limited(self, tmp_path):
        """When phase 5B is rate-limited, manifest phase_5 must NOT be 'complete'."""
        with patch("pipeline.call_claude") as mock_call, \
             patch("pipeline._load_implementor", return_value="mock-agent"):

            def fake_call(model, agent, prompt, label, **kwargs):
                if "PHASE-5B" in label:
                    raise PipelineError(RATE_LIMIT_MSG)
                # 5A returns an empty summary (no code blocks) — simulates direct write
                return ("Files written.", {"input_tokens": 10, "output_tokens": 5})

            mock_call.side_effect = fake_call

            phase_5_code_generation(
                MINIMAL_TI, MINIMAL_INFRA, MINIMAL_ATTACK, tmp_path
            )

        manifest = load_manifest(tmp_path)
        phase5 = manifest["phases"]["phase_5"]
        assert phase5["status"] != "complete", (
            f"phase_5 was marked '{phase5['status']}' but should be "
            f"'incomplete_rate_limit' after a rate-limit exit"
        )

    def test_manifest_status_is_incomplete_rate_limit_when_5b_rate_limited(self, tmp_path):
        """The specific status value must be 'incomplete_rate_limit'."""
        with patch("pipeline.call_claude") as mock_call, \
             patch("pipeline._load_implementor", return_value="mock-agent"):

            def fake_call(model, agent, prompt, label, **kwargs):
                if "PHASE-5B" in label:
                    raise PipelineError(RATE_LIMIT_MSG)
                return ("ok", {"input_tokens": 10, "output_tokens": 5})

            mock_call.side_effect = fake_call

            phase_5_code_generation(
                MINIMAL_TI, MINIMAL_INFRA, MINIMAL_ATTACK, tmp_path
            )

        manifest = load_manifest(tmp_path)
        assert manifest["phases"]["phase_5"]["status"] == "incomplete_rate_limit"

    def test_manifest_complete_when_both_succeed(self, tmp_path):
        """When neither sub-phase is rate-limited, status must be 'complete'."""
        with patch("pipeline.call_claude") as mock_call, \
             patch("pipeline._load_implementor", return_value="mock-agent"):

            mock_call.return_value = ("ok", {"input_tokens": 10, "output_tokens": 5})

            phase_5_code_generation(
                MINIMAL_TI, MINIMAL_INFRA, MINIMAL_ATTACK, tmp_path
            )

        manifest = load_manifest(tmp_path)
        assert manifest["phases"]["phase_5"]["status"] == "complete"

    def test_done_returns_false_after_rate_limit(self, tmp_path):
        """Simulates the resume check: done('phase_5') must be False after a
        rate-limit exit so the pipeline re-runs the phase."""
        # Write a manifest with the old broken status
        manifest_path = tmp_path / "run_manifest.json"
        manifest_path.write_text(json.dumps({
            "run_id": "test",
            "phases": {
                "phase_5": {
                    "status": "incomplete_rate_limit",
                    "attack_files": 0,
                }
            }
        }))

        from utils import is_phase_complete
        assert is_phase_complete(tmp_path, "phase_5") is False

    def test_done_returns_true_only_for_complete(self, tmp_path):
        manifest_path = tmp_path / "run_manifest.json"
        manifest_path.write_text(json.dumps({
            "run_id": "test",
            "phases": {"phase_5": {"status": "complete", "attack_files": 1}}
        }))

        from utils import is_phase_complete
        assert is_phase_complete(tmp_path, "phase_5") is True


# ── Integration tests: manifest status after phase 6 rate-limit ─────────────

class TestPhase6ManifestStatusOnRateLimit:

    def test_manifest_not_marked_complete_when_6a_rate_limited(self, tmp_path):
        """When phase 6A (detections) is rate-limited, manifest must NOT be 'complete'."""
        with patch("pipeline.call_claude") as mock_call, \
             patch("pipeline._load_implementor", return_value="mock-agent"):

            def fake_call(model, agent, prompt, label, **kwargs):
                if "PHASE-6A" in label:
                    raise PipelineError(RATE_LIMIT_MSG)
                return ("ok", {"input_tokens": 10, "output_tokens": 5})

            mock_call.side_effect = fake_call

            phase_6_detections_and_content(MINIMAL_TI, MINIMAL_ATTACK, tmp_path)

        manifest = load_manifest(tmp_path)
        phase6 = manifest["phases"]["phase_6"]
        assert phase6["status"] != "complete", (
            f"phase_6 was marked '{phase6['status']}' after a rate-limit exit"
        )

    def test_manifest_status_is_incomplete_rate_limit_when_6c_rate_limited(self, tmp_path):
        """6C (guardrails) rate-limit must also set incomplete status."""
        with patch("pipeline.call_claude") as mock_call, \
             patch("pipeline._load_implementor", return_value="mock-agent"):

            def fake_call(model, agent, prompt, label, **kwargs):
                if "PHASE-6C" in label:
                    raise PipelineError(RATE_LIMIT_MSG)
                return ("ok", {"input_tokens": 10, "output_tokens": 5})

            mock_call.side_effect = fake_call

            phase_6_detections_and_content(MINIMAL_TI, MINIMAL_ATTACK, tmp_path)

        manifest = load_manifest(tmp_path)
        assert manifest["phases"]["phase_6"]["status"] == "incomplete_rate_limit"

    def test_manifest_complete_when_all_6_succeed(self, tmp_path):
        with patch("pipeline.call_claude") as mock_call, \
             patch("pipeline._load_implementor", return_value="mock-agent"):

            mock_call.return_value = ("ok", {"input_tokens": 10, "output_tokens": 5})

            phase_6_detections_and_content(MINIMAL_TI, MINIMAL_ATTACK, tmp_path)

        manifest = load_manifest(tmp_path)
        assert manifest["phases"]["phase_6"]["status"] == "complete"
