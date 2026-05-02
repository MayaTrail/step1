"""Tests for _load_implementor — the base+task+platform overlay composer.

Invariants:
  - Always includes base compat rules content
  - Always includes the requested task section
  - Platform overlay is appended when the file exists, silently skipped otherwise
  - Sections are separated by '---'
  - File-not-found for task overlay raises FileNotFoundError (caught by caller)
"""
import pytest
from pathlib import Path
from utils import _load_implementor

# Resolve agents directory relative to this test file
AGENTS_DIR = Path(__file__).resolve().parent.parent / "agents"


class TestBasicComposition:
    def test_base_content_included(self):
        result = _load_implementor(AGENTS_DIR, "attack", "aws")
        # Base file always starts with the role header
        assert "Code Implementor" in result

    def test_compat_rules_included(self):
        result = _load_implementor(AGENTS_DIR, "attack", "aws")
        assert "CRITICAL COMPATIBILITY RULES" in result

    def test_task_section_included_attack(self):
        result = _load_implementor(AGENTS_DIR, "attack", "aws")
        assert "TASK: IMPLEMENT ATTACK SCRIPT" in result

    def test_task_section_included_infra(self):
        result = _load_implementor(AGENTS_DIR, "infra", "aws")
        assert "TASK: IMPLEMENT INFRASTRUCTURE" in result

    def test_task_section_included_detections(self):
        result = _load_implementor(AGENTS_DIR, "detections", "aws")
        assert "TASK: GENERATE DETECTIONS" in result

    def test_task_section_included_playbook(self):
        result = _load_implementor(AGENTS_DIR, "playbook", "aws")
        assert "TASK: GENERATE PLAYBOOK" in result

    def test_task_section_included_guardrails(self):
        result = _load_implementor(AGENTS_DIR, "guardrails", "aws")
        assert "TASK: GENERATE GUARDRAILS" in result

    def test_sections_separated_by_divider(self):
        result = _load_implementor(AGENTS_DIR, "attack", "aws")
        assert "---" in result


class TestCrossContamination:
    """Each task overlay should contain ONLY its own task section."""

    def test_infra_does_not_include_attack_section(self):
        result = _load_implementor(AGENTS_DIR, "infra", "aws")
        assert "TASK: IMPLEMENT ATTACK SCRIPT" not in result

    def test_attack_does_not_include_infra_section(self):
        result = _load_implementor(AGENTS_DIR, "attack", "aws")
        assert "TASK: IMPLEMENT INFRASTRUCTURE" not in result

    def test_detections_does_not_include_playbook_section(self):
        result = _load_implementor(AGENTS_DIR, "detections", "aws")
        assert "TASK: GENERATE PLAYBOOK" not in result

    def test_playbook_does_not_include_guardrails_section(self):
        result = _load_implementor(AGENTS_DIR, "playbook", "aws")
        assert "TASK: GENERATE GUARDRAILS" not in result


class TestPlatformOverlay:
    def test_no_overlay_file_does_not_raise(self):
        # 'aws' has no compat overlay — should compose cleanly without it
        result = _load_implementor(AGENTS_DIR, "attack", "aws")
        assert len(result) > 0

    def test_unknown_platform_does_not_raise(self):
        # Platform with no overlay file — graceful skip
        result = _load_implementor(AGENTS_DIR, "attack", "nonexistent_cloud")
        assert "TASK: IMPLEMENT ATTACK SCRIPT" in result

    def test_overlay_appended_when_file_exists(self, tmp_path):
        # Create a temporary agents dir with base, task, and platform overlay
        (tmp_path / "opus_implementor_base.md").write_text("BASE_CONTENT", encoding="utf-8")
        (tmp_path / "opus_implementor_attack.md").write_text("ATTACK_CONTENT", encoding="utf-8")
        (tmp_path / "opus_implementor_compat_testcloud.md").write_text(
            "TESTCLOUD_COMPAT", encoding="utf-8"
        )
        result = _load_implementor(tmp_path, "attack", "testcloud")
        assert "BASE_CONTENT" in result
        assert "TESTCLOUD_COMPAT" in result
        assert "ATTACK_CONTENT" in result

    def test_overlay_order_base_then_platform_then_task(self, tmp_path):
        (tmp_path / "opus_implementor_base.md").write_text("BASE", encoding="utf-8")
        (tmp_path / "opus_implementor_infra.md").write_text("TASK", encoding="utf-8")
        (tmp_path / "opus_implementor_compat_mycloud.md").write_text("PLATFORM", encoding="utf-8")
        result = _load_implementor(tmp_path, "infra", "mycloud")
        base_pos = result.index("BASE")
        platform_pos = result.index("PLATFORM")
        task_pos = result.index("TASK")
        assert base_pos < platform_pos < task_pos


class TestSizeInvariant:
    """Task-specific prompt must be smaller than the old monolith."""

    def test_attack_overlay_smaller_than_legacy(self):
        legacy = (AGENTS_DIR / "opus_implementor_legacy.md").read_text(encoding="utf-8")
        result = _load_implementor(AGENTS_DIR, "attack", "aws")
        # base + attack overlay should be noticeably smaller than the monolith
        assert len(result) < len(legacy)

    def test_each_task_overlay_smaller_than_legacy(self):
        legacy_len = len((AGENTS_DIR / "opus_implementor_legacy.md").read_text(encoding="utf-8"))
        for task in ("infra", "attack", "detections", "playbook", "guardrails"):
            result = _load_implementor(AGENTS_DIR, task, "aws")
            assert len(result) < legacy_len, f"{task} overlay not smaller than legacy"


class TestMissingFile:
    def test_missing_task_file_raises(self, tmp_path):
        (tmp_path / "opus_implementor_base.md").write_text("BASE", encoding="utf-8")
        with pytest.raises(FileNotFoundError):
            _load_implementor(tmp_path, "nonexistent_task", "aws")

    def test_missing_base_file_raises(self, tmp_path):
        (tmp_path / "opus_implementor_attack.md").write_text("TASK", encoding="utf-8")
        with pytest.raises(FileNotFoundError):
            _load_implementor(tmp_path, "attack", "aws")
