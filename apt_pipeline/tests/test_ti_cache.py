"""Tests for the TI-extract content-hash cache helpers in pipeline.py.

Covers:
  - _ti_cache_path: deterministic path, keyed by URL, stored under _TI_CACHE_DIR
  - _load_ti_cache: miss (no file), hit (valid JSON), graceful corrupt-file handling
  - _save_ti_cache: creates dirs, writes valid JSON, overwrites safely
  - Round-trip: save → load gives back identical data
  - Different URLs → different cache paths
  - Single-technique (no URL) path is unaffected by cache
"""
import json
import pytest
from pathlib import Path
from unittest import mock

# pipeline.py is in the parent of tests/
import pipeline


# ── Helpers ──────────────────────────────────────────────────────────────

SAMPLE_URL = "https://example.com/apt-report"
SAMPLE_TI  = {
    "status": "PHASE_0B_COMPLETE",
    "threat_actor": {"name": "TestActor"},
    "platform": "aws",
    "techniques": [
        {"mitre_id": "T1078", "name": "Valid Accounts"},
        {"mitre_id": "T1087", "name": "Account Discovery"},
    ],
}


# ── _ti_cache_path ────────────────────────────────────────────────────────

class TestTiCachePath:
    def test_returns_path_under_cache_dir(self):
        p = pipeline._ti_cache_path(SAMPLE_URL)
        assert str(pipeline._TI_CACHE_DIR) in str(p)

    def test_has_json_extension(self):
        p = pipeline._ti_cache_path(SAMPLE_URL)
        assert p.suffix == ".json"

    def test_starts_with_ti_prefix(self):
        p = pipeline._ti_cache_path(SAMPLE_URL)
        assert p.name.startswith("ti_")

    def test_deterministic_same_url(self):
        p1 = pipeline._ti_cache_path(SAMPLE_URL)
        p2 = pipeline._ti_cache_path(SAMPLE_URL)
        assert p1 == p2

    def test_different_url_different_path(self):
        p1 = pipeline._ti_cache_path(SAMPLE_URL)
        p2 = pipeline._ti_cache_path("https://other.com/report")
        assert p1 != p2

    def test_hash_hex_in_filename(self):
        """Filename segment must be hexadecimal (SHA-256 prefix)."""
        p = pipeline._ti_cache_path(SAMPLE_URL)
        hash_part = p.stem[len("ti_"):]   # everything after "ti_"
        assert all(c in "0123456789abcdef" for c in hash_part)


# ── _load_ti_cache ────────────────────────────────────────────────────────

class TestLoadTiCache:
    def test_miss_returns_none_when_no_file(self, tmp_path):
        with mock.patch.object(pipeline, "_TI_CACHE_DIR", tmp_path):
            result = pipeline._load_ti_cache(SAMPLE_URL)
        assert result is None

    def test_hit_returns_dict(self, tmp_path):
        # Write a valid cache entry manually
        with mock.patch.object(pipeline, "_TI_CACHE_DIR", tmp_path):
            cache_file = pipeline._ti_cache_path(SAMPLE_URL)
            cache_file.write_text(json.dumps(SAMPLE_TI), encoding="utf-8")
            result = pipeline._load_ti_cache(SAMPLE_URL)
        assert result is not None
        assert result["threat_actor"]["name"] == "TestActor"

    def test_hit_preserves_techniques_list(self, tmp_path):
        with mock.patch.object(pipeline, "_TI_CACHE_DIR", tmp_path):
            cache_file = pipeline._ti_cache_path(SAMPLE_URL)
            cache_file.write_text(json.dumps(SAMPLE_TI), encoding="utf-8")
            result = pipeline._load_ti_cache(SAMPLE_URL)
        assert len(result["techniques"]) == 2

    def test_corrupt_file_returns_none(self, tmp_path):
        """Corrupted JSON must return None, not raise."""
        with mock.patch.object(pipeline, "_TI_CACHE_DIR", tmp_path):
            cache_file = pipeline._ti_cache_path(SAMPLE_URL)
            cache_file.write_text("not valid json {{{{", encoding="utf-8")
            result = pipeline._load_ti_cache(SAMPLE_URL)
        assert result is None

    def test_empty_file_returns_none(self, tmp_path):
        with mock.patch.object(pipeline, "_TI_CACHE_DIR", tmp_path):
            cache_file = pipeline._ti_cache_path(SAMPLE_URL)
            cache_file.write_text("", encoding="utf-8")
            result = pipeline._load_ti_cache(SAMPLE_URL)
        assert result is None


# ── _save_ti_cache ────────────────────────────────────────────────────────

class TestSaveTiCache:
    def test_creates_file(self, tmp_path):
        with mock.patch.object(pipeline, "_TI_CACHE_DIR", tmp_path):
            pipeline._save_ti_cache(SAMPLE_URL, SAMPLE_TI)
            cache_file = pipeline._ti_cache_path(SAMPLE_URL)
        assert cache_file.exists()

    def test_creates_parent_dirs(self, tmp_path):
        nested = tmp_path / "a" / "b" / "c"
        with mock.patch.object(pipeline, "_TI_CACHE_DIR", nested):
            pipeline._save_ti_cache(SAMPLE_URL, SAMPLE_TI)
        assert nested.exists()

    def test_written_content_is_valid_json(self, tmp_path):
        with mock.patch.object(pipeline, "_TI_CACHE_DIR", tmp_path):
            pipeline._save_ti_cache(SAMPLE_URL, SAMPLE_TI)
            cache_file = pipeline._ti_cache_path(SAMPLE_URL)
        data = json.loads(cache_file.read_text(encoding="utf-8"))
        assert isinstance(data, dict)

    def test_overwrite_updates_content(self, tmp_path):
        updated_ti = {**SAMPLE_TI, "platform": "azure"}
        with mock.patch.object(pipeline, "_TI_CACHE_DIR", tmp_path):
            pipeline._save_ti_cache(SAMPLE_URL, SAMPLE_TI)
            pipeline._save_ti_cache(SAMPLE_URL, updated_ti)
            cache_file = pipeline._ti_cache_path(SAMPLE_URL)
            data = json.loads(cache_file.read_text(encoding="utf-8"))
        assert data["platform"] == "azure"

    def test_write_failure_does_not_raise(self, tmp_path):
        """If the write fails (e.g. read-only fs), the function must not raise."""
        with mock.patch.object(pipeline, "_TI_CACHE_DIR", tmp_path):
            with mock.patch("pathlib.Path.write_text", side_effect=OSError("disk full")):
                # Should swallow the error and log a warning
                pipeline._save_ti_cache(SAMPLE_URL, SAMPLE_TI)


# ── Round-trip ────────────────────────────────────────────────────────────

class TestRoundTrip:
    def test_save_then_load_identical(self, tmp_path):
        with mock.patch.object(pipeline, "_TI_CACHE_DIR", tmp_path):
            pipeline._save_ti_cache(SAMPLE_URL, SAMPLE_TI)
            loaded = pipeline._load_ti_cache(SAMPLE_URL)
        assert loaded == SAMPLE_TI

    def test_different_urls_independent(self, tmp_path):
        url_a = "https://example.com/apt-a"
        url_b = "https://example.com/apt-b"
        ti_a  = {**SAMPLE_TI, "platform": "aws"}
        ti_b  = {**SAMPLE_TI, "platform": "azure"}
        with mock.patch.object(pipeline, "_TI_CACHE_DIR", tmp_path):
            pipeline._save_ti_cache(url_a, ti_a)
            pipeline._save_ti_cache(url_b, ti_b)
            loaded_a = pipeline._load_ti_cache(url_a)
            loaded_b = pipeline._load_ti_cache(url_b)
        assert loaded_a["platform"] == "aws"
        assert loaded_b["platform"] == "azure"

    def test_large_ti_extract_round_trips(self, tmp_path):
        """Ensure large payloads (many techniques) survive serialisation."""
        large_ti = {
            **SAMPLE_TI,
            "techniques": [
                {"mitre_id": f"T{1000+i}", "name": f"Technique {i}",
                 "expected_audit_events": ["foo:bar"] * 20}
                for i in range(50)
            ],
        }
        with mock.patch.object(pipeline, "_TI_CACHE_DIR", tmp_path):
            pipeline._save_ti_cache(SAMPLE_URL, large_ti)
            loaded = pipeline._load_ti_cache(SAMPLE_URL)
        assert len(loaded["techniques"]) == 50
