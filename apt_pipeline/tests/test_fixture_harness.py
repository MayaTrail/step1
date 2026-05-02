"""Tests for the fixture harness (_save_fixture / _load_fixture).

The harness is what lets us smoke-test the pipeline offline. Its round-trip
correctness is load-bearing for the entire test strategy going forward."""
import importlib
import os
from pathlib import Path


def _reimport_utils_with_fixture_dir(fixture_dir: Path):
    """_FIXTURE_DIR is baked at module import time. Tests that want to
    control it must re-import utils after setting PIPELINE_FIXTURE_DIR."""
    os.environ["PIPELINE_FIXTURE_DIR"] = str(fixture_dir)
    import utils
    importlib.reload(utils)
    return utils


def test_save_load_roundtrip(tmp_path):
    utils = _reimport_utils_with_fixture_dir(tmp_path)

    utils._save_fixture(
        label="TEST_PHASE",
        index=1,
        system_prompt="system",
        user_prompt="user",
        response='{"result": "ok"}',
        token_info={"input_tokens": 10, "output_tokens": 5, "model": "sonnet"},
    )

    loaded = utils._load_fixture("TEST_PHASE", 1)
    assert loaded is not None
    response, token_info = loaded
    assert response == '{"result": "ok"}'
    assert token_info["input_tokens"] == 10
    assert token_info["model"] == "sonnet"


def test_load_missing_returns_none(tmp_path):
    utils = _reimport_utils_with_fixture_dir(tmp_path)
    assert utils._load_fixture("DOES_NOT_EXIST", 99) is None


def test_label_sanitization(tmp_path):
    """Fixture filenames must be safe: unsafe chars in labels are replaced."""
    utils = _reimport_utils_with_fixture_dir(tmp_path)
    utils._save_fixture(
        label="PHASE/5A with spaces",
        index=0,
        system_prompt="",
        user_prompt="",
        response="x",
        token_info={},
    )
    # Should be on disk with a sanitized filename
    files = list(tmp_path.glob("*.json"))
    assert len(files) == 1
    # No raw slashes or spaces in the filename
    name = files[0].name
    assert "/" not in name
    assert " " not in name


def test_save_creates_parent_dir(tmp_path):
    nested = tmp_path / "deep" / "nested"
    utils = _reimport_utils_with_fixture_dir(nested)
    utils._save_fixture("X", 0, "", "", "r", {})
    assert (nested).exists()
    assert list(nested.glob("*.json"))
