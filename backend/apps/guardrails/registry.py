"""
Registry for the SCP/RCP guardrails library.

Guardrails are plain AWS policy JSON files in the Guardrails/ directory, plus a
MANIFEST.json sidecar that carries the metadata the policy documents themselves
do not have: the SCP/RCP split, the human-readable purpose, and the service tags.

Mirrors apps.emulations.registry: the catalogue is loaded once and cached
in-process; call reset_cache() to force a reload.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

MANIFEST_FILENAME = "MANIFEST.json"

_cache: list[dict[str, Any]] | None = None


def _base_dir() -> Path | None:
    """
    Resolve the Guardrails/ directory from GUARDRAILS_BASE_DIR.

    Returns:
        The directory as a Path, or None if the variable is unset or does not
        point at an existing directory.
    """
    configured = os.environ.get("GUARDRAILS_BASE_DIR", "")
    if not configured:
        return None
    path = Path(configured)
    return path if path.is_dir() else None


def _load() -> list[dict[str, Any]]:
    """
    Read MANIFEST.json and attach each guardrail's policy JSON as `code`.

    A manifest entry whose policy file is missing or unreadable is skipped and
    logged rather than failing the whole catalogue, so one bad file cannot take
    the library offline.

    Returns:
        List of guardrail dicts ready for serialisation.
    """
    global _cache  # noqa: PLW0603
    if _cache is not None:
        return _cache

    base = _base_dir()
    if base is None:
        logger.error(
            "Failed to load guardrails registry — "
            "check that GUARDRAILS_BASE_DIR points to the Guardrails/ directory. "
            "Current value: %r",
            os.environ.get("GUARDRAILS_BASE_DIR", ""),
        )
        _cache = []
        return _cache

    manifest_path = base / MANIFEST_FILENAME
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.error("Could not read guardrails manifest %s: %s", manifest_path, exc)
        _cache = []
        return _cache

    entries: list[dict[str, Any]] = []
    for entry in manifest.get("guardrails", []):
        filename = entry.get("file", "")
        # Guard against a manifest entry escaping the guardrails directory.
        policy_path = (base / filename).resolve()
        if not filename or base.resolve() not in policy_path.parents:
            logger.warning("Skipping guardrail with unsafe file path: %r", filename)
            continue
        try:
            code = policy_path.read_text(encoding="utf-8")
        except OSError as exc:
            logger.warning("Could not read guardrail policy %s: %s", policy_path, exc)
            continue
        entries.append({
            "id": entry.get("id", ""),
            "type": entry.get("type", ""),
            "name": entry.get("name", ""),
            "purpose": entry.get("purpose", ""),
            "services": entry.get("services", []),
            "source": entry.get("source", ""),
            "code": code.rstrip("\n"),
        })

    _cache = entries
    logger.info("Guardrails registry loaded: %d policy document(s)", len(entries))
    return _cache


def reset_cache() -> None:
    """
    Clear the in-process guardrails cache so the next call reloads from disk.

    Use after editing the Guardrails/ directory without restarting the process,
    or in tests that need a clean state.
    """
    global _cache  # noqa: PLW0603
    _cache = None
    logger.debug("Guardrails registry cache cleared")


def list_guardrails() -> list[dict[str, Any]]:
    """
    Return every guardrail in the library.

    Returns:
        List of guardrail dicts, each with id, type, name, purpose, services,
        source and code.
    """
    return _load()
