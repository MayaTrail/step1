"""
Django-side registry helpers for the emulations app.

These thin wrappers load the top-level emulations.registry module and provide
convenience look-ups used by the serializers and views.

The registry is loaded once and cached in-process (_cache).  Call
reset_cache() to force a reload — useful in tests or after hot-reloading
emulation packages without restarting the Django process.
"""

from __future__ import annotations

import importlib
import logging
import os
import sys
from typing import Any

logger = logging.getLogger(__name__)

_cache: list[dict[str, Any]] | None = None


def _load_registry() -> list[dict[str, Any]]:
    """
    Import and call emulations.registry.discover().

    The emulations package lives at EMULATIONS_BASE_DIR (/opt/emulations/).
    Its parent (/opt) is inserted into sys.path so that
    `import emulations.registry` resolves correctly both inside Docker and
    in local development.

    Logs at ERROR level if the import fails so the misconfiguration is
    immediately visible in server logs rather than silently returning [].

    Returns:
        List of emulation catalogue dicts as returned by discover().
    """
    global _cache  # noqa: PLW0603
    if _cache is not None:
        return _cache

    emulations_base_dir = os.environ.get("EMULATIONS_BASE_DIR", "")
    if emulations_base_dir:
        parent = os.path.dirname(emulations_base_dir)
        if parent and parent not in sys.path:
            sys.path.insert(0, parent)

    try:
        registry = importlib.import_module("emulations.registry")
        # Force a fresh discover() in case the module was already imported
        # before the parent directory was on sys.path.
        importlib.reload(registry)
        _cache = registry.discover()
        logger.info(
            "Emulations registry loaded: %d package(s) discovered",
            len(_cache),
        )
    except Exception as exc:
        logger.error(
            "Failed to load emulations registry — "
            "check that EMULATIONS_BASE_DIR points to the emulations/ directory. "
            "Error: %s",
            exc,
        )
        _cache = []

    return _cache


def reset_cache() -> None:
    """
    Clear the in-process registry cache so the next call to list_emulations()
    or get_emulation() triggers a fresh discover().

    Use after adding a new emulation package without restarting the process,
    or in tests that need a clean state.
    """
    global _cache  # noqa: PLW0603
    _cache = None
    logger.debug("Emulations registry cache cleared")


def list_emulations() -> list[dict[str, Any]]:
    """
    Return all discovered emulation packages as a list of dicts.

    Returns:
        List of emulation catalogue dicts, e.g.:
        [{"id": "scarleteel", "name": "scarleteel", "display_name": "SCARLETEEL 2.0", ...}]
    """
    return _load_registry()


def get_emulation(emulation_type: str) -> dict[str, Any] | None:
    """
    Look up a single emulation by its name field.

    Args:
        emulation_type: The MANIFEST name value, e.g. "scarleteel".

    Returns:
        The emulation catalogue dict, or None if not found.
    """
    return next(
        (e for e in _load_registry() if e.get("name") == emulation_type),
        None,
    )
