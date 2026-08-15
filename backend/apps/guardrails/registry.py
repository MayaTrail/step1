"""
Django-side registry helpers for the guardrails app.

These thin wrappers load the top-level guardrails.registry module and provide
the look-ups the views use.  Mirrors apps.emulations.registry: the catalogue is
loaded once and cached in-process (_cache), and reset_cache() forces a reload.

Caching the catalogue also caches every policy document, so a request never
touches the filesystem.  The library is a read-only mount that changes only on
deploy, which is what makes that safe.
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
    Import and call guardrails.registry.discover().

    The guardrails package lives at GUARDRAILS_BASE_DIR (/opt/guardrails/).
    Its parent (/opt) is inserted into sys.path so that
    `import guardrails.registry` resolves both inside Docker and in local
    development.

    Logs at ERROR level if the import fails so the misconfiguration is
    immediately visible in server logs rather than silently returning [].

    Returns:
        List of guardrail catalogue dicts as returned by discover().
    """
    global _cache  # noqa: PLW0603
    if _cache is not None:
        return _cache

    guardrails_base_dir = os.environ.get("GUARDRAILS_BASE_DIR", "")
    if guardrails_base_dir:
        parent = os.path.dirname(guardrails_base_dir.rstrip("/"))
        if parent and parent not in sys.path:
            sys.path.insert(0, parent)

    try:
        registry = importlib.import_module("guardrails.registry")
        # Force a fresh discover() in case the module was already imported
        # before the parent directory was on sys.path.
        importlib.reload(registry)
        _cache = registry.discover()
    except Exception as exc:
        logger.error(
            "Failed to load guardrails registry, "
            "check that GUARDRAILS_BASE_DIR points to the guardrails/ directory. "
            "Error: %s",
            exc,
        )
        _cache = []

    return _cache


def reset_cache() -> None:
    """
    Clear the in-process catalogue cache so the next look-up reloads from disk.

    Use after editing the guardrails library without restarting the process, or
    in tests that need a clean state.
    """
    global _cache  # noqa: PLW0603
    _cache = None
    logger.debug("Guardrails registry cache cleared")


def list_guardrails() -> list[dict[str, Any]]:
    """
    Return every guardrail in the library.

    Returns:
        List of catalogue dicts, ordered by type then purpose.
    """
    return _load_registry()


def get_guardrail(guardrail_id: str) -> dict[str, Any] | None:
    """
    Look up a single guardrail by its catalogue id.

    Args:
        guardrail_id: The slug from the catalogue, e.g. "deny-kms-key-deletion".

    Returns:
        The catalogue dict, or None if no guardrail carries that id.
    """
    return next(
        (g for g in _load_registry() if g.get("id") == guardrail_id),
        None,
    )
