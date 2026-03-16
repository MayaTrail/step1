"""
Simulation registry — auto-discovers simulation modules in this package.

Every simulation module should expose:
    MANIFEST = {"name": "...", "description": "..."}
    def run(): ...

Call ``discover()`` to get an ordered list of all available simulations.
Modules missing ``MANIFEST`` or ``run()`` are silently skipped with a warning.
"""

from __future__ import annotations

import importlib
import logging
import pathlib
import sys
from typing import Any

logger = logging.getLogger(__name__)

# Files that live in simulations/ but are NOT simulation modules.
_SKIP = frozenset({"__init__", "logger", "registry"})


def discover() -> list[dict[str, Any]]:
    """
    Scan ``simulations/*.py``, import each module, and return a catalogue.

    Returns:
        Sorted list of dicts with keys: ``id``, ``name``, ``description``,
        ``module`` (the imported module object).
    """
    package_dir = pathlib.Path(__file__).resolve().parent
    # Ensure src/ (parent of simulations/) is on sys.path so that
    # `import simulations.<module>` works from any working directory.
    src_dir = str(package_dir.parent)
    if src_dir not in sys.path:
        sys.path.insert(0, src_dir)

    modules: list[dict[str, Any]] = []

    for py_file in sorted(package_dir.glob("*.py")):
        stem = py_file.stem
        if stem.startswith("_") or stem in _SKIP:
            continue

        try:
            mod = importlib.import_module(f"simulations.{stem}")
        except Exception as exc:
            logger.warning("Failed to import simulations.%s: %s", stem, exc)
            continue

        manifest = getattr(mod, "MANIFEST", None)
        run_fn = getattr(mod, "run", None)

        if manifest is None or not callable(run_fn):
            logger.warning(
                "Skipping simulations.%s — missing MANIFEST or run()", stem
            )
            continue

        if not isinstance(manifest, dict) or "name" not in manifest or "description" not in manifest:
            logger.warning(
                "Skipping simulations.%s — MANIFEST must have 'name' and 'description'", stem
            )
            continue

        modules.append(
            {
                "name": manifest["name"],
                "description": manifest["description"],
                "module": mod,
            }
        )

    # Assign deterministic IDs by alphabetical order of name.
    for idx, entry in enumerate(modules, start=1):
        entry["id"] = idx

    return modules