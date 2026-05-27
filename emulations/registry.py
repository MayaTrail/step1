"""
Emulation registry — auto-discovers emulation packages in this directory.

Every emulation package must expose a MANIFEST.py at the package root
containing a MANIFEST dict.  The attack module (attack.py) must expose
a run(outputs: dict) function.

Versioning:
    Packages should include a schema_version key in their MANIFEST dict.
    If absent, a warning is logged and the package is still registered —
    this preserves backward compatibility during the transition period.

Detection discovery:
    If a detections/ subdirectory exists, the registry enumerates its files
    and includes the list in the catalogue entry.  Backend views use
    detections_path to serve detection content without re-scanning the
    filesystem on every request.

Call discover() to get an ordered list of all available emulations.
Packages missing MANIFEST.py or with an invalid MANIFEST format are
skipped with a warning.
"""

from __future__ import annotations

import importlib
import logging
import pathlib
import sys
from typing import Any

logger = logging.getLogger(__name__)

_SKIP = frozenset({"__pycache__"})

_REQUIRED_FIELDS = {"name", "display_name", "description", "tier"}


def discover() -> list[dict[str, Any]]:
    """
    Scan emulations/*/MANIFEST.py and return a catalogue of emulations.

    Each entry contains all MANIFEST fields plus:
        id:               Same as MANIFEST["name"] — used as the API/URL identifier.
        detections_path:  Absolute path to the detections/ subdirectory, or None.
        detection_files:  Sorted list of filenames inside detections/, or [].
        module:           The imported MANIFEST module (for direct attribute access).

    Returns:
        Sorted list of emulation catalogue dicts, ordered by name.
    """
    package_dir = pathlib.Path(__file__).resolve().parent
    src_dir = str(package_dir.parent)
    if src_dir not in sys.path:
        sys.path.insert(0, src_dir)

    emulations: list[dict[str, Any]] = []

    for subdir in sorted(package_dir.iterdir()):
        if not subdir.is_dir():
            continue
        if subdir.name.startswith("_") or subdir.name in _SKIP:
            continue

        manifest_file = subdir / "MANIFEST.py"
        if not manifest_file.exists():
            logger.warning("Skipping emulations.%s — no MANIFEST.py found", subdir.name)
            continue

        try:
            mod = importlib.import_module(f"emulations.{subdir.name}.MANIFEST")
        except Exception as exc:
            logger.warning("Failed to import emulations.%s.MANIFEST: %s", subdir.name, exc)
            continue

        manifest = getattr(mod, "MANIFEST", None)
        if not isinstance(manifest, dict):
            logger.warning(
                "Skipping emulations.%s — MANIFEST.py must define a MANIFEST dict",
                subdir.name,
            )
            continue

        missing = _REQUIRED_FIELDS - manifest.keys()
        if missing:
            logger.warning(
                "Skipping emulations.%s — MANIFEST missing required keys: %s",
                subdir.name,
                missing,
            )
            continue

        if "schema_version" not in manifest:
            logger.warning(
                "emulations.%s — MANIFEST is missing schema_version; "
                "add schema_version=1 for forward compatibility",
                subdir.name,
            )

        detections_dir = subdir / "detections"
        if detections_dir.is_dir():
            detection_files = sorted(f.name for f in detections_dir.iterdir() if f.is_file())
            detections_path = str(detections_dir)
        else:
            detection_files = []
            detections_path = None

        entry: dict[str, Any] = {
            **{k: v for k, v in manifest.items() if k != "resource_costs"},
            "resource_costs": manifest.get("resource_costs", []),
            "id": manifest["name"],
            "detections_path": detections_path,
            "detection_files": detection_files,
            "manifest": manifest,
            "module": mod,
        }
        emulations.append(entry)

    for idx, entry in enumerate(sorted(emulations, key=lambda e: e["name"]), start=1):
        entry["catalogue_id"] = idx

    return emulations
