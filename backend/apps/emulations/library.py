"""
The standalone IR playbook library (playbooks/), read as documentation.

These playbooks are indexed by DETECTION USE CASE (`<service>.<tactic>.<what-
happened>`), while emulations are indexed by TECHNIQUE. The two do not map one
to one: an emulation's attack can light up several playbooks, and most playbooks
here describe behaviour no emulation performs yet. So this is deliberately a
separate, read-only surface rather than an extension of the emulation catalogue
-- listing these as emulations would put deploy buttons on things that cannot be
deployed and inflate the MITRE heatmap with techniques the platform cannot
actually simulate.

Deliberately minimal, and deliberately temporary:

  * No model, no migration, no new Django app. Playbooks are files, exactly as
    emulations are, and the registry pattern already proves that works.
  * No MANIFEST authoring. Every playbook already carries a `## Classification`
    table with the same seven fields, so the metadata is parsed from content
    that exists rather than duplicated into 115 hand-written manifests that
    would drift from the prose beside them.

Detection rules under a playbook's detections/ are REFERENCE material. A rule
only ships as a MayaTrail detection once an emulation exists that fires it and a
run has proven it fires, so callers must present these as unvalidated.
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Rows of the "## Classification" markdown table: | Field | Value |
_ROW_RE = re.compile(r"^\|\s*([A-Za-z][A-Za-z /&]*?)\s*\|\s*(.*?)\s*\|\s*$", re.M)

# Severity is written as prose in several playbooks ("**High.** The source rates
# it P3, which reads the alert as..."), so take the first level word rather than
# the whole cell.
_LEVEL_RE = re.compile(r"(Critical|High|Medium|Low|Informational)", re.I)

_TECHNIQUE_RE = re.compile(r"T\d{4}(?:\.\d{3})?")

# Directories that are shared material, not playbooks in their own right.
_SKIP = {"_ground-truth", "_superseded"}

_CACHE: list[dict[str, Any]] | None = None


def base_dir() -> Path | None:
    """
    Resolve the playbook library root.

    Prefers PLAYBOOKS_BASE_DIR (set to /opt/playbooks in Docker); falls back to
    the repo-relative playbooks/ directory so a bare checkout also works.

    Returns:
        The directory, or None when it does not exist. A missing library is not
        an error: the deployment simply has no playbook content mounted.
    """
    env_dir = os.environ.get("PLAYBOOKS_BASE_DIR", "")
    if env_dir:
        path = Path(env_dir)
        return path if path.is_dir() else None
    # backend/apps/emulations/library.py -> repo root is parents[3]
    fallback = Path(__file__).resolve().parents[3] / "playbooks"
    return fallback if fallback.is_dir() else None


def reset_cache() -> None:
    """Drop the in-process cache so the next call re-scans the directory."""
    global _CACHE
    _CACHE = None


def _classification(text: str) -> dict[str, str]:
    """Return the '## Classification' table of a PLAYBOOK.md as a dict."""
    if "## Classification" not in text:
        return {}
    block = text.split("## Classification", 1)[1].split("\n---", 1)[0]
    return {key.lower(): value for key, value in _ROW_RE.findall(block)}


def _summarise(directory: Path) -> dict[str, Any] | None:
    """
    Build one library entry from a playbook directory.

    Args:
        directory: A `<service>.<tactic>.<what-happened>` directory.

    Returns:
        The entry dict, or None when the directory holds no PLAYBOOK.md.
    """
    playbook = directory / "PLAYBOOK.md"
    if not playbook.exists():
        return None

    try:
        text = playbook.read_text(encoding="utf-8")
    except OSError as exc:
        logger.warning("Could not read %s: %s", playbook, exc)
        return None

    fields = _classification(text)
    parts = directory.name.split(".", 2)
    level = _LEVEL_RE.search(fields.get("severity", ""))

    detections_dir = directory / "detections"
    detection_files = (
        sorted(f.name for f in detections_dir.iterdir() if f.is_file())
        if detections_dir.is_dir()
        else []
    )

    # The first markdown H1 is the playbook's own title; the directory name is a
    # slug and reads poorly in a card.
    heading = re.search(r"^#\s+(.+)$", text, re.M)

    return {
        "id": directory.name,
        "title": heading.group(1).strip() if heading else directory.name,
        "service": parts[0] if parts else "",
        "tactic": parts[1] if len(parts) > 1 else "",
        "severity": level.group(1).capitalize() if level else "",
        "incidentType": fields.get("incident type", ""),
        "platform": fields.get("platform", "aws"),
        "techniques": _TECHNIQUE_RE.findall(fields.get("mitre techniques", "")),
        "tactics": [t.strip() for t in fields.get("mitre tactics", "").split(",") if t.strip()],
        "services": [s.strip() for s in fields.get("services in scope", "").split(",") if s.strip()],
        "detectionFiles": detection_files,
        "lineCount": text.count("\n") + 1,
    }


def discover() -> list[dict[str, Any]]:
    """
    Scan the library and return one summary per playbook, sorted by id.

    Cached in process. Returns an empty list when no library is mounted, so the
    endpoint degrades to "nothing to show" rather than failing.
    """
    global _CACHE
    if _CACHE is not None:
        return _CACHE

    root = base_dir()
    if root is None:
        logger.info("No playbook library mounted; set PLAYBOOKS_BASE_DIR to enable it")
        _CACHE = []
        return _CACHE

    entries: list[dict[str, Any]] = []
    for directory in sorted(root.iterdir()):
        if not directory.is_dir() or directory.name.startswith("_") or directory.name in _SKIP:
            continue
        entry = _summarise(directory)
        if entry:
            entries.append(entry)

    _CACHE = entries
    return _CACHE


def get(playbook_id: str) -> dict[str, Any] | None:
    """
    Return one playbook's summary plus its markdown body.

    Args:
        playbook_id: The directory name, e.g. "s3.exfiltration.bucket-acl-configured".

    Returns:
        The entry with a "markdown" key added, or None when unknown. The id is
        matched against the discovered set rather than joined onto a path, so a
        traversal attempt ("../../etc/passwd") simply finds no match.
    """
    entry = next((e for e in discover() if e["id"] == playbook_id), None)
    if entry is None:
        return None

    root = base_dir()
    if root is None:
        return None

    try:
        markdown = (root / entry["id"] / "PLAYBOOK.md").read_text(encoding="utf-8")
    except OSError as exc:
        logger.error("Could not read playbook %s: %s", playbook_id, exc)
        return None

    return {**entry, "markdown": markdown}


def detection_bodies(playbook_id: str) -> list[dict[str, str]] | None:
    """
    Return the raw detection files shipped alongside a playbook.

    These are REFERENCE rules: unlike an emulation's detections they have no
    attack proving they fire, so callers must label them as unvalidated. The
    bodies are returned verbatim rather than parsed, because 24 of the library's
    Sigma files do not currently satisfy the platform's Sigma validator and
    parsing them here would turn a documentation page into an error page.

    Args:
        playbook_id: The playbook directory name.

    Returns:
        One dict per file with "name" and "body", or None when unknown.
    """
    entry = next((e for e in discover() if e["id"] == playbook_id), None)
    root = base_dir()
    if entry is None or root is None:
        return None

    detections_dir = root / entry["id"] / "detections"
    if not detections_dir.is_dir():
        return []

    files: list[dict[str, str]] = []
    for name in entry["detectionFiles"]:
        try:
            files.append({"name": name, "body": (detections_dir / name).read_text(encoding="utf-8")})
        except OSError as exc:
            logger.warning("Could not read detection %s/%s: %s", playbook_id, name, exc)
    return files
