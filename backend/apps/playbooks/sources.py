"""
Locate the PLAYBOOK.md that ships with an emulation package.

Imports from apps.emulations.registry, not apps.emulations.views. The registry
is stdlib-only; the views module reaches the serializers, the tasks module and
from there pulumi, boto3 and the logs models. Depending on the registry keeps
this app importable under config.settings.ci, which is what lets the playbooks
tests run without the full runtime stack installed.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from apps.emulations.registry import get_emulation

logger = logging.getLogger(__name__)


class PlaybookSourceError(Exception):
    """Raised when a shipped playbook cannot be located or read."""


def load_shipped_playbook(emulation_type: str) -> tuple[str, str]:
    """
    Return (display_name, markdown) for an emulation's shipped playbook.

    Args:
        emulation_type: Emulation package name, e.g. 'ambersquid'. Callers must
            have validated it is a bare name - it is used as a path segment.

    Returns:
        A (display_name, markdown_content) pair.

    Raises:
        PlaybookSourceError: the emulation is unknown, the server is missing
            EMULATIONS_BASE_DIR, the package ships no playbook, or the file
            could not be read.
    """
    entry = get_emulation(emulation_type)
    if entry is None:
        raise PlaybookSourceError("Unknown emulation '%s'." % emulation_type)

    detections_path = entry.get("detections_path")
    if detections_path:
        # detections/ sits one level below the package root.
        package_dir = Path(detections_path).parent
    else:
        base = os.environ.get("EMULATIONS_BASE_DIR", "")
        if not base:
            raise PlaybookSourceError(
                "EMULATIONS_BASE_DIR is not configured on this server."
            )
        package_dir = Path(base) / emulation_type

    playbook_path = package_dir / "PLAYBOOK.md"
    if not playbook_path.exists():
        raise PlaybookSourceError(
            "'%s' does not ship a playbook to fork." % emulation_type
        )

    try:
        content = playbook_path.read_text(encoding="utf-8")
    except OSError as exc:
        logger.error("Could not read playbook for %s: %s", emulation_type, exc)
        raise PlaybookSourceError("Playbook could not be read.") from exc

    return entry.get("display_name", emulation_type), content
