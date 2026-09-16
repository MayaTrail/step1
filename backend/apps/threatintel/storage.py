"""
Local-disk persistence for the threat intel feed.

The ingest writes one document, and the API serves it back:

    {THREATINTEL_DIR}/latest.json   the rolling window the API returns.

Deliberately a file on disk rather than a bucket or a table. The feed is a
single document that is rewritten whole on each run and read whole on each
request, so it needs no queries, and keeping it local means the feature works
from `docker-compose up` with nothing to provision.

A missing or unreadable file is reported as an empty feed rather than an error,
so a failed ingest shows the page's empty state instead of taking it down.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any

from django.conf import settings

logger = logging.getLogger(__name__)

LATEST_FILENAME = "latest.json"


def _directory() -> Path | None:
    """
    Resolve the configured storage directory, creating it if needed.

    Returns:
        The directory as a Path, or None when THREATINTEL_DIR is unset or the
        directory cannot be created.
    """
    configured = getattr(settings, "THREATINTEL_DIR", "")
    if not configured:
        return None
    path = Path(configured)
    try:
        path.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        logger.error("Could not create threat intel directory %s: %s", path, exc)
        return None
    return path


def is_configured() -> bool:
    """
    Report whether the feed has somewhere to live.

    Returns:
        True when THREATINTEL_DIR resolves to a usable directory.
    """
    return _directory() is not None


def read_latest() -> dict[str, Any] | None:
    """
    Read the stored rolling window.

    Returns:
        The payload, or None when nothing has been stored yet or the file
        cannot be read.
    """
    directory = _directory()
    if directory is None:
        return None
    try:
        return json.loads((directory / LATEST_FILENAME).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, json.JSONDecodeError) as exc:
        logger.error("Could not read threat intel feed: %s", exc)
        return None


def write_latest(payload: dict[str, Any]) -> dict[str, str]:
    """
    Persist the rolling window.

    Written to a temporary file and renamed, because the API may read this file
    while an ingest is rewriting it and a partial JSON document would surface as
    an empty feed. os.replace is atomic within a filesystem.

    Args:
        payload: The document to store.

    Returns:
        {"path": ...} naming what was written.

    Raises:
        RuntimeError: When no storage directory is configured.
    """
    directory = _directory()
    if directory is None:
        raise RuntimeError("THREATINTEL_DIR is not configured.")

    target = directory / LATEST_FILENAME
    handle, temporary = tempfile.mkstemp(dir=str(directory), suffix=".tmp")
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
        os.replace(temporary, target)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise

    logger.info("Threat intel feed written: %s (%d item(s))", target, payload.get("itemCount", 0))
    return {"path": str(target)}
