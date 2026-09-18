"""
Writing the activity trail.

`LogEntry` has existed since the first release with an Event enum naming every
stack and emulation transition, and exactly one write site: playbook commands.
The rest of the trail was declared and never written, so the audit trail held
three rows. This module is the missing half.

Recording is best effort on purpose. These calls sit inside Celery tasks that
deploy infrastructure and run attacks, and a failure to write a notification
must never fail the deploy it describes. Every error is swallowed and reported
to the task's own logger instead.
"""

from __future__ import annotations

import logging
from typing import Any

from .models import LogEntry

logger = logging.getLogger(__name__)


def record_activity(
    event: str,
    message: str,
    *,
    actor: Any = None,
    stack: Any = None,
    level: str = LogEntry.Level.INFO,
) -> None:
    """
    Write one entry to the activity trail.

    Args:
        event: A member of LogEntry.Event.
        message: One sentence a reader sees in the notification panel. Written
            for a person, not as a field dump.
        actor: The user who caused it. Set this whenever it is known, because
            the read API returns entries where the caller is the actor or owns
            the stack, and an entry with neither is invisible to everyone.
        stack: The stack this concerns, when there is one. It is also what the
            panel links to, so pass it even for emulation and workflow events.
        level: LogEntry.Level, raising the row's prominence in the panel.

    Returns:
        None. Failures are logged and swallowed: a missing notification is
        never worth failing a deploy over.
    """
    try:
        LogEntry.objects.create(
            event=event,
            message=message,
            actor=actor,
            stack=stack,
            level=level,
        )
    except Exception:  # noqa: BLE001 - an audit write must not break its caller
        logger.warning("Could not record activity: %s", event, exc_info=True)
