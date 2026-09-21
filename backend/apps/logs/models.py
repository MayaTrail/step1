"""
Models for the logs app.

LogEntry — an immutable audit event written by Celery tasks and views.
           Never deleted; forms the audit trail for all platform activity.
"""

import uuid

from django.conf import settings
from django.db import models

from apps.infrastructure.models import Stack


class LogEntry(models.Model):
    """
    Immutable audit log entry.

    Records discrete events (stack deployments, emulation runs) with
    free-form message text.  All foreign keys are nullable so that a
    log entry survives the deletion of its referenced objects.
    """

    class Level(models.TextChoices):
        """Severity levels for log entries."""

        INFO = "info", "Info"
        WARNING = "warning", "Warning"
        ERROR = "error", "Error"

    class Event(models.TextChoices):
        """Well-known event names written by the platform."""

        STACK_DEPLOYED = "stack.deployed", "Stack Deployed"
        STACK_DESTROYED = "stack.destroyed", "Stack Destroyed"
        EMULATION_STARTED = "emulation.started", "Emulation Started"
        EMULATION_COMPLETED = "emulation.completed", "Emulation Completed"
        EMULATION_FAILED = "emulation.failed", "Emulation Failed"
        STACK_FAILED = "stack.failed", "Stack Failed"
        WORKFLOW_STARTED = "workflow.started", "Workflow Started"
        WORKFLOW_COMPLETED = "workflow.completed", "Workflow Completed"
        WORKFLOW_FAILED = "workflow.failed", "Workflow Failed"
        # Archiving hides a run from coverage history, which changes the
        # figures a client is shown without changing what was measured. Both
        # directions are recorded so the trail explains a shifted percentage.
        WORKFLOW_ARCHIVED = "workflow.archived", "Workflow Archived"
        WORKFLOW_RESTORED = "workflow.restored", "Workflow Restored"
        PLAYBOOK_COMMAND = "playbook.command", "Playbook Command Run"
        # An attack graph scan reads the tenant's IAM and nothing else, but it
        # assumes a role in their account, so it belongs in the same trail as
        # every other action MayaTrail takes there.
        SCAN_STARTED = "scan.started", "Attack Graph Scan Started"
        SCAN_COMPLETED = "scan.completed", "Attack Graph Scan Completed"
        SCAN_FAILED = "scan.failed", "Attack Graph Scan Failed"

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )
    level = models.CharField(
        max_length=16,
        choices=Level.choices,
        default=Level.INFO,
        db_index=True,
    )
    event = models.CharField(
        max_length=64,
        choices=Event.choices,
        db_index=True,
        help_text="Machine-readable event identifier.",
    )
    message = models.TextField(
        help_text="Human-readable description of the event.",
    )
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="log_entries",
        help_text="User who caused this event, if applicable.",
    )
    stack = models.ForeignKey(
        Stack,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="log_entries",
        help_text="Stack this event relates to, if applicable.",
    )
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["-timestamp"]
        verbose_name = "log entry"
        verbose_name_plural = "log entries"
        db_table = "log_entries"

    def __str__(self) -> str:
        """Return a concise summary of the log entry."""
        return f"[{self.level.upper()}] {self.event} @ {self.timestamp:%Y-%m-%d %H:%M:%S}"
