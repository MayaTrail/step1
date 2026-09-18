"""
Models for the emulations app.

EmulationRun — tracks a single execution of an enterprise emulation against
               a deployed emulation stack.  Records phase progress,
               stdout/stderr output, and lifecycle timestamps.
"""

import uuid

from django.conf import settings
from django.db import models


class EmulationRun(models.Model):
    """
    A single execution of an enterprise emulation.

    Each EmulationRun is associated with one Stack (the infrastructure
    that was deployed for this emulation) and one triggering user.

    Phase progress is tracked via phase_current and phase_total so the
    frontend can display a real-time progress indicator.

    stdout and stderr are captured from the attack module's run() function
    and stored here for display in the results UI.
    """

    class Status(models.TextChoices):
        """Lifecycle statuses for an emulation run."""

        PENDING = "pending", "Pending"
        RUNNING = "running", "Running"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )
    stack = models.ForeignKey(
        "infrastructure.Stack",
        on_delete=models.CASCADE,
        related_name="emulation_runs",
        help_text="The infrastructure stack this emulation ran against.",
    )
    emulation_type = models.CharField(
        max_length=64,
        help_text="Emulation package identifier, e.g. 'scarleteel'.",
    )
    status = models.CharField(
        max_length=16,
        choices=Status.choices,
        default=Status.PENDING,
        db_index=True,
    )
    phase_current = models.IntegerField(
        default=0,
        help_text="Index of the phase currently executing (0 = not started).",
    )
    phase_total = models.IntegerField(
        default=0,
        help_text="Total number of phases for this emulation type.",
    )
    stdout = models.TextField(
        blank=True,
        help_text="Captured stdout from the attack module's run() function.",
    )
    stderr = models.TextField(
        blank=True,
        help_text="Captured stderr from the attack module's run() function.",
    )
    triggered_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="emulation_runs",
        help_text="User who triggered this emulation run.",
    )
    started_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="UTC timestamp when the Celery task began executing.",
    )
    completed_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="UTC timestamp when the run reached a terminal status.",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "emulation run"
        verbose_name_plural = "emulation runs"
        db_table = "emulation_runs"

    def __str__(self) -> str:
        """Return a readable representation of this emulation run."""
        return f"{self.emulation_type} [{self.status}] — stack {self.stack_id}"
