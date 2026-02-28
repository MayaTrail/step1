"""
Models for the simulations app.

SimulationRun — a single execution of a simulation module against a Stack.
                Lifecycle: pending -> running -> completed | failed.
"""

import uuid

from django.conf import settings
from django.db import models

from apps.infrastructure.models import Stack


class SimulationRun(models.Model):
    """
    Records a single simulation execution.

    Each run is tied to a Stack (which provides the AWS environment) and a
    module name that maps to a file under src/simulations/.  stdout and
    stderr are captured from the subprocess or module execution.
    """

    class Status(models.TextChoices):
        """Lifecycle statuses for a simulation run."""

        PENDING = "pending", "Pending"
        RUNNING = "running", "Running"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"

    # Known simulation module names — validated in the serializer.
    KNOWN_MODULES = [
        "attach_role_policy",
        "enumeration",
        "eventual_consistency",
        "s3_initial_access",
        "s3_kms_encryption",
    ]

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )
    stack = models.ForeignKey(
        Stack,
        on_delete=models.CASCADE,
        related_name="simulation_runs",
        help_text="Stack (AWS environment) this simulation ran against.",
    )
    module = models.CharField(
        max_length=128,
        help_text="Module name under src/simulations/ (without .py extension).",
    )
    status = models.CharField(
        max_length=16,
        choices=Status.choices,
        default=Status.PENDING,
        db_index=True,
    )
    stdout = models.TextField(blank=True, default="")
    stderr = models.TextField(blank=True, default="")
    triggered_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="simulation_runs",
        help_text="User who triggered this run.",
    )
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "simulation run"
        verbose_name_plural = "simulation runs"
        db_table = "simulation_runs"

    def __str__(self) -> str:
        """Return a human-readable identifier for this run."""
        return f"{self.module} on {self.stack.name} [{self.status}]"
