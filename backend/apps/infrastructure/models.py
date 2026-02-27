"""
Models for the infrastructure app.

Stack — represents a single Pulumi stack (a set of AWS resources).
        Lifecycle: pending -> deploying -> ready, or -> failed.
        The outputs JSONField stores Pulumi stack outputs once deployed.
"""

import uuid

from django.conf import settings
from django.db import models


class Stack(models.Model):
    """
    Represents a provisioned (or pending) Pulumi stack.

    Each stack is owned by a user and tracks its deployment lifecycle.
    The `outputs` field is populated by the deploy_stack Celery task once
    `pulumi up` completes successfully.
    """

    class Status(models.TextChoices):
        """Lifecycle statuses for a Pulumi stack."""

        PENDING = "pending", "Pending"
        DEPLOYING = "deploying", "Deploying"
        READY = "ready", "Ready"
        DESTROYING = "destroying", "Destroying"
        FAILED = "failed", "Failed"

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )
    name = models.CharField(
        max_length=128,
        unique=True,
        help_text="Pulumi stack name, e.g. dev-himan10",
    )
    region = models.CharField(
        max_length=32,
        default="us-east-1",
        help_text="AWS region for this stack.",
    )
    status = models.CharField(
        max_length=16,
        choices=Status.choices,
        default=Status.PENDING,
        db_index=True,
    )
    outputs = models.JSONField(
        default=dict,
        blank=True,
        help_text="Pulumi stack outputs as returned after a successful deploy.",
    )
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="stacks",
        help_text="User who created this stack.",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "stack"
        verbose_name_plural = "stacks"
        db_table = "stacks"

    def __str__(self) -> str:
        """Return stack name and status as the string representation."""
        return f"{self.name} [{self.status}]"
