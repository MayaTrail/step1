"""
Models for the infrastructure app.

Stack — represents a single Pulumi stack (a set of AWS resources).
        Lifecycle: pending -> deploying -> ready (demo), or
        pending -> deploying -> ec2_booting -> ready_for_attack -> attacking
        -> attack_complete -> destroying -> destroyed (enterprise).
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

    Two new fields distinguish enterprise emulation stacks from demo stacks:
      - emulation_type: the emulation package name (e.g. "scarleteel").
        Empty string means a demo/generic stack.
      - expires_at: auto-destroy deadline set at deploy time for enterprise
        stacks.  Celery Beat destroys the stack when this is exceeded.

    The `tier` property is derived from the owner's account type and is
    never stored — the User record remains the source of truth.
    """

    class Status(models.TextChoices):
        """
        Lifecycle statuses for a Pulumi stack.

        Demo stacks use: pending -> deploying -> ready -> destroying -> destroyed.
        Enterprise stacks use the full state machine including ec2_booting,
        ready_for_attack, attacking, and attack_complete.
        """

        PENDING = "pending", "Pending"
        DEPLOYING = "deploying", "Deploying"
        READY = "ready", "Ready"
        DESTROYING = "destroying", "Destroying"
        REFRESHING = "refreshing", "Refreshing"
        FAILED = "failed", "Failed"

        # Enterprise-only statuses
        EC2_BOOTING = "ec2_booting", "EC2 Booting"
        READY_FOR_ATTACK = "ready_for_attack", "Ready for Attack"
        ATTACKING = "attacking", "Attacking"
        ATTACK_COMPLETE = "attack_complete", "Attack Complete"
        DESTROYED = "destroyed", "Destroyed"

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
        default="ap-south-1",
        help_text="AWS region for this stack.",
    )
    status = models.CharField(
        max_length=20,
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

    # Enterprise emulation fields
    emulation_type = models.CharField(
        max_length=64,
        blank=True,
        default="",
        help_text=(
            "Identifies the emulation package for enterprise stacks "
            "(e.g. 'scarleteel', 'apt29'). Empty for demo/generic stacks."
        ),
    )
    task_id = models.CharField(
        max_length=255,
        blank=True,
        default="",
        help_text=(
            "Celery task ID of the most recent deploy operation. "
            "Used by the progress endpoint to read live deployment state from Redis."
        ),
    )
    expires_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=(
            "Auto-destroy deadline for enterprise stacks. "
            "Celery Beat destroys the stack when this timestamp is exceeded. "
            "Set at deploy time from the emulation MANIFEST's default_ttl_hours."
        ),
    )

    # Operational visibility fields (Stacks Milestone 1, Phase 2)
    last_logs = models.JSONField(
        default=list,
        blank=True,
        help_text=(
            "Captured Pulumi output for the most recent deploy/destroy/refresh, "
            "as a list of {'t': ISO-8601 timestamp, 'line': str}. Only the most "
            "recent run is retained; overwritten on each operation."
        ),
    )
    last_error = models.TextField(
        blank=True,
        default="",
        help_text=(
            "Failure reason from the most recent operation (truncated). "
            "Empty when the last operation succeeded."
        ),
    )
    resource_summary = models.JSONField(
        default=dict,
        blank=True,
        help_text=(
            "Actual deployed-resource inventory derived from the Pulumi state on "
            "the last successful deploy/refresh. Shape: "
            "{'total': int, 'by_type': {<service>: count}, "
            "'resources': [{'name': str, 'type': str}]}. Empty before first deploy."
        ),
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

    @property
    def tier(self) -> str:
        """
        Return the tier of this stack based on the owner's account type.

        Derived from the owner, not stored separately — the User record
        is always the source of truth for tier classification.

        Returns:
            "demo"       if the owner is a demo user.
            "enterprise" if the owner has a verified AWS IAM role.
        """
        if self.owner.is_demo:
            return "demo"
        return "enterprise"
