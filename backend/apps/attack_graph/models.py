"""
Models for the attack_graph app.

ScoutScan — one run of the Scout IAM privilege-escalation scan against a
            tenant's account, holding the serialized result envelope the
            frontend renders.

active_scans — the single definition of "a scan is in flight", shared by the
            two endpoints that refuse a request while one is.
"""

import uuid
from datetime import timedelta

from django.conf import settings
from django.db import models
from django.utils import timezone

from .constants import SCAN_TIME_LIMIT


class ScoutScan(models.Model):
    """
    A single Attack Graph scan.

    Every scan is its own row and history is kept, matching EmulationRun: a
    customer comparing this month's paths to last month's is the point of
    keeping them, and an overwritten latest-only row cannot answer that.

    `result` holds the versioned envelope produced by envelope.serialize_scan,
    never Scout's own objects — Scout is maintained independently and its
    chain shape is not a contract this product can hold the frontend to.
    """

    class Status(models.TextChoices):
        """Lifecycle statuses, deliberately identical to EmulationRun's."""

        PENDING = "pending", "Pending"
        RUNNING = "running", "Running"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="scout_scans",
        help_text="User who triggered this scan; the audit role assumed is theirs.",
    )
    status = models.CharField(
        max_length=16,
        choices=Status.choices,
        default=Status.PENDING,
        db_index=True,
    )
    task_id = models.CharField(
        max_length=255,
        blank=True,
        help_text="Celery task id, for tracing a scan that stops reporting.",
    )
    result = models.JSONField(
        null=True,
        blank=True,
        help_text="The serialized result envelope (see envelope.py), once complete.",
    )
    graph = models.JSONField(
        null=True,
        blank=True,
        help_text=(
            "Scout's own Graph.to_dict() for this scan — every node and edge, "
            "not just the chain endpoints the envelope keeps. Null for every "
            "scan stored before this field existed: that is a normal, "
            "permanent state, not a backfill that is pending. Never returned "
            "by the detail or list serializer; the page polls those."
        ),
    )
    error_message = models.TextField(
        blank=True,
        help_text="Human-readable failure reason, shown to the user verbatim.",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="UTC timestamp when the Celery task began executing.",
    )
    completed_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="UTC timestamp when the scan reached a terminal status.",
    )

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "scout scan"
        verbose_name_plural = "scout scans"
        db_table = "scout_scans"

    def __str__(self) -> str:
        """Return a readable representation of this scan."""
        return f"scout scan [{self.status}] — {self.user_id}"


# Statuses that mean a scan has not finished.
ACTIVE_SCAN_STATUSES = (ScoutScan.Status.PENDING, ScoutScan.Status.RUNNING)

# How long a non-terminal scan is believed to still be running. Past this, it
# is treated as dead regardless of what its status column says.
#
# Celery's hard time_limit kills the worker process, so a scan that hits it —
# or whose worker crashed, or that was queued while no worker was up — never
# runs its own failure handler and stays at "running" or "pending" forever.
# Both callers of active_scans() refuse a request while a scan is active, so
# without this cutoff a single dead row would permanently deny the user both
# a new scan and the ability to disconnect the audit role, with no way out of
# either from the UI. The margin over SCAN_TIME_LIMIT covers queue latency
# between the row being created and the worker picking it up.
SCAN_STALE_AFTER_SECONDS = SCAN_TIME_LIMIT + 300


def active_scans(user):
    """
    Return this user's scans that are genuinely still in flight.

    The one definition of "in flight", used by ScoutScanTriggerView (which
    refuses a second concurrent scan) and by AWSAuditConnectorView.delete
    (which refuses to pull the role out from under a running task). Two
    copies of this filter would be two places for the staleness cutoff to go
    missing, and the symptom of it going missing is a user locked out with no
    error to search for.

    Args:
        user: The owner whose scans to consider.

    Returns:
        QuerySet of ScoutScan rows that are pending or running and were
        created recently enough to still plausibly be executing.
    """
    cutoff = timezone.now() - timedelta(seconds=SCAN_STALE_AFTER_SECONDS)
    return ScoutScan.objects.filter(
        user=user,
        status__in=ACTIVE_SCAN_STATUSES,
        created_at__gte=cutoff,
    )
