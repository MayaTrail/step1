"""
Models for the workflows app.

Three records, and the seam between them is deliberate:

    AlertEndpoint   where a client's SIEM posts what it caught.
    IngestedAlert   one alert, stored exactly as received.
    WorkflowRun     one validation of one emulation, from deploy to score.

An alert is never written against a workflow. The endpoint authenticates,
parses and stores; attribution to a run happens later, by owner and time
window, when the run settles. That keeps the only unauthenticated route in the
platform as small as possible, lets an alert that arrives before its run still
count, and means a re-score picks up anything that landed since.
"""

from __future__ import annotations

import uuid

from django.conf import settings
from django.db import models


class AlertEndpoint(models.Model):
    """
    A webhook a client's SIEM posts alerts to.

    One user may hold several, so a team running more than one SIEM, or
    separating production from a test integration, does not have to share a
    secret between them. The secret is Fernet-encrypted at rest and shown to
    the user exactly once, at creation.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="alert_endpoints",
    )
    name = models.CharField(
        max_length=120,
        help_text="Client-chosen label, for example 'Splunk production'.",
    )
    secret_encrypted = models.BinaryField(
        help_text=(
            "Fernet-encrypted HMAC secret. Never returned after creation; the "
            "client stores their own copy in the SIEM's webhook action."
        ),
    )
    secret_hint = models.CharField(
        max_length=12,
        blank=True,
        help_text="Last few characters of the secret, so a user can tell two endpoints apart.",
    )
    enabled = models.BooleanField(
        default=True,
        help_text="Set False to reject posts without deleting the endpoint or its history.",
    )
    last_alert_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=(
            "When this endpoint last accepted an alert. Drives the 'integration "
            "not wired up' verdict, which must never be scored as a missed detection."
        ),
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        """Return a label identifying the endpoint and its owner."""
        return f"{self.name} ({self.owner_id})"


class IngestedAlert(models.Model):
    """
    One alert a SIEM reported, stored as received.

    The parsed fields are what correlation matches on; `raw` keeps the client's
    original payload so a verdict can always be traced back to the evidence
    that produced it. Nothing here is trusted for authorisation: the endpoint
    has already verified the signature by the time a row is written.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    endpoint = models.ForeignKey(
        AlertEndpoint,
        on_delete=models.CASCADE,
        related_name="alerts",
    )
    received_at = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
        help_text=(
            "When MayaTrail accepted the alert. Attribution uses this rather "
            "than fired_at, because the SIEM's clock is not ours to trust."
        ),
    )
    fired_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When the SIEM says the rule fired. Displayed, not used for attribution.",
    )
    rule_id = models.CharField(
        max_length=200,
        blank=True,
        db_index=True,
        help_text=(
            "Rule identifier from the SIEM. When the client deployed MayaTrail's "
            "rules this is the Sigma UUID, which matches a shipped rule exactly."
        ),
    )
    rule_name = models.CharField(max_length=400, blank=True)
    technique = models.CharField(
        max_length=32,
        blank=True,
        db_index=True,
        help_text=(
            "ATT&CK technique the alert is tagged with, upper-cased. The fallback "
            "match for a client running their own detections rather than ours."
        ),
    )
    severity = models.CharField(max_length=32, blank=True)
    raw = models.JSONField(
        default=dict,
        blank=True,
        help_text="The payload as posted, so a verdict can be traced to its evidence.",
    )

    class Meta:
        ordering = ["-received_at"]
        indexes = [models.Index(fields=["endpoint", "received_at"])]

    def __str__(self) -> str:
        """Return a label identifying the alert's rule and arrival time."""
        return f"{self.rule_name or self.rule_id or 'alert'} @ {self.received_at:%Y-%m-%d %H:%M}"


class WorkflowRun(models.Model):
    """
    One end-to-end validation of a single emulation.

    Holds its own state because it outlives the request that started it: the
    attack takes minutes, and a SIEM may take tens of minutes more to report
    what it caught, so the user is expected to navigate away and come back.

    The evidence window is the span alerts are attributed from. It opens when
    the attack starts, not when the workflow does, so infrastructure
    provisioning does not sweep in unrelated alerts.
    """

    class Status(models.TextChoices):
        """Lifecycle of a workflow, in the order a run passes through it."""

        PENDING = "pending", "Pending"
        DEPLOYING = "deploying", "Deploying infrastructure"
        ATTACKING = "attacking", "Running emulation"
        AWAITING_ALERTS = "awaiting_alerts", "Waiting for SIEM alerts"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="workflow_runs",
    )
    emulation_type = models.CharField(
        max_length=120,
        help_text="Registry name of the emulation this workflow validates.",
    )
    stack = models.ForeignKey(
        "infrastructure.Stack",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="workflow_runs",
    )
    emulation_run = models.ForeignKey(
        "emulations.EmulationRun",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="workflow_runs",
    )
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.PENDING,
        db_index=True,
    )
    detail = models.TextField(
        blank=True,
        help_text="Human-readable reason for the current status, set when a step fails.",
    )
    failed_step = models.CharField(
        max_length=20,
        blank=True,
        help_text=(
            "Which step abandoned the run: deploy, attack, alerts or score. Recorded "
            "because only the code that gave up knows this. Inferring it afterwards "
            "from timestamps marked a failed deploy as successful and blamed the "
            "attack step, which had never run."
        ),
    )
    window_start = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Attack start. Alerts before this belong to something else.",
    )
    window_end = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Attack end. Alerts are attributed from window_start to alert_deadline.",
    )
    alert_deadline = models.DateTimeField(
        null=True,
        blank=True,
        db_index=True,
        help_text=(
            "When to stop waiting and score with whatever arrived. SIEMs evaluate "
            "on a schedule, so this is minutes after the attack, not seconds."
        ),
    )
    report = models.JSONField(
        null=True,
        blank=True,
        help_text="Per-rule verdicts with the alert evidence behind each one.",
    )
    score = models.JSONField(
        null=True,
        blank=True,
        help_text=(
            "Detection coverage and integration health. Separate figures on "
            "purpose: a rule nothing exercised is a connection problem, not a "
            "detection failure, and blending them hides the actionable one."
        ),
    )
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["owner", "-created_at"])]

    def __str__(self) -> str:
        """Return a label identifying the workflow and its emulation."""
        return f"{self.emulation_type} workflow {str(self.id)[:8]} ({self.status})"
