"""
Serialisers for the workflows app.

Two shapes for a workflow: a summary for list rows and a detail carrying the
per-rule verdicts. The report can hold a verdict and an evidence block per rule,
which is worth sending for one run and wasteful for a hundred.

Field names are camelCase so the frontend types match without client-side
mapping, following the emulations app.
"""

from __future__ import annotations

from rest_framework import serializers

from apps.emulations.registry import get_emulation

from .models import AlertEndpoint, WorkflowRun
from .scoring import headline


class AlertEndpointSerializer(serializers.ModelSerializer):
    """
    One webhook endpoint, without its secret.

    The secret is returned exactly once, by the create view, and is not a field
    here so it cannot be exposed by a later listing.
    """

    lastAlertAt = serializers.DateTimeField(source="last_alert_at", read_only=True)
    secretHint = serializers.CharField(source="secret_hint", read_only=True)
    createdAt = serializers.DateTimeField(source="created_at", read_only=True)
    createdBy = serializers.CharField(source="owner.username", read_only=True)
    alertCount = serializers.SerializerMethodField()

    class Meta:
        model = AlertEndpoint
        fields = [
            "id", "name", "enabled", "secretHint", "lastAlertAt", "createdAt",
            "createdBy", "alertCount",
        ]

    def get_alertCount(self, obj) -> int:  # noqa: N802 - camelCase to match the API
        """
        Count alerts this endpoint has accepted.

        Args:
            obj: The endpoint being serialised.

        Returns:
            Total alerts received, which is what tells a client their
            integration works before they spend money running an emulation.
        """
        return obj.alerts.count()


class WorkflowRunSerializer(serializers.ModelSerializer):
    """A workflow as a list row: status, timing and the headline result."""

    emulationType = serializers.CharField(source="emulation_type", read_only=True)
    failedStep = serializers.CharField(source="failed_step", read_only=True)
    alertDeadline = serializers.DateTimeField(source="alert_deadline", read_only=True)
    scheduledFor = serializers.DateTimeField(source="scheduled_for", read_only=True)
    createdAt = serializers.DateTimeField(source="created_at", read_only=True)
    startedAt = serializers.DateTimeField(source="started_at", read_only=True)
    completedAt = serializers.DateTimeField(source="completed_at", read_only=True)
    summary = serializers.SerializerMethodField()
    platform = serializers.SerializerMethodField()

    class Meta:
        model = WorkflowRun
        fields = [
            "id", "emulationType", "platform", "status", "detail", "failedStep", "score",
            "summary", "alertDeadline", "scheduledFor", "createdAt", "startedAt",
            "completedAt",
        ]

    def get_platform(self, obj) -> str:
        """
        Resolve the emulation's platform, for links into its pages.

        Args:
            obj: The workflow being serialised.

        Returns:
            The platform id, defaulting to aws for an emulation the registry no
            longer carries, since that is where the link would have gone anyway.
        """
        entry = get_emulation(obj.emulation_type) or {}
        return entry.get("platform", "aws")

    def get_summary(self, obj) -> str:
        """
        Describe the run in one sentence.

        Args:
            obj: The workflow being serialised.

        Returns:
            The scored headline, or an empty string while the run is still
            open. An unfinished run has no result to summarise, and inventing
            one would read as a verdict.
        """
        return headline(obj.score) if obj.score else ""


class WorkflowRunDetailSerializer(WorkflowRunSerializer):
    """A workflow with its per-rule verdicts and the alerts behind them."""

    windowStart = serializers.DateTimeField(source="window_start", read_only=True)
    windowEnd = serializers.DateTimeField(source="window_end", read_only=True)
    stackId = serializers.UUIDField(source="stack_id", read_only=True)
    stackStatus = serializers.CharField(source="stack.status", read_only=True, default="")
    emulationRunId = serializers.UUIDField(source="emulation_run_id", read_only=True)
    emulationRunStatus = serializers.CharField(
        source="emulation_run.status", read_only=True, default=""
    )

    class Meta(WorkflowRunSerializer.Meta):
        fields = WorkflowRunSerializer.Meta.fields + [
            "report", "windowStart", "windowEnd",
            "stackId", "stackStatus", "emulationRunId", "emulationRunStatus",
        ]
