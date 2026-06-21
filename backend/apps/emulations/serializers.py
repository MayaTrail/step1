"""
Serializers for the emulations app.

EmulationRunSerializer   — read-only representation of an EmulationRun.
DeployEmulationSerializer — validates the POST /api/emulations/deploy/ body.
TriggerAttackSerializer  — validates the POST /api/emulations/{id}/attack/ body (currently empty).
"""

from rest_framework import serializers

from .models import EmulationRun


class EmulationRunSerializer(serializers.ModelSerializer):
    """
    Read-only serializer for EmulationRun.

    Exposes all fields needed for the frontend to poll run status,
    display phase progress, and render stdout/stderr output.
    """

    class Meta:
        model = EmulationRun
        fields = [
            "id",
            "stack",
            "emulation_type",
            "status",
            "phase_current",
            "phase_total",
            "stdout",
            "stderr",
            "triggered_by",
            "started_at",
            "completed_at",
            "created_at",
        ]
        read_only_fields = fields


class EmulationRunListSerializer(serializers.ModelSerializer):
    """
    Lightweight serializer for the runs list (Active Runs / Results pages).

    Omits the heavy stdout/stderr fields (those live on the per-run detail
    endpoint) and enriches each row with data the table needs but the model
    doesn't store directly:

      * emulation_name — friendly display name from the registry MANIFEST.
      * platform       — derived from the run's emulation_type via the registry
                         (defaults to "aws"); EmulationRun stores no platform.
      * stack_name     — the associated stack's human-readable name.
    """

    emulation_name = serializers.SerializerMethodField()
    platform = serializers.SerializerMethodField()
    stack_name = serializers.CharField(source="stack.name", read_only=True)

    class Meta:
        model = EmulationRun
        fields = [
            "id",
            "stack",
            "stack_name",
            "emulation_type",
            "emulation_name",
            "platform",
            "status",
            "phase_current",
            "phase_total",
            "triggered_by",
            "started_at",
            "completed_at",
            "created_at",
        ]
        read_only_fields = fields

    def _entry(self, obj: EmulationRun) -> dict | None:
        """Look up the registry MANIFEST entry for this run's emulation type."""
        from apps.emulations.registry import get_emulation  # noqa: PLC0415
        return get_emulation(obj.emulation_type)

    def get_emulation_name(self, obj: EmulationRun) -> str:
        """Return the friendly display name, falling back to the raw type."""
        entry = self._entry(obj)
        return entry.get("display_name", obj.emulation_type) if entry else obj.emulation_type

    def get_platform(self, obj: EmulationRun) -> str:
        """Return the emulation's platform, defaulting to 'aws'."""
        entry = self._entry(obj)
        return entry.get("platform", "aws") if entry else "aws"


class DeployEmulationSerializer(serializers.Serializer):
    """
    Validates the request body for POST /api/emulations/deploy/.

    Requires:
        emulation_type: Identifier of the emulation package to deploy
                        (must match a discovered MANIFEST in emulations/).
        stack_name:     Pulumi stack name suffix (e.g. "dev-himan10").
    """

    emulation_type = serializers.CharField(
        max_length=64,
        help_text="Emulation package name, e.g. 'scarleteel'.",
    )
    stack_name = serializers.CharField(
        max_length=128,
        help_text="Pulumi stack name for this deployment.",
    )

    def validate_emulation_type(self, value: str) -> str:
        """
        Ensure the requested emulation type exists in the registry.

        Args:
            value: The emulation_type string from the request body.

        Returns:
            The validated emulation_type string.

        Raises:
            ValidationError if the type is not registered.
        """
        from apps.emulations.registry import get_emulation  # noqa: PLC0415
        if get_emulation(value) is None:
            raise serializers.ValidationError(
                f"Unknown emulation type '{value}'. "
                "Call GET /api/emulations/ for available types."
            )
        return value
