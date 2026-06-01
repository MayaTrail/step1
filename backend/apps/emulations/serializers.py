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
