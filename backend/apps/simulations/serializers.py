"""
Serializers for the simulations app.

SimulationRunSerializer    — full representation of a SimulationRun.
TriggerSimulationSerializer — validates the payload for POST /api/simulations/run/.
"""

from rest_framework import serializers

from .models import SimulationRun


class SimulationRunSerializer(serializers.ModelSerializer):
    """
    Full read serializer for SimulationRun.

    Exposes all fields including stdout/stderr for results polling.
    """

    triggered_by = serializers.StringRelatedField(read_only=True)

    class Meta:
        model = SimulationRun
        fields = [
            "id",
            "stack",
            "module",
            "status",
            "stdout",
            "stderr",
            "triggered_by",
            "started_at",
            "completed_at",
            "created_at",
        ]
        read_only_fields = fields


class TriggerSimulationSerializer(serializers.Serializer):
    """
    Input serializer for triggering a new simulation run.

    Validates that both stack_id and module_id are provided, and that
    the module_id corresponds to a known simulation module.
    """

    stack_id = serializers.UUIDField(
        help_text="UUID of the Stack to run the simulation against.",
    )
    module_id = serializers.IntegerField(
        help_text="Numeric ID of the simulation module (see GET /api/simulations/modules/).",
    )

    def validate_module_id(self, value: int) -> int:
        """Ensure the module_id maps to a discovered simulation."""
        valid_ids = SimulationRun.get_module_ids()
        if value not in valid_ids:
            raise serializers.ValidationError(
                f"Invalid module_id. Valid IDs: {valid_ids}"
            )
        return value
