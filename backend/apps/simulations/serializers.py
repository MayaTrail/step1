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

    Validates that both stack_id and module are provided, and that
    the module name is one of the known simulation modules.
    """

    stack_id = serializers.UUIDField(
        help_text="UUID of the Stack to run the simulation against.",
    )
    module = serializers.ChoiceField(
        choices=SimulationRun.KNOWN_MODULES,
        help_text="Simulation module name (matches a file in src/simulations/).",
    )
