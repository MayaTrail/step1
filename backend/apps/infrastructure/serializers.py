"""
Serializers for the infrastructure app.

StackSerializer — full representation of a Stack instance.
"""

from rest_framework import serializers

from . import lifecycle
from .models import Stack


class StackSerializer(serializers.ModelSerializer):
    """
    Serializer for the Stack model.

    The owner field is read-only and is set automatically from the
    authenticated user in the view layer.
    """

    owner = serializers.StringRelatedField(read_only=True)
    lifecycle = serializers.SerializerMethodField()

    def get_lifecycle(self, obj) -> list:
        """
        Return the stack's measured phases, marked against its own baseline.

        The baseline map arrives through the serializer context, computed once
        per request by the view. Deriving it here instead would run a query for
        every card on a page that lists every stack the user owns.

        Args:
            obj: The stack being serialised.

        Returns:
            Phases oldest first, each with its duration and whether it is
            running long. Empty for a stack that predates this recording, which
            the UI renders as a status without invented history.
        """
        baselines = (self.context or {}).get("phase_baselines", {})
        return lifecycle.annotate(
            obj.status_history or [], baselines.get(obj.emulation_type, {})
        )

    class Meta:
        model = Stack
        fields = [
            "id",
            "name",
            "region",
            "status",
            "outputs",
            "owner",
            "emulation_type",
            "expires_at",
            "task_id",
            "last_logs",
            "last_error",
            "resource_summary",
            "created_at",
            "updated_at",
            "lifecycle",
        ]
        read_only_fields = [
            "id", "status", "outputs", "owner",
            "emulation_type", "expires_at", "task_id",
            "last_logs", "last_error", "resource_summary",
            "created_at", "updated_at", "lifecycle",
        ]
