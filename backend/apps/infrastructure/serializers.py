"""
Serializers for the infrastructure app.

StackSerializer — full representation of a Stack instance.
"""

from rest_framework import serializers

from .models import Stack


class StackSerializer(serializers.ModelSerializer):
    """
    Serializer for the Stack model.

    The owner field is read-only and is set automatically from the
    authenticated user in the view layer.
    """

    owner = serializers.StringRelatedField(read_only=True)

    class Meta:
        model = Stack
        fields = [
            "id",
            "name",
            "region",
            "status",
            "outputs",
            "owner",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "status", "outputs", "owner", "created_at", "updated_at"]
