"""
Serializers for the attack_graph app.
"""

from rest_framework import serializers

from .models import ScoutScan


class ScoutScanListSerializer(serializers.ModelSerializer):
    """A scan without its result — what the history strip needs."""

    class Meta:
        model = ScoutScan
        fields = ["id", "status", "error_message", "created_at", "started_at", "completed_at"]
        read_only_fields = fields


class ScoutScanDetailSerializer(serializers.ModelSerializer):
    """A scan with its result envelope — what the graph renders."""

    class Meta:
        model = ScoutScan
        fields = [
            "id", "status", "result", "error_message",
            "created_at", "started_at", "completed_at",
        ]
        read_only_fields = fields
