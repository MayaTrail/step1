"""
Serializers for the attack_graph app.
"""

from rest_framework import serializers

from .models import ScoutScan


class ScoutScanListSerializer(serializers.ModelSerializer):
    """A scan without its result — what the history strip needs."""

    # Only the top-level classification, not the chains themselves — the
    # history strip needs to say "5 findings" or "Partial" next to a past
    # scan without paying for its full envelope, which is the largest field
    # on the row. serialize_scan() always stamps "state", so a completed scan
    # with none reveals a scan that reached "completed" without a result
    # (the same signal ResultRegion's "Scan result missing" branch guards).
    state = serializers.SerializerMethodField()

    class Meta:
        model = ScoutScan
        fields = ["id", "status", "state", "error_message", "created_at", "started_at", "completed_at"]
        read_only_fields = fields

    def get_state(self, obj: ScoutScan) -> str | None:
        return (obj.result or {}).get("state")


class ScoutScanDetailSerializer(serializers.ModelSerializer):
    """A scan with its result envelope — what the graph renders."""

    class Meta:
        model = ScoutScan
        fields = [
            "id", "status", "result", "error_message",
            "created_at", "started_at", "completed_at",
        ]
        read_only_fields = fields
