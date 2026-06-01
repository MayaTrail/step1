"""
Serializers for the logs app.

LogEntrySerializer — read-only representation of a LogEntry.
"""

from rest_framework import serializers

from .models import LogEntry


class LogEntrySerializer(serializers.ModelSerializer):
    """
    Read-only serializer for the LogEntry model.

    All fields are read-only; log entries are never created via the API —
    they are written internally by Celery tasks and views.
    """

    actor = serializers.StringRelatedField(read_only=True)

    class Meta:
        model = LogEntry
        fields = [
            "id",
            "level",
            "event",
            "message",
            "actor",
            "stack",
            "timestamp",
        ]
        read_only_fields = fields
