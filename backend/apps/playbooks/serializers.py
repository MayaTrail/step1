"""
Serializers for the playbooks app.

PlaybookListSerializer  — the card view: everything but the body, so listing a
                          hundred playbooks does not ship a hundred documents.
PlaybookSerializer      — the full record, used by retrieve/create/update.
PlaybookForkSerializer  — validates a fork request.
"""

from rest_framework import serializers

from .generation import (
    MAX_BRIEF_CHARS,
    MAX_REFERENCE_CHARS,
    MAX_REFERENCE_URLS,
)
from .models import Playbook

# An IR playbook is a document, not a blob store. The cap is generous for real
# use (the shipped AMBERSQUID playbook is ~28 KB) and keeps a runaway paste or a
# hostile client from filling the table.
MAX_BODY_BYTES = 512 * 1024


class PlaybookListSerializer(serializers.ModelSerializer):
    """Playbook without its body, for list responses."""

    is_fork = serializers.BooleanField(read_only=True)
    owner_username = serializers.CharField(source="owner.username", read_only=True)

    class Meta:
        model = Playbook
        fields = [
            "id", "title", "slug", "summary", "source_emulation", "is_fork",
            "is_example", "status", "visibility", "owner_username",
            "created_at", "updated_at",
        ]
        read_only_fields = fields


class PlaybookSerializer(serializers.ModelSerializer):
    """Full playbook record."""

    is_fork = serializers.BooleanField(read_only=True)
    owner_username = serializers.CharField(source="owner.username", read_only=True)

    class Meta:
        model = Playbook
        fields = [
            "id", "title", "slug", "summary", "body", "source_emulation",
            "is_fork", "is_example", "status", "visibility", "owner_username",
            "created_at", "updated_at",
        ]
        read_only_fields = [
            "id", "slug", "is_fork", "is_example", "owner_username",
            "created_at", "updated_at",
        ]

    def validate_title(self, value: str) -> str:
        """Reject a blank or whitespace-only title."""
        title = value.strip()
        if not title:
            raise serializers.ValidationError("Title cannot be blank.")
        return title

    def validate_body(self, value: str) -> str:
        """Cap the document size."""
        if len(value.encode("utf-8")) > MAX_BODY_BYTES:
            raise serializers.ValidationError(
                "Playbook is larger than %d KB." % (MAX_BODY_BYTES // 1024)
            )
        return value


class PlaybookForkSerializer(serializers.Serializer):
    """Request body for POST /api/playbooks/fork/."""

    emulation_type = serializers.CharField(max_length=64)
    title = serializers.CharField(max_length=200, required=False, allow_blank=True)

    def validate_emulation_type(self, value: str) -> str:
        """
        Reject anything that is not a bare package name.

        The value is used to locate a directory on disk, so a separator or a
        parent reference here would be a path traversal.
        """
        name = value.strip()
        if not name or "/" in name or "\\" in name or name.startswith("."):
            raise serializers.ValidationError("Not a valid emulation package name.")
        return name


class PlaybookGenerateSerializer(serializers.Serializer):
    """Request body for POST /api/playbooks/generate/."""

    brief = serializers.CharField(max_length=MAX_BRIEF_CHARS)
    reference_urls = serializers.ListField(
        child=serializers.URLField(max_length=500),
        required=False,
        allow_empty=True,
        max_length=MAX_REFERENCE_URLS,
    )
    reference_text = serializers.CharField(
        required=False, allow_blank=True, max_length=MAX_REFERENCE_CHARS
    )

    def validate_brief(self, value: str) -> str:
        """A brief of three words produces a playbook worth nothing."""
        brief = value.strip()
        if len(brief) < 20:
            raise serializers.ValidationError(
                "Describe the incident in a sentence or two so the draft has "
                "something to work from."
            )
        return brief
