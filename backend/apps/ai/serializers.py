"""
Serializers for the ai app.

LLMConnectorSerializer — read/write a user's connector. `api_key` is write-only
and never returned; reads expose only non-sensitive fields plus `has_key` and
the last-4 `key_hint` for masked display.
"""

from rest_framework import serializers

from .models import Conversation, LLMConnector, Message
from .providers import SUPPORTED_PROVIDERS


class LLMConnectorSerializer(serializers.ModelSerializer):
    """Serializer for the per-user LLM connector."""

    api_key = serializers.CharField(
        write_only=True,
        required=False,
        allow_blank=False,
        trim_whitespace=False,
        min_length=8,
        help_text="Provider API key. Write-only; stored encrypted, never returned.",
    )
    has_key = serializers.SerializerMethodField()

    class Meta:
        model = LLMConnector
        fields = ["provider", "model", "enabled", "api_key", "has_key", "key_hint", "updated_at"]
        read_only_fields = ["has_key", "key_hint", "updated_at"]

    def get_has_key(self, obj: LLMConnector) -> bool:
        """True when an encrypted key is stored."""
        return bool(obj.api_key_encrypted)

    def validate_provider(self, value: str) -> str:
        """Reject providers we cannot talk to."""
        if value not in SUPPORTED_PROVIDERS:
            raise serializers.ValidationError(
                f"Unsupported provider. Choose one of: {sorted(SUPPORTED_PROVIDERS)}."
            )
        return value


class MessageSerializer(serializers.ModelSerializer):
    """One persisted chat turn (user or assistant)."""

    class Meta:
        model = Message
        fields = ["id", "role", "content", "created_at"]
        read_only_fields = fields


class ConversationSerializer(serializers.ModelSerializer):
    """
    A conversation summary. `messages` is included on the detail view only;
    list responses omit it for brevity.
    """

    messages = MessageSerializer(many=True, read_only=True)

    class Meta:
        model = Conversation
        fields = ["id", "emulation_type", "title", "created_at", "updated_at", "messages"]
        read_only_fields = ["id", "title", "created_at", "updated_at", "messages"]


class ConversationListSerializer(serializers.ModelSerializer):
    """Lightweight conversation row for the history list (no messages)."""

    class Meta:
        model = Conversation
        fields = ["id", "emulation_type", "title", "created_at", "updated_at"]
        read_only_fields = fields
