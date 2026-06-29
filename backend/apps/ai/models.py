"""
Models for the ai app.

LLMConnector — a single user's bring-your-own-key configuration for an LLM
provider. The API key is stored encrypted at rest (Fernet via apps.ai.crypto);
only the last four characters are kept in clear, for a masked display hint. The
plaintext key is never returned by the API and never logged.
"""

import uuid

from django.conf import settings
from django.db import models


class LLMConnector(models.Model):
    """
    Per-user LLM provider configuration (bring your own key).

    One connector per user (OneToOne). The encrypted key is written by the view
    via apps.ai.crypto; readers never receive the plaintext, only `has_key` and
    the last-4 `key_hint`.
    """

    class Provider(models.TextChoices):
        """Supported LLM providers."""

        OPENAI = "openai", "OpenAI"
        ANTHROPIC = "anthropic", "Anthropic"
        BEDROCK = "bedrock", "Amazon Bedrock"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="llm_connector",
    )
    provider = models.CharField(
        max_length=32,
        choices=Provider.choices,
        default=Provider.OPENAI,
    )
    model = models.CharField(
        max_length=128,
        help_text=(
            "Provider model id, e.g. 'gpt-4o', 'claude-sonnet-4-6', or a Bedrock "
            "inference-profile id like 'us.anthropic.claude-3-5-sonnet-20241022-v2:0'."
        ),
    )
    region = models.CharField(
        max_length=32,
        blank=True,
        default="",
        help_text=(
            "AWS region for Amazon Bedrock (e.g. 'us-east-1'). Required for the "
            "bedrock provider; unused by key-based providers."
        ),
    )
    api_key_encrypted = models.BinaryField(
        null=True,
        blank=True,
        help_text=(
            "Fernet-encrypted provider API key. Never stored or returned in "
            "plaintext. Null for the bedrock provider, which authenticates via "
            "the user's assumed AWS role instead of a stored key."
        ),
    )
    key_hint = models.CharField(
        max_length=4,
        blank=True,
        default="",
        help_text="Last 4 characters of the API key, for masked display only.",
    )
    enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "llm_connectors"
        verbose_name = "LLM connector"
        verbose_name_plural = "LLM connectors"

    def __str__(self) -> str:
        """Return a concise, secret-free summary."""
        state = "enabled" if self.enabled else "disabled"
        return f"{self.user_id} · {self.provider} ({state})"


class Conversation(models.Model):
    """
    A multi-turn chat about one emulation, owned by a single user.

    Stores only the user/assistant turns (see Message). The grounding system
    prompt is never stored; it is rebuilt from the emulation MANIFEST on every
    request so it can never go stale. Serves as the durable, per-user audit
    record of what was asked of the user's LLM.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="ai_conversations",
    )
    emulation_type = models.CharField(
        max_length=128,
        help_text="Emulation package name this conversation is grounded on.",
    )
    title = models.CharField(
        max_length=200,
        blank=True,
        default="",
        help_text="Short label, seeded from the first user message.",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "ai_conversations"
        ordering = ["-updated_at"]
        verbose_name = "AI conversation"
        verbose_name_plural = "AI conversations"

    def __str__(self) -> str:
        """Return a concise summary."""
        return f"{self.user_id} · {self.emulation_type} · {self.title or '(untitled)'}"


class Message(models.Model):
    """
    One turn in a Conversation. Only user and assistant roles are persisted;
    the system/grounding prompt is rebuilt server-side and never stored.
    """

    class Role(models.TextChoices):
        """Persisted message roles."""

        USER = "user", "User"
        ASSISTANT = "assistant", "Assistant"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    conversation = models.ForeignKey(
        Conversation,
        on_delete=models.CASCADE,
        related_name="messages",
    )
    role = models.CharField(max_length=16, choices=Role.choices)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "ai_messages"
        ordering = ["created_at"]
        verbose_name = "AI message"
        verbose_name_plural = "AI messages"

    def __str__(self) -> str:
        """Return a truncated, role-tagged summary."""
        preview = self.content[:40].replace("\n", " ")
        return f"[{self.role}] {preview}"
