"""Initial migration for the ai app: the LLMConnector model."""

import uuid

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    """Create the llm_connectors table."""

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="LLMConnector",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4, editable=False, primary_key=True, serialize=False
                    ),
                ),
                (
                    "provider",
                    models.CharField(
                        choices=[("openai", "OpenAI"), ("anthropic", "Anthropic")],
                        default="openai",
                        max_length=32,
                    ),
                ),
                (
                    "model",
                    models.CharField(
                        help_text="Provider model id, e.g. 'gpt-4o' or 'claude-sonnet-4-6'.",
                        max_length=128,
                    ),
                ),
                (
                    "api_key_encrypted",
                    models.BinaryField(
                        help_text="Fernet-encrypted provider API key. Never stored or returned in plaintext."
                    ),
                ),
                (
                    "key_hint",
                    models.CharField(
                        blank=True,
                        default="",
                        help_text="Last 4 characters of the API key, for masked display only.",
                        max_length=4,
                    ),
                ),
                ("enabled", models.BooleanField(default=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "user",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="llm_connector",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "verbose_name": "LLM connector",
                "verbose_name_plural": "LLM connectors",
                "db_table": "llm_connectors",
            },
        ),
    ]
