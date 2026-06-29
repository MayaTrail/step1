"""App config for the ai app (LLM connector and emulation chat)."""

from django.apps import AppConfig


class AiConfig(AppConfig):
    """Configuration for the ai app."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.ai"
    verbose_name = "AI Assistant"
